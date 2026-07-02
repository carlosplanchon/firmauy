#!/usr/bin/env python3
# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

import json
import os
import shutil
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Annotated, Iterable, List, Optional
from zoneinfo import ZoneInfo

import pkcs11
import typer
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from pyhanko import stamp
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.layout import (
    AxisAlignment,
    InnerScaling,
    Margins,
    SimpleBoxLayoutRule,
)
from pyhanko.sign import fields, signers
from pyhanko.sign.pkcs11 import PKCS11Signer
from pyhanko.sign.timestamps import HTTPTimeStamper

from firmauy.appearance import ensure_output_parent, make_appearance_pdf
from firmauy.card_reader import (
    card_to_json_obj,
    format_card_human,
    list_readers,
    open_reader,
    photo_to_json_obj,
    read_card,
    read_photo,
    select_applet,
)
from firmauy.cert_utils import (
    cert_not_after,
    cert_not_before,
    get_common_name,
    name_fields,
    normalize_issuer_name,
)
from firmauy.ci import complete_ci, validate_ci
from firmauy.constants import (
    APPEARANCE_HEIGHT,
    APPEARANCE_WIDTH,
    DEFAULT_IMAGE_OPACITY,
    DEFAULT_PKCS11_LIB,
    DEFAULT_TIMEZONE,
    DEFAULT_X1,
    DEFAULT_X2,
    DEFAULT_Y1,
    DEFAULT_Y2,
    ImageMode,
    SignAs,
)
from firmauy.pin import PinSource, get_pin
from firmauy.pkcs11_utils import (
    cert_is_expired,
    cert_not_yet_valid,
    find_token,
    get_private_key,
    iter_cert_objects,
    load_pkcs11_lib,
    normalize_cert_id_hex,
    select_certificate,
)
from firmauy.national_ca import (
    cache_dir,
    fetch_cas,
    load_bundled_trust_anchors,
    load_cached_trust_anchors,
)
from firmauy.pdf_verify import verify_pdf
from firmauy.xml_sign import sign_xml
from firmauy.xml_verify import verify_xml
from firmauy.cms_sign import sign_cms_detached
from firmauy.cms_verify import verify_cms

app = typer.Typer(
    help=(
        "Sign and verify PDF (PAdES), XML (XAdES) and arbitrary files (CAdES/.p7s) "
        "with the Uruguayan ID card (cédula) via PKCS#11.\n\n"
        "Runs locally by default: no data is transmitted externally.\n"
        "(Note: TSA usage may involve external connections depending on configuration.)\n\n"
        "This project is not affiliated with or endorsed by AGESIC. "
        "No legal validity guaranteed. Use at your own risk."
    )
)


def _version_callback(value: bool) -> None:
    if value:
        from importlib.metadata import PackageNotFoundError, version
        try:
            v = version("firmauy")
        except PackageNotFoundError:
            v = "unknown (not installed)"
        typer.echo(f"firmauy {v}")
        raise typer.Exit()


@app.callback()
def _main(
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version", callback=_version_callback, is_eager=True,
            help="Show the version and exit.",
        ),
    ] = None,
) -> None:
    pass


# ---------------------------------------------------------------------------
# Error formatting
# ---------------------------------------------------------------------------

def _format_error(exc: Exception) -> str:
    """Human-readable message for an exception, with friendly text for common
    PKCS#11 PIN errors (whose own str() is empty)."""
    import pkcs11.exceptions as pe
    if isinstance(exc, pe.PinIncorrect):
        return "Incorrect PIN."
    if isinstance(exc, pe.PinLocked):
        return "The PIN is locked (too many incorrect attempts)."
    return str(exc) or type(exc).__name__


# ---------------------------------------------------------------------------
# Shared CLI option types (reused by `sign-pdf` and `sign-pdf-batch`)
# ---------------------------------------------------------------------------

Pkcs11LibOpt = Annotated[str, typer.Option("--pkcs11-lib", help="Path to the PKCS#11 module.")]
TokenLabelOpt = Annotated[Optional[str], typer.Option("--token-label", help="Exact PKCS#11 token label. If not provided, auto-detected.")]
CertIdOpt = Annotated[Optional[str], typer.Option("--cert-id", help="Hexadecimal ID of the PKCS#11 certificate/key. If not provided, auto-detected.")]
PinSourceOpt = Annotated[PinSource, typer.Option("--pin-source", help="How to obtain the PIN: prompt (default), env, stdin, fd.")]
PinEnvVarOpt = Annotated[Optional[str], typer.Option("--pin-env-var", help="Environment variable holding the PIN (requires --pin-source env).")]
PinFdOpt = Annotated[Optional[int], typer.Option("--pin-fd", help="File descriptor holding the PIN (requires --pin-source fd).")]
FieldNameOpt = Annotated[str, typer.Option("--field-name", help="Signature field name.")]
PageOpt = Annotated[int, typer.Option("--page", help="Page where the visible signature is placed. -1 = last page.")]
X1Opt = Annotated[int, typer.Option("--x1", help="X1 coordinate of the signature box.")]
Y1Opt = Annotated[int, typer.Option("--y1", help="Y1 coordinate of the signature box.")]
X2Opt = Annotated[int, typer.Option("--x2", help="X2 coordinate of the signature box.")]
Y2Opt = Annotated[int, typer.Option("--y2", help="Y2 coordinate of the signature box.")]
TimezoneOpt = Annotated[str, typer.Option("--timezone", help="Timezone for the visible timestamp.")]
ReasonOpt = Annotated[Optional[str], typer.Option("--reason", help="Reason for signing.")]
LocationOpt = Annotated[Optional[str], typer.Option("--location", help="Location of signing.")]
ContactInfoOpt = Annotated[Optional[str], typer.Option("--contact-info", help="Signer contact information.")]
TsaUrlOpt = Annotated[
    Optional[str],
    typer.Option(
        "--tsa-url",
        help=(
            "URL of a Time Stamping Authority (TSA). Embeds independent, "
            "trusted-time evidence in the signature. Optional: the Uruguayan "
            "cédula signing flow does not require it."
        ),
    ),
]
TsaUserOpt = Annotated[Optional[str], typer.Option("--tsa-user", help="Username for HTTP Basic auth on the TSA (requires --tsa-url and --tsa-pass-env).")]
TsaPassEnvOpt = Annotated[Optional[str], typer.Option("--tsa-pass-env", help="Environment variable holding the TSA password for HTTP Basic auth (kept off the command line).")]
TsaHeaderOpt = Annotated[Optional[List[str]], typer.Option("--tsa-header", help="Extra HTTP header sent to the TSA as 'Name: Value' (repeatable). The value is visible in the process list (argv); for a secret (Bearer token / API key) use --tsa-header-env instead.")]
TsaHeaderEnvOpt = Annotated[Optional[List[str]], typer.Option("--tsa-header-env", help="Like --tsa-header but the value is read from an environment variable: 'Name: ENV_VAR' (repeatable). Keeps secrets (Bearer token / API key) off the command line.")]
OverwriteOpt = Annotated[bool, typer.Option("--overwrite", help="Allow overwriting existing output file(s).")]
ForceOpt = Annotated[bool, typer.Option("--force", help="Continue even if the signature field already contains a signature (the resulting PDF may become invalid).")]
QuietOpt = Annotated[bool, typer.Option("--quiet", "-q", help="Do not print the signer identity block (name, issuer, certificate serial, PKCS#11 ID). Use in batch/automation to keep identifying data out of logs.")]
VerifyOpt = Annotated[bool, typer.Option("--verify", help="After signing, re-verify the produced signature (integrity and coverage, no trust); the command fails if it is not intact.")]
ImageOpt = Annotated[Optional[Path], typer.Option("--image", exists=True, dir_okay=False, readable=True, help="Image (PNG/JPEG) to show in the signature appearance. Cosmetic only; does not affect the signature.")]
ImageModeOpt = Annotated[ImageMode, typer.Option("--image-mode", help="Where the --image goes: background (behind the text, default), side (left of the text), or only (image, no text).")]
ImageOpacityOpt = Annotated[float, typer.Option("--image-opacity", min=0.0, max=1.0, help="Opacity of the --image in background mode (0..1). Default 0.2 (subtle watermark).")]
NativeOpt = Annotated[bool, typer.Option("--native", help="Sign natively over PC/SC APDUs instead of PKCS#11: talk to the cédula directly, with no PKCS#11 middleware (--pkcs11-lib/--token-label/--cert-id are then ignored). Experimental; not AGESIC-certified. Needs pcscd and a reader, not the PKCS#11 module.")]
ReaderOpt = Annotated[Optional[str], typer.Option("--reader", help="PC/SC reader name (as shown by list-readers) for --native. Auto-detected when exactly one reader is present.")]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _print_signing_info(
    *,
    token_label_display: str,
    signer_name: str,
    issuer_name: str,
    key_id: Optional[bytes],
    cert_serial: str,
    tsa_url: Optional[str],
    quiet: bool = False,
    source_caption: str = "Token",
) -> None:
    """Print the aligned signer/token summary shared by every sign-* command.

    ``source_caption`` labels the first line: "Token" for the PKCS#11 backend, "Reader" for the
    native PC/SC backend. ``key_id`` is the PKCS#11 object ID; pass None in native mode (there is no
    such ID) to omit that line. Skipped entirely when ``quiet`` is set, to keep identifying data
    (signer name, certificate serial, PKCS#11 ID) out of automation/CI logs.
    """
    if quiet:
        return
    typer.echo(f"{source_caption + ':':<21}{token_label_display}")
    typer.echo(f"Signer:              {signer_name}")
    typer.echo(f"Issuer:              {issuer_name}")
    if key_id is not None:
        typer.echo(f"PKCS#11 ID:          {key_id.hex()}")
    typer.echo(f"Certificate serial:  {cert_serial}")
    if tsa_url:
        typer.echo(f"TSA:                 {tsa_url}")


class _SigningContext:
    """Backend-agnostic context yielded by ``_signing_session``.

    Carries the selected certificate and its display fields, plus lazy factories for the two signer
    shapes the sign-* commands need: a pyHanko ``Signer`` (PDF/CMS) via ``pyhanko_signer()`` and a raw
    bytes->bytes callable (XML) via ``raw_signer()``. The factories are backend-specific (PKCS#11 vs
    native card); each is built at most once, so a PDF-only sign never constructs the XML signer and
    vice-versa, and a batch reuses the one instance across all files."""

    def __init__(self, *, cert, signer_name, issuer_name, cert_serial,
                 pyhanko_signer_factory, raw_signer_factory):
        self.cert = cert
        self.signer_name = signer_name
        self.issuer_name = issuer_name
        self.cert_serial = cert_serial
        self._pyhanko_signer_factory = pyhanko_signer_factory
        self._raw_signer_factory = raw_signer_factory
        self._pyhanko_signer = None
        self._raw_signer = None

    def pyhanko_signer(self):
        if self._pyhanko_signer is None:
            self._pyhanko_signer = self._pyhanko_signer_factory()
        return self._pyhanko_signer

    def raw_signer(self):
        if self._raw_signer is None:
            self._raw_signer = self._raw_signer_factory()
        return self._raw_signer


@contextmanager
def _signing_session(*, native, reader, pkcs11_lib, token_label, cert_id, pin_source, pin_env_var,
                     pin_fd, tsa_url, quiet):
    """Open a signing session with the selected backend and yield a ``_SigningContext``.

    Dispatches to the native PC/SC backend (``--native``) or the PKCS#11 backend. Both select the
    signing certificate, print the identity block, and expose the same signer factories, so every
    sign-* command (single and batch) stays backend-agnostic. Warns first (pre-flight, before any
    PIN prompt) about options that don't apply to the chosen backend. Callers keep their own
    (fail-fast, pre-PIN) validation and timestamper build."""
    _warn_backend_options(
        native=native, reader=reader, pkcs11_lib=pkcs11_lib, token_label=token_label,
        cert_id=cert_id,
    )
    if native:
        with _native_signing_session(
            reader=reader, pin_source=pin_source, pin_env_var=pin_env_var, pin_fd=pin_fd,
            tsa_url=tsa_url, quiet=quiet,
        ) as ctx:
            yield ctx
    else:
        with _pkcs11_signing_session(
            pkcs11_lib=pkcs11_lib, token_label=token_label, cert_id=cert_id, pin_source=pin_source,
            pin_env_var=pin_env_var, pin_fd=pin_fd, tsa_url=tsa_url, quiet=quiet,
        ) as ctx:
            yield ctx


@contextmanager
def _pkcs11_signing_session(*, pkcs11_lib, token_label, cert_id, pin_source, pin_env_var, pin_fd,
                            tsa_url, quiet):
    """PKCS#11 backend: load the module, open a PIN session, select the signing certificate and print
    the identity block, then yield the context. The session is closed on exit."""
    # Validate the hex cert ID up front: a malformed --cert-id must fail before we prompt for the
    # PIN (an incorrect PIN counts toward the card's retry limit), not later inside select_certificate.
    if cert_id is not None:
        normalize_cert_id_hex(cert_id)
    lib = load_pkcs11_lib(pkcs11_lib)
    token = find_token(lib, token_label)
    final_pin = get_pin(pin_source, pin_env_var, pin_fd)
    with token.open(user_pin=final_pin) as session:
        key_id, cert = select_certificate(session, cert_id)
        signer_name = get_common_name(cert.subject)
        issuer_name = normalize_issuer_name(get_common_name(cert.issuer))
        cert_serial = format(cert.serial_number, "X")
        token_label_display = (getattr(token, "label", "") or "").strip() or "<no label>"
        _print_signing_info(
            token_label_display=token_label_display, signer_name=signer_name,
            issuer_name=issuer_name, key_id=key_id, cert_serial=cert_serial,
            tsa_url=tsa_url, quiet=quiet,
        )
        yield _SigningContext(
            cert=cert, signer_name=signer_name, issuer_name=issuer_name, cert_serial=cert_serial,
            pyhanko_signer_factory=lambda: PKCS11Signer(
                pkcs11_session=session, cert_id=key_id, key_id=key_id),
            raw_signer_factory=lambda: _make_raw_signer(session, key_id),
        )


@contextmanager
def _native_signing_session(*, reader, pin_source, pin_env_var, pin_fd, tsa_url, quiet):
    """Native PC/SC backend: open the reader, select the applet, read the public signing certificate,
    verify the PIN and yield the context. No PKCS#11 module is loaded. The connection is closed on
    exit. Do not run while a PKCS#11 sign session is open on the same card: both go through pcscd and
    will conflict."""
    from firmauy import native_card
    conn = open_reader(reader)
    try:
        select_applet(conn)
        cert = native_card.read_signing_certificate(conn)
        # Same validity guard the PKCS#11 path gets from select_certificate: never sign with an
        # expired / not-yet-valid certificate, and fail before prompting for the PIN.
        if cert_is_expired(cert) or cert_not_yet_valid(cert):
            if cert_is_expired(cert):
                reason = f"expired (valid until {cert_not_after(cert)})"
            else:
                reason = f"not yet valid (valid from {cert_not_before(cert)})"
            raise RuntimeError(
                f"The card's signing certificate is {reason}: {get_common_name(cert.subject)}"
            )
        signer_name = get_common_name(cert.subject)
        issuer_name = normalize_issuer_name(get_common_name(cert.issuer))
        cert_serial = format(cert.serial_number, "X")
        # Prompt/read the PIN only after the (PIN-free) cert read succeeds, so a reader/card problem
        # surfaces before we ask for a PIN. verify_pin refuses to spend the card's last retry.
        final_pin = get_pin(pin_source, pin_env_var, pin_fd)
        native_card.verify_pin(conn, final_pin)
        _print_signing_info(
            # The reader name pyscard resolved, so the identity block records the actual device
            # even when it was auto-detected rather than passed via --reader.
            token_label_display=conn.getReader(),
            signer_name=signer_name, issuer_name=issuer_name, key_id=None,
            cert_serial=cert_serial, tsa_url=tsa_url, quiet=quiet, source_caption="Reader",
        )
        # The pyHanko signer is built lazily through the factory (honoring _SigningContext's
        # contract: an XML-only sign never constructs it, nor loads the bundled trust anchors).
        sig_len = (cert.public_key().key_size + 7) // 8   # expected RSA signature size (256)
        yield _SigningContext(
            cert=cert, signer_name=signer_name, issuer_name=issuer_name, cert_serial=cert_serial,
            pyhanko_signer_factory=lambda: native_card.make_native_signer(conn, cert),
            raw_signer_factory=lambda: (
                lambda data: native_card.sign_message(conn, data, expected_len=sig_len)),
        )
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass


# Header names whose value is usually a secret. If passed literally via --tsa-header the value
# lands in argv (world-readable via `ps` / /proc), so warn and point at --tsa-header-env.
_SENSITIVE_HEADERS = frozenset({
    "authorization", "proxy-authorization", "x-api-key", "api-key", "x-auth-token", "x-auth",
})


def _build_timestamper(
    *,
    tsa_url: Optional[str],
    tsa_user: Optional[str],
    tsa_pass_env: Optional[str],
    tsa_header: Optional[List[str]],
    tsa_header_env: Optional[List[str]],
):
    """Build an HTTPTimeStamper from the TSA options, or None when no --tsa-url is given.

    Supports HTTP Basic auth (``--tsa-user`` + ``--tsa-pass-env``) and arbitrary extra headers for
    credentialed RFC 3161 TSAs. A header value may be literal (``--tsa-header 'Name: Value'``) or,
    for a secret, read from an environment variable (``--tsa-header-env 'Name: ENV_VAR'``) so it
    never appears in argv. Passwords/secrets are never taken on the command line. Raises
    ``typer.BadParameter`` on inconsistent options."""
    if tsa_url is None:
        if tsa_user or tsa_pass_env or tsa_header or tsa_header_env:
            raise typer.BadParameter(
                "--tsa-user / --tsa-pass-env / --tsa-header / --tsa-header-env require --tsa-url."
            )
        return None

    auth = None
    if tsa_user or tsa_pass_env:
        if not (tsa_user and tsa_pass_env):
            raise typer.BadParameter(
                "HTTP Basic auth for the TSA needs both --tsa-user and --tsa-pass-env."
            )
        password = os.environ.get(tsa_pass_env)
        if password is None:
            raise typer.BadParameter(
                f"Environment variable '{tsa_pass_env}' (from --tsa-pass-env) is not set."
            )
        auth = (tsa_user, password)

    headers: dict = {}
    # Literal headers: the value is on the command line. Warn if one looks like a credential.
    for item in (tsa_header or []):
        name, sep, value = item.partition(":")
        if not sep or not name.strip():
            raise typer.BadParameter(
                f"--tsa-header '{item}' must be in 'Name: Value' format."
            )
        nm = name.strip()
        if nm.lower() in _SENSITIVE_HEADERS:
            typer.secho(
                f"Warning: the value of --tsa-header '{nm}' is visible in the process list (argv). "
                "Use --tsa-header-env to read it from an environment variable instead.",
                fg=typer.colors.YELLOW, err=True,
            )
        headers[nm] = value.strip()
    # Env-backed headers: the value is read from an environment variable, kept off argv.
    for item in (tsa_header_env or []):
        name, sep, env_var = item.partition(":")
        if not sep or not name.strip() or not env_var.strip():
            raise typer.BadParameter(
                f"--tsa-header-env '{item}' must be in 'Name: ENV_VAR' format."
            )
        val = os.environ.get(env_var.strip())
        if val is None:
            raise typer.BadParameter(
                f"Environment variable '{env_var.strip()}' "
                f"(from --tsa-header-env '{name.strip()}') is not set."
            )
        headers[name.strip()] = val

    return HTTPTimeStamper(tsa_url, auth=auth, headers=headers or None)


def _warn_backend_options(*, native, reader, pkcs11_lib, token_label, cert_id) -> None:
    """Pre-flight (before the PIN): warn about options that don't apply to the chosen backend.

    In native mode --pkcs11-lib/--token-label/--cert-id are ignored (no PKCS#11 module is loaded), and
    the pcscd single-card caveat applies (same wording as fetch-identity). --reader only applies to
    the native backend, so it is a no-op with PKCS#11."""
    if native:
        ignored = [
            name for name, changed in (
                ("--pkcs11-lib", pkcs11_lib != DEFAULT_PKCS11_LIB),
                ("--token-label", token_label is not None),
                ("--cert-id", cert_id is not None),
            ) if changed
        ]
        if ignored:
            typer.secho(
                f"Note: {', '.join(ignored)} {'is' if len(ignored) == 1 else 'are'} ignored with "
                "--native (no PKCS#11 module is used).",
                fg=typer.colors.YELLOW, err=True,
            )
        typer.secho(
            "Note: --native talks to the card over PC/SC; do not run while a PKCS#11 session (other "
            "sign-* invocations) is active on the same card -- both go through pcscd and may conflict.",
            fg=typer.colors.YELLOW, err=True,
        )
    elif reader is not None:
        typer.secho(
            "Note: --reader only applies to --native; it is ignored with the PKCS#11 backend.",
            fg=typer.colors.YELLOW, err=True,
        )


def _warn_image_opacity_unused(image, image_mode, image_opacity) -> None:
    """--image-opacity only affects background mode; warn (once) if it was set for another mode."""
    if image and image_mode != ImageMode.background and image_opacity != DEFAULT_IMAGE_OPACITY:
        typer.secho(
            "Note: --image-opacity only applies to --image-mode background; it is ignored here.",
            fg=typer.colors.YELLOW, err=True,
        )


def _validate_image(image) -> None:
    """Fail early (in pre-flight, before the PIN/card session) if --image is not a usable image.
    typer only checks the file exists; this catches a corrupt file or a non-image."""
    if image is None:
        return
    from PIL import Image, UnidentifiedImageError
    try:
        with Image.open(image) as im:
            im.verify()
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise RuntimeError(f"--image '{image}' is not a valid image: {exc}")


def _validate_timezone(tz: str) -> None:
    """Fail early (in pre-flight, before the PIN/card) on an invalid --timezone, instead of
    after the PIN with a cryptic ZoneInfoNotFoundError (and once, not once per file in a batch)."""
    try:
        ZoneInfo(tz)
    except Exception as exc:
        raise typer.BadParameter(f"--timezone '{tz}' is not a valid IANA timezone ({exc}).")


def _batch_output(p: Path, input_dir: Optional[Path], output_dir: Path, ext: str, suffix: str) -> Path:
    """Output path for a batch input file. A file from ``--input-dir`` keeps its sub-directory
    structure under ``output_dir`` (so equally-named files in different sub-folders never collide
    under ``--recursive``); a positional file (``input_dir is None``) is placed flat by name.
    ``ext`` is like ``.pdf``; ``suffix`` is appended to the stem (e.g. ``_firmado``)."""
    name = f"{p.stem}{suffix}{ext}"
    if input_dir is None:
        return output_dir / name
    return output_dir / p.relative_to(input_dir).parent / name


def _raise_on_output_collisions(jobs: Iterable[tuple[Path, Path]]) -> None:
    """Fail fast (before the PIN) if two inputs map to the same output path. Without this a batch
    silently overwrites an earlier output with --overwrite, or fails mid-run without it. ``jobs`` is
    an iterable of (input_path, output_path)."""
    seen: dict[Path, Path] = {}
    collisions: list[tuple[Path, Path, Path]] = []
    for input_path, output in jobs:
        prior = seen.get(output)
        if prior is None:
            seen[output] = input_path
        else:
            collisions.append((prior, input_path, output))
    if collisions:
        detail = "\n".join(f"  '{a}' and '{b}' both map to {out}" for a, b, out in collisions)
        raise RuntimeError(
            "Output path collision: these inputs would write to the same file:\n"
            f"{detail}\n"
            "Rename an input, change --suffix, or sign the colliding files separately."
        )


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically: write a sibling ``.part`` then os.replace() it into
    place. os.replace() *replaces* an output symlink with the file instead of writing through it (so
    a pre-existing symlink at ``path`` cannot redirect the bytes elsewhere), and an interrupted write
    never leaves a truncated file at ``path`` -- the same guarantees the PDF signing path relies on."""
    tmp = path.with_name(path.name + ".part")
    try:
        tmp.write_bytes(data)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _sign_one_pdf(
    *,
    input_pdf: Path,
    output_pdf: Path,
    pkcs11_signer: "PKCS11Signer",
    signer_name: str,
    issuer_name: str,
    cert_serial: str,
    timestamper,
    meta: "signers.PdfSignatureMetadata",
    page: int,
    x1: int,
    y1: int,
    x2: int,
    y2: int,
    timezone: str,
    field_name: str,
    force: bool,
    overwrite: bool,
    image_path: Optional[Path] = None,
    image_mode: ImageMode = ImageMode.background,
    image_opacity: float = DEFAULT_IMAGE_OPACITY,
) -> None:
    """Sign a single PDF. Raises on any error."""
    if input_pdf.resolve() == output_pdf.resolve():
        raise RuntimeError(
            f"Input and output are the same file: {output_pdf}. "
            "Choose a different output path (in batch mode, adjust --output-dir or --suffix)."
        )
    if output_pdf.exists() and not overwrite:
        raise RuntimeError(
            f"Output file already exists: {output_pdf}\n"
            "Use --overwrite to overwrite it."
        )

    ensure_output_parent(output_pdf)

    with input_pdf.open("rb") as inf:
        writer = IncrementalPdfFileWriter(inf)

        existing_fields = list(fields.enumerate_sig_fields(writer))
        matching = [(name, val) for name, val, _ in existing_fields if name == field_name]
        if matching:
            _, field_value = matching[0]
            if field_value is not None:
                if not force:
                    raise RuntimeError(
                        f"Field '{field_name}' already contains a signature. "
                        "Use --force to continue anyway (the PDF may become invalid)."
                    )
                typer.secho(
                    f"Warning: field '{field_name}' already contains a signature. "
                    "Continuing due to --force (the PDF may become invalid).",
                    fg=typer.colors.YELLOW,
                    err=True,
                )
            else:
                typer.secho(
                    f"Warning: field '{field_name}' already exists but is unsigned, "
                    "it will be reused.",
                    fg=typer.colors.YELLOW,
                    err=True,
                )
        else:
            fields.append_signature_field(
                writer,
                sig_field_spec=fields.SigFieldSpec(
                    field_name,
                    on_page=page,
                    box=(x1, y1, x2, y2),
                ),
            )

        ts = datetime.now(ZoneInfo(timezone)).strftime("%d/%m/%Y %H:%M")

        appearance_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
                appearance_path = tmp.name

            make_appearance_pdf(
                appearance_path,
                signer=signer_name,
                cert_serial=cert_serial,
                ts=ts,
                issuer=issuer_name,
                image_path=str(image_path) if image_path else None,
                image_mode=image_mode,
                image_opacity=image_opacity,
            )

            pdf_signer = signers.PdfSigner(
                meta,
                signer=pkcs11_signer,
                timestamper=timestamper,
                stamp_style=stamp.StaticStampStyle.from_pdf_file(
                    appearance_path,
                    border_width=0,
                    background_layout=SimpleBoxLayoutRule(
                        x_align=AxisAlignment.ALIGN_MIN,
                        y_align=AxisAlignment.ALIGN_MIN,
                        margins=Margins(0, 0, 0, 0),
                        inner_content_scaling=InnerScaling.NO_SCALING,
                    ),
                ),
            )

            # Sign into a sibling temp file, then atomically move it into place. A failure
            # mid-signing (e.g. the card is pulled) then never leaves a partial/corrupt file at
            # output_pdf, and with --overwrite it never destroys the previous good output either.
            # (The XML/CMS paths get the same guarantee via _atomic_write_bytes.)
            # os.replace also *replaces* an output symlink with the signed file instead of writing
            # through it, so a pre-created symlink cannot redirect the output to another location.
            tmp_out = output_pdf.with_name(output_pdf.name + ".part")
            try:
                with tmp_out.open("wb") as outf:
                    pdf_signer.sign_pdf(writer, output=outf)
                os.replace(tmp_out, output_pdf)
            except BaseException:
                tmp_out.unlink(missing_ok=True)
                raise

        finally:
            if appearance_path:
                try:
                    Path(appearance_path).unlink(missing_ok=True)
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# Subcommand: list-tokens
# ---------------------------------------------------------------------------

@app.command("list-tokens")
def list_tokens(
    pkcs11_lib: str = typer.Option(
        DEFAULT_PKCS11_LIB, "--pkcs11-lib", help="Path to the PKCS#11 module.",
    ),
) -> None:
    """List all PKCS#11 tokens visible in the library."""
    try:
        lib = load_pkcs11_lib(pkcs11_lib)
        tokens = list(lib.get_tokens())
        if not tokens:
            typer.echo("No PKCS#11 tokens found.")
            return

        header = f"{'Label':<32}  {'Manufacturer':<20}  {'Model':<16}  Serial"
        typer.echo(header)
        typer.echo("-" * len(header))
        for token in tokens:
            label = (getattr(token, "label", "") or "").strip() or "<no label>"
            manufacturer = (getattr(token, "manufacturer", "") or "").strip() or "-"
            model = (getattr(token, "model", "") or "").strip() or "-"
            serial = (getattr(token, "serial", "") or "").strip() or "-"
            typer.echo(f"{label:<32}  {manufacturer:<20}  {model:<16}  {serial}")

    except Exception as exc:
        typer.secho(f"Error: {_format_error(exc)}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: list-certs
# ---------------------------------------------------------------------------

def _cert_digital_signature(cert) -> Optional[bool]:
    try:
        return bool(cert.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature)
    except x509.ExtensionNotFound:
        return None


def _cert_record(obj_id_hex: str, cert, include_pem: bool) -> dict:
    rec = {
        "id": obj_id_hex,
        "subject": name_fields(cert.subject),
        "issuer": name_fields(cert.issuer),
        "certificate_serial": format(cert.serial_number, "X"),
        "not_after": cert_not_after(cert),
        "digital_signature": _cert_digital_signature(cert),
    }
    if include_pem:
        rec["pem"] = cert.public_bytes(Encoding.PEM).decode().strip()
    return rec


def _redact_cert_record(rec: dict) -> dict:
    """Hide the cardholder's personal data for a shareable listing. The issuer (a public CA) is
    kept; the certificate serial and the PEM identify the holder, so they are hidden too."""
    out = dict(rec)
    out["subject"] = dict(rec["subject"])
    for k in ("common_name", "serial_number"):
        if out["subject"].get(k):
            out["subject"][k] = "[REDACTED]"
    out["certificate_serial"] = "[REDACTED]"
    if "pem" in out:
        out["pem"] = "[REDACTED]"
    return out


@app.command("list-certs")
def list_certs(
    pkcs11_lib: str = typer.Option(
        DEFAULT_PKCS11_LIB, "--pkcs11-lib", help="Path to the PKCS#11 module.",
    ),
    token_label: Optional[str] = typer.Option(
        None, "--token-label",
        help="Exact PKCS#11 token label. If not provided, auto-detected.",
    ),
    pin_source: Optional[PinSource] = typer.Option(
        None, "--pin-source",
        help="Optional. Certificates are public and read without login by default; set a PIN "
             "source (prompt, env, stdin, fd) only if your token requires login to list certs.",
    ),
    pin_env_var: Optional[str] = typer.Option(
        None, "--pin-env-var",
        help="Environment variable holding the PIN (requires --pin-source env).",
    ),
    pin_fd: Optional[int] = typer.Option(
        None, "--pin-fd",
        help="File descriptor holding the PIN (requires --pin-source fd).",
    ),
    pem: bool = typer.Option(
        False, "--pem",
        help="Output the certificate(s) as PEM instead of the human listing (pipeable, e.g. to "
             "'openssl x509 -text'). This is your leaf certificate, not a --ca-file trust anchor.",
    ),
    json_output: bool = typer.Option(
        False, "--json",
        help="Emit the certificate list as a single JSON object (schema_version 1); with --pem, "
             "each entry also includes a 'pem' field.",
    ),
    json_pretty: bool = typer.Option(
        False, "--json-pretty",
        help="Like --json but indented for humans (implies --json).",
    ),
    redact: bool = typer.Option(
        False, "--redact",
        help="Hide personal data (subject common name, document number, certificate serial and "
             "PEM) for sharing; the issuer (a public CA) is kept.",
    ),
) -> None:
    """List the certificates on the token: human-readable, --pem, or --json."""
    try:
        json_output = json_output or json_pretty
        if redact and pem and not json_output:
            raise RuntimeError(
                "--redact has no effect on raw --pem output (a certificate cannot be partially "
                "redacted); use --json --redact, or drop --pem."
            )

        lib = load_pkcs11_lib(pkcs11_lib)
        token = find_token(lib, token_label)
        final_pin = None if pin_source is None else get_pin(pin_source, pin_env_var, pin_fd)

        entries = []
        with token.open(user_pin=final_pin) as session:
            for cert_obj in iter_cert_objects(session):
                try:
                    obj_id = cert_obj[pkcs11.Attribute.ID]
                    cert = x509.load_der_x509_certificate(cert_obj[pkcs11.Attribute.VALUE])
                except Exception:
                    continue
                entries.append((obj_id.hex(), cert))

        if json_output:
            records = [_cert_record(oid, cert, include_pem=pem) for oid, cert in entries]
            if redact:
                records = [_redact_cert_record(r) for r in records]
            typer.echo(_json_dumps(
                {"schema_version": _JSON_SCHEMA_VERSION, "redacted": redact, "certificates": records},
                json_pretty))
            return

        if pem:
            for _, cert in entries:
                typer.echo(cert.public_bytes(Encoding.PEM).decode().rstrip())
            if not entries:
                typer.secho("No certificates found in the token.", fg=typer.colors.YELLOW, err=True)
            return

        if not entries:
            typer.echo("No certificates found in the token.")
            return
        for obj_id_hex, cert in entries:
            subject = "[REDACTED]" if redact else get_common_name(cert.subject)
            serial = "[REDACTED]" if redact else format(cert.serial_number, "X")
            ds = _cert_digital_signature(cert)
            typer.echo(
                f"ID:                {obj_id_hex}\n"
                f"Subject:           {subject}\n"
                f"Issuer:            {normalize_issuer_name(get_common_name(cert.issuer))}\n"
                f"Serial:            {serial}\n"
                f"Valid until:       {cert_not_after(cert)}\n"
                f"Digital signature: {'yes' if ds else ('?' if ds is None else 'no')}\n"
            )

    except Exception as exc:
        typer.secho(f"Error: {_format_error(exc)}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: sign-pdf
# ---------------------------------------------------------------------------

@app.command("sign-pdf")
def sign_pdf(
    input_pdf: Path = typer.Argument(..., exists=True, readable=True, help="Input PDF."),
    output_pdf: Optional[Path] = typer.Argument(None, help="Signed output PDF. Default: <input>_firmado.pdf"),
    pkcs11_lib: Pkcs11LibOpt = DEFAULT_PKCS11_LIB,
    token_label: TokenLabelOpt = None,
    cert_id: CertIdOpt = None,
    native: NativeOpt = False,
    reader: ReaderOpt = None,
    pin_source: PinSourceOpt = PinSource.prompt,
    pin_env_var: PinEnvVarOpt = None,
    pin_fd: PinFdOpt = None,
    field_name: FieldNameOpt = "Sig1",
    page: PageOpt = -1,
    x1: X1Opt = DEFAULT_X1,
    y1: Y1Opt = DEFAULT_Y1,
    x2: X2Opt = DEFAULT_X2,
    y2: Y2Opt = DEFAULT_Y2,
    timezone: TimezoneOpt = DEFAULT_TIMEZONE,
    reason: ReasonOpt = None,
    location: LocationOpt = None,
    contact_info: ContactInfoOpt = None,
    tsa_url: TsaUrlOpt = None,
    tsa_user: TsaUserOpt = None,
    tsa_pass_env: TsaPassEnvOpt = None,
    tsa_header: TsaHeaderOpt = None,
    tsa_header_env: TsaHeaderEnvOpt = None,
    overwrite: OverwriteOpt = False,
    force: ForceOpt = False,
    quiet: QuietOpt = False,
    verify: VerifyOpt = False,
    image: ImageOpt = None,
    image_mode: ImageModeOpt = ImageMode.background,
    image_opacity: ImageOpacityOpt = DEFAULT_IMAGE_OPACITY,
) -> None:
    """Sign a PDF with a Uruguayan cédula via PKCS#11 and pyHanko."""
    if output_pdf is None:
        output_pdf = input_pdf.with_stem(input_pdf.stem + "_firmado")
    try:
        # --- Pre-flight checks ---
        _warn_image_opacity_unused(image, image_mode, image_opacity)
        _validate_image(image)
        _validate_timezone(timezone)
        timestamper = _build_timestamper(
            tsa_url=tsa_url,
            tsa_user=tsa_user,
            tsa_pass_env=tsa_pass_env,
            tsa_header=tsa_header,
            tsa_header_env=tsa_header_env,
        )

        if input_pdf.resolve() == output_pdf.resolve():
            raise RuntimeError(
                "Input and output files are the same. "
                "Specify a different output path."
            )

        # Fail-fast before prompting for the PIN. _sign_one_pdf re-checks this
        # right before writing (the authoritative guard, also used by sign-pdf-batch);
        # here it only avoids asking for the PIN when we already know we'd refuse.
        if output_pdf.exists() and not overwrite:
            raise RuntimeError(
                f"Output file already exists: {output_pdf}\n"
                "Use --overwrite to overwrite it."
            )

        if x2 <= x1 or y2 <= y1:
            raise typer.BadParameter(
                "Coordinates must satisfy x1 < x2 and y1 < y2."
            )

        box_width = x2 - x1
        box_height = y2 - y1
        if box_width != APPEARANCE_WIDTH or box_height != APPEARANCE_HEIGHT:
            typer.secho(
                f"Warning: signature box ({box_width}x{box_height}) differs from "
                f"the reference size ({APPEARANCE_WIDTH}x{APPEARANCE_HEIGHT}). "
                "The appearance will be scaled.",
                fg=typer.colors.YELLOW,
                err=True,
            )

        with _signing_session(
            native=native, reader=reader,
            pkcs11_lib=pkcs11_lib, token_label=token_label, cert_id=cert_id,
            pin_source=pin_source, pin_env_var=pin_env_var, pin_fd=pin_fd,
            tsa_url=tsa_url, quiet=quiet,
        ) as ctx:

            meta = signers.PdfSignatureMetadata(
                field_name=field_name,
                reason=reason,
                location=location,
                contact_info=contact_info,
                md_algorithm=None,
            )

            _sign_one_pdf(
                input_pdf=input_pdf,
                output_pdf=output_pdf,
                pkcs11_signer=ctx.pyhanko_signer(),
                signer_name=ctx.signer_name,
                issuer_name=ctx.issuer_name,
                cert_serial=ctx.cert_serial,
                timestamper=timestamper,
                meta=meta,
                page=page,
                x1=x1,
                y1=y1,
                x2=x2,
                y2=y2,
                timezone=timezone,
                field_name=field_name,
                force=force,
                overwrite=overwrite,
                image_path=image,
                image_mode=image_mode,
                image_opacity=image_opacity,
            )

        if verify:
            _verify_after_pdf(output_pdf)
        typer.secho(f"PDF signed successfully: {output_pdf}", fg=typer.colors.GREEN)
        if verify:
            typer.secho("Verified: signature intact and covers the whole file.", fg=typer.colors.GREEN)

    except Exception as exc:
        typer.secho(f"Error: {_format_error(exc)}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: sign-pdf-batch
# ---------------------------------------------------------------------------

@app.command("sign-pdf-batch")
def sign_pdf_batch(
    input_pdfs: Optional[List[Path]] = typer.Argument(None, help="Input PDFs to sign."),
    output_dir: Path = typer.Option(..., "--output-dir", help="Directory where signed PDFs will be saved."),
    suffix: str = typer.Option("_firmado", "--suffix", help="Suffix appended to the base name of each output file."),
    input_dir: Optional[Path] = typer.Option(
        None, "--input-dir",
        help="Folder of PDFs to sign. Can be combined with positional arguments.",
    ),
    recursive: bool = typer.Option(
        False, "--recursive",
        help="Recursively search for PDFs in --input-dir.",
    ),
    pkcs11_lib: Pkcs11LibOpt = DEFAULT_PKCS11_LIB,
    token_label: TokenLabelOpt = None,
    cert_id: CertIdOpt = None,
    native: NativeOpt = False,
    reader: ReaderOpt = None,
    pin_source: PinSourceOpt = PinSource.prompt,
    pin_env_var: PinEnvVarOpt = None,
    pin_fd: PinFdOpt = None,
    field_name: FieldNameOpt = "Sig1",
    page: PageOpt = -1,
    x1: X1Opt = DEFAULT_X1,
    y1: Y1Opt = DEFAULT_Y1,
    x2: X2Opt = DEFAULT_X2,
    y2: Y2Opt = DEFAULT_Y2,
    timezone: TimezoneOpt = DEFAULT_TIMEZONE,
    reason: ReasonOpt = None,
    location: LocationOpt = None,
    contact_info: ContactInfoOpt = None,
    tsa_url: TsaUrlOpt = None,
    tsa_user: TsaUserOpt = None,
    tsa_pass_env: TsaPassEnvOpt = None,
    tsa_header: TsaHeaderOpt = None,
    tsa_header_env: TsaHeaderEnvOpt = None,
    overwrite: OverwriteOpt = False,
    force: ForceOpt = False,
    quiet: QuietOpt = False,
    verify: VerifyOpt = False,
    image: ImageOpt = None,
    image_mode: ImageModeOpt = ImageMode.background,
    image_opacity: ImageOpacityOpt = DEFAULT_IMAGE_OPACITY,
) -> None:
    """Sign multiple PDFs with a single PKCS#11 session (batch mode)."""
    try:
        _warn_image_opacity_unused(image, image_mode, image_opacity)
        _validate_image(image)
        _validate_timezone(timezone)
        timestamper = _build_timestamper(
            tsa_url=tsa_url,
            tsa_user=tsa_user,
            tsa_pass_env=tsa_pass_env,
            tsa_header=tsa_header,
            tsa_header_env=tsa_header_env,
        )

        # Build (input, output) jobs. Files from --input-dir keep their sub-directory structure
        # under --output-dir (so equally-named files in different sub-folders do not collide when
        # --recursive); positional files are placed flat by name.
        jobs: list[tuple[Path, Path]] = [
            (p, _batch_output(p, None, output_dir, ".pdf", suffix)) for p in (input_pdfs or [])
        ]

        if input_dir is not None:
            if not input_dir.is_dir():
                typer.secho(
                    f"--input-dir '{input_dir}' is not a valid directory.",
                    fg=typer.colors.RED,
                    err=True,
                )
                raise typer.Exit(code=1)
            pattern = "**/*.pdf" if recursive else "*.pdf"
            for p in sorted(input_dir.glob(pattern)):
                if p.is_file():
                    jobs.append((p, _batch_output(p, input_dir, output_dir, ".pdf", suffix)))

        if not jobs:
            typer.secho(
                "No input files specified. "
                "Use positional arguments or --input-dir.",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)

        if x2 <= x1 or y2 <= y1:
            typer.secho(
                "Coordinates must satisfy x1 < x2 and y1 < y2.",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)

        box_width = x2 - x1
        box_height = y2 - y1
        if box_width != APPEARANCE_WIDTH or box_height != APPEARANCE_HEIGHT:
            typer.secho(
                f"Warning: signature box ({box_width}x{box_height}) differs from "
                f"the reference size ({APPEARANCE_WIDTH}x{APPEARANCE_HEIGHT}). "
                "The appearance will be scaled.",
                fg=typer.colors.YELLOW,
                err=True,
            )

        _raise_on_output_collisions(jobs)
        output_dir.mkdir(parents=True, exist_ok=True)

        with _signing_session(
            native=native, reader=reader,
            pkcs11_lib=pkcs11_lib, token_label=token_label, cert_id=cert_id,
            pin_source=pin_source, pin_env_var=pin_env_var, pin_fd=pin_fd,
            tsa_url=tsa_url, quiet=quiet,
        ) as ctx:
            typer.echo(f"Files to sign:       {len(jobs)}")
            typer.echo("")

            pkcs11_signer = ctx.pyhanko_signer()

            meta = signers.PdfSignatureMetadata(
                field_name=field_name,
                reason=reason,
                location=location,
                contact_info=contact_info,
                md_algorithm=None,
            )

            ok_count = 0
            err_count = 0

            for input_pdf, output_pdf in jobs:
                try:
                    _sign_one_pdf(
                        input_pdf=input_pdf,
                        output_pdf=output_pdf,
                        pkcs11_signer=pkcs11_signer,
                        signer_name=ctx.signer_name,
                        issuer_name=ctx.issuer_name,
                        cert_serial=ctx.cert_serial,
                        timestamper=timestamper,
                        meta=meta,
                        page=page,
                        x1=x1,
                        y1=y1,
                        x2=x2,
                        y2=y2,
                        timezone=timezone,
                        field_name=field_name,
                        force=force,
                        overwrite=overwrite,
                        image_path=image,
                        image_mode=image_mode,
                        image_opacity=image_opacity,
                    )
                    if verify:
                        _verify_after_pdf(output_pdf)
                    typer.secho(f"OK:    {output_pdf}", fg=typer.colors.GREEN)
                    ok_count += 1
                except Exception as exc:
                    typer.secho(f"ERROR: {input_pdf}: {_format_error(exc)}", fg=typer.colors.RED, err=True)
                    err_count += 1

        typer.echo("")
        typer.echo(f"Signed: {ok_count}/{len(jobs)}. Errors: {err_count}.")

        if err_count:
            raise typer.Exit(code=1)

    except typer.Exit:
        raise
    except Exception as exc:
        typer.secho(f"Error: {_format_error(exc)}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# XML signing helpers (shared by sign-xml and sign-xml-batch)
# ---------------------------------------------------------------------------

def _make_raw_signer(session, key_id: bytes):
    """Return a callable that signs bytes on the token with RSA-SHA256."""
    priv = get_private_key(session, key_id)

    def raw_signer(data: bytes) -> bytes:
        return bytes(priv.sign(data, mechanism=pkcs11.Mechanism.SHA256_RSA_PKCS))

    return raw_signer


def _sign_one_xml(
    *,
    input_xml: Path,
    output_xml: Path,
    cert: "x509.Certificate",
    signer,
    signing_time: datetime,
    overwrite: bool,
    timestamper=None,
) -> None:
    """Sign a single XML (XAdES-BES, or XAdES-T with a timestamper). Raises on any error."""
    if input_xml.resolve() == output_xml.resolve():
        raise RuntimeError(
            f"Input and output are the same file: {output_xml}. "
            "Choose a different output path (in batch mode, adjust --output-dir or --suffix)."
        )
    if output_xml.exists() and not overwrite:
        raise RuntimeError(
            f"Output file already exists: {output_xml}\n"
            "Use --overwrite to overwrite it."
        )
    ensure_output_parent(output_xml)
    signed = sign_xml(
        input_xml.read_bytes(),
        cert=cert,
        signer=signer,
        signing_time=signing_time,
        timestamper=timestamper,
    )
    _atomic_write_bytes(output_xml, signed)


# ---------------------------------------------------------------------------
# CMS / CAdES signing helper (shared by sign-any and sign-any-batch)
# ---------------------------------------------------------------------------

def _sign_one_cms(
    *,
    input_file: Path,
    output_p7s: Path,
    pkcs11_signer: "PKCS11Signer",
    timestamper,
    overwrite: bool,
) -> None:
    """Sign a single file as a detached CAdES-BES ``.p7s``. Raises on any error."""
    if input_file.resolve() == output_p7s.resolve():
        raise RuntimeError(
            f"Input and output are the same file: {output_p7s}. "
            "Choose a different output path (in batch mode, adjust --output-dir or --suffix)."
        )
    if output_p7s.exists() and not overwrite:
        raise RuntimeError(
            f"Output file already exists: {output_p7s}\n"
            "Use --overwrite to overwrite it."
        )
    ensure_output_parent(output_p7s)
    with input_file.open("rb") as f:
        p7s = sign_cms_detached(f, signer=pkcs11_signer, timestamper=timestamper)
    _atomic_write_bytes(output_p7s, p7s)


# ---------------------------------------------------------------------------
# Post-sign self-check (--verify): re-verify the freshly produced signature for
# integrity and coverage (no trust), to catch a broken/corrupt output at once.
# ---------------------------------------------------------------------------

def _check_post_sign(result) -> None:
    """Raise if a post-sign verification result has any failed check."""
    failed = [c for c in result.checks if not c.ok]
    if failed:
        detail = "; ".join(c.name + (f" ({c.detail})" if c.detail else "") for c in failed)
        raise RuntimeError(
            f"post-sign verification failed (the produced signature is not intact): {detail}"
        )


def _verify_after_pdf(output_pdf: Path) -> None:
    # Only the signature we just appended (the last one); integrity + coverage, no trust.
    _check_post_sign(verify_pdf(output_pdf, trust_roots=None)[-1])


def _verify_after_xml(output_xml: Path) -> None:
    # Only the signature we just appended (the last one); integrity, no trust.
    _check_post_sign(verify_xml(output_xml.read_bytes(), trust_roots=None)[-1])


def _verify_after_cms(input_file: Path, output_p7s: Path) -> None:
    with input_file.open("rb") as data:
        _check_post_sign(verify_cms(data, output_p7s.read_bytes(), trust_roots=None))


# ---------------------------------------------------------------------------
# Subcommand: sign-xml
# ---------------------------------------------------------------------------

@app.command("sign-xml")
def sign_xml_cmd(
    input_xml: Path = typer.Argument(..., exists=True, readable=True, help="Input XML."),
    output_xml: Optional[Path] = typer.Argument(None, help="Signed output XML. Default: <input>_firmado.xml"),
    pkcs11_lib: Pkcs11LibOpt = DEFAULT_PKCS11_LIB,
    token_label: TokenLabelOpt = None,
    cert_id: CertIdOpt = None,
    native: NativeOpt = False,
    reader: ReaderOpt = None,
    pin_source: PinSourceOpt = PinSource.prompt,
    pin_env_var: PinEnvVarOpt = None,
    pin_fd: PinFdOpt = None,
    timezone: TimezoneOpt = DEFAULT_TIMEZONE,
    tsa_url: TsaUrlOpt = None,
    tsa_user: TsaUserOpt = None,
    tsa_pass_env: TsaPassEnvOpt = None,
    tsa_header: TsaHeaderOpt = None,
    tsa_header_env: TsaHeaderEnvOpt = None,
    overwrite: OverwriteOpt = False,
    quiet: QuietOpt = False,
    verify: VerifyOpt = False,
) -> None:
    """Sign an XML document with a Uruguayan cédula (XAdES-BES, or XAdES-T with --tsa-url)."""
    if output_xml is None:
        output_xml = input_xml.with_stem(input_xml.stem + "_firmado")
    try:
        if input_xml.resolve() == output_xml.resolve():
            raise RuntimeError(
                "Input and output files are the same. "
                "Specify a different output path."
            )
        if output_xml.exists() and not overwrite:
            raise RuntimeError(
                f"Output file already exists: {output_xml}\n"
                "Use --overwrite to overwrite it."
            )
        ensure_output_parent(output_xml)
        _validate_timezone(timezone)

        timestamper = _build_timestamper(
            tsa_url=tsa_url, tsa_user=tsa_user, tsa_pass_env=tsa_pass_env, tsa_header=tsa_header,
            tsa_header_env=tsa_header_env,
        )

        with _signing_session(
            native=native, reader=reader,
            pkcs11_lib=pkcs11_lib, token_label=token_label, cert_id=cert_id,
            pin_source=pin_source, pin_env_var=pin_env_var, pin_fd=pin_fd,
            tsa_url=tsa_url, quiet=quiet,
        ) as ctx:

            _sign_one_xml(
                input_xml=input_xml,
                output_xml=output_xml,
                cert=ctx.cert,
                signer=ctx.raw_signer(),
                signing_time=datetime.now(ZoneInfo(timezone)),
                overwrite=overwrite,
                timestamper=timestamper,
            )

        if verify:
            _verify_after_xml(output_xml)
        typer.secho(f"XML signed successfully: {output_xml}", fg=typer.colors.GREEN)
        if verify:
            typer.secho("Verified: signature intact.", fg=typer.colors.GREEN)

    except Exception as exc:
        typer.secho(f"Error: {_format_error(exc)}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: sign-xml-batch
# ---------------------------------------------------------------------------

@app.command("sign-xml-batch")
def sign_xml_batch(
    input_xmls: Optional[List[Path]] = typer.Argument(None, help="Input XMLs to sign."),
    output_dir: Path = typer.Option(..., "--output-dir", help="Directory where signed XMLs will be saved."),
    suffix: str = typer.Option("_firmado", "--suffix", help="Suffix appended to the base name of each output file."),
    input_dir: Optional[Path] = typer.Option(
        None, "--input-dir",
        help="Folder of XMLs to sign. Can be combined with positional arguments.",
    ),
    recursive: bool = typer.Option(
        False, "--recursive",
        help="Recursively search for XMLs in --input-dir.",
    ),
    pkcs11_lib: Pkcs11LibOpt = DEFAULT_PKCS11_LIB,
    token_label: TokenLabelOpt = None,
    cert_id: CertIdOpt = None,
    native: NativeOpt = False,
    reader: ReaderOpt = None,
    pin_source: PinSourceOpt = PinSource.prompt,
    pin_env_var: PinEnvVarOpt = None,
    pin_fd: PinFdOpt = None,
    timezone: TimezoneOpt = DEFAULT_TIMEZONE,
    tsa_url: TsaUrlOpt = None,
    tsa_user: TsaUserOpt = None,
    tsa_pass_env: TsaPassEnvOpt = None,
    tsa_header: TsaHeaderOpt = None,
    tsa_header_env: TsaHeaderEnvOpt = None,
    overwrite: OverwriteOpt = False,
    quiet: QuietOpt = False,
    verify: VerifyOpt = False,
) -> None:
    """Sign multiple XML documents with a single PKCS#11 session (XAdES-BES, or XAdES-T with --tsa-url)."""
    try:
        _validate_timezone(timezone)
        timestamper = _build_timestamper(
            tsa_url=tsa_url, tsa_user=tsa_user, tsa_pass_env=tsa_pass_env, tsa_header=tsa_header,
            tsa_header_env=tsa_header_env,
        )
        # (input, output) jobs: --input-dir files keep their sub-directory structure under
        # --output-dir (so equally-named files in different sub-folders do not collide when
        # --recursive); positional files are placed flat by name.
        jobs: list[tuple[Path, Path]] = [
            (p, _batch_output(p, None, output_dir, ".xml", suffix)) for p in (input_xmls or [])
        ]

        if input_dir is not None:
            if not input_dir.is_dir():
                typer.secho(
                    f"--input-dir '{input_dir}' is not a valid directory.",
                    fg=typer.colors.RED,
                    err=True,
                )
                raise typer.Exit(code=1)
            pattern = "**/*.xml" if recursive else "*.xml"
            for p in sorted(input_dir.glob(pattern)):
                if p.is_file():
                    jobs.append((p, _batch_output(p, input_dir, output_dir, ".xml", suffix)))

        if not jobs:
            typer.secho(
                "No input files specified. "
                "Use positional arguments or --input-dir.",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)

        _raise_on_output_collisions(jobs)
        output_dir.mkdir(parents=True, exist_ok=True)

        with _signing_session(
            native=native, reader=reader,
            pkcs11_lib=pkcs11_lib, token_label=token_label, cert_id=cert_id,
            pin_source=pin_source, pin_env_var=pin_env_var, pin_fd=pin_fd,
            tsa_url=tsa_url, quiet=quiet,
        ) as ctx:
            typer.echo(f"Files to sign:       {len(jobs)}")
            typer.echo("")

            raw_signer = ctx.raw_signer()

            ok_count = 0
            err_count = 0

            for input_xml, output_xml in jobs:
                try:
                    _sign_one_xml(
                        input_xml=input_xml,
                        output_xml=output_xml,
                        cert=ctx.cert,
                        signer=raw_signer,
                        signing_time=datetime.now(ZoneInfo(timezone)),
                        overwrite=overwrite,
                        timestamper=timestamper,
                    )
                    if verify:
                        _verify_after_xml(output_xml)
                    typer.secho(f"OK:    {output_xml}", fg=typer.colors.GREEN)
                    ok_count += 1
                except Exception as exc:
                    typer.secho(f"ERROR: {input_xml}: {_format_error(exc)}", fg=typer.colors.RED, err=True)
                    err_count += 1

        typer.echo("")
        typer.echo(f"Signed: {ok_count}/{len(jobs)}. Errors: {err_count}.")

        if err_count:
            raise typer.Exit(code=1)

    except typer.Exit:
        raise
    except Exception as exc:
        typer.secho(f"Error: {_format_error(exc)}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: sign-any
# ---------------------------------------------------------------------------

@app.command("sign-any")
def sign_any(
    input_file: Path = typer.Argument(..., exists=True, readable=True, dir_okay=False, help="File to sign (any type)."),
    output_p7s: Optional[Path] = typer.Argument(None, help="Detached signature output. Default: <input>.p7s"),
    pkcs11_lib: Pkcs11LibOpt = DEFAULT_PKCS11_LIB,
    token_label: TokenLabelOpt = None,
    cert_id: CertIdOpt = None,
    native: NativeOpt = False,
    reader: ReaderOpt = None,
    pin_source: PinSourceOpt = PinSource.prompt,
    pin_env_var: PinEnvVarOpt = None,
    pin_fd: PinFdOpt = None,
    tsa_url: TsaUrlOpt = None,
    tsa_user: TsaUserOpt = None,
    tsa_pass_env: TsaPassEnvOpt = None,
    tsa_header: TsaHeaderOpt = None,
    tsa_header_env: TsaHeaderEnvOpt = None,
    overwrite: OverwriteOpt = False,
    quiet: QuietOpt = False,
    verify: VerifyOpt = False,
) -> None:
    """Sign any file with a Uruguayan cédula, producing a detached CAdES-BES
    signature (.p7s, CMS/PKCS#7). The original file is left untouched."""
    if output_p7s is None:
        output_p7s = input_file.with_name(input_file.name + ".p7s")
    try:
        timestamper = _build_timestamper(
            tsa_url=tsa_url,
            tsa_user=tsa_user,
            tsa_pass_env=tsa_pass_env,
            tsa_header=tsa_header,
            tsa_header_env=tsa_header_env,
        )

        if input_file.resolve() == output_p7s.resolve():
            raise RuntimeError(
                "Input and output files are the same. "
                "Specify a different output path."
            )

        # Fail-fast before prompting for the PIN. _sign_one_cms re-checks this right
        # before writing (the authoritative guard, also used by sign-any-batch).
        if output_p7s.exists() and not overwrite:
            raise RuntimeError(
                f"Output file already exists: {output_p7s}\n"
                "Use --overwrite to overwrite it."
            )

        with _signing_session(
            native=native, reader=reader,
            pkcs11_lib=pkcs11_lib, token_label=token_label, cert_id=cert_id,
            pin_source=pin_source, pin_env_var=pin_env_var, pin_fd=pin_fd,
            tsa_url=tsa_url, quiet=quiet,
        ) as ctx:

            _sign_one_cms(
                input_file=input_file,
                output_p7s=output_p7s,
                pkcs11_signer=ctx.pyhanko_signer(),
                timestamper=timestamper,
                overwrite=overwrite,
            )

        if verify:
            _verify_after_cms(input_file, output_p7s)
        typer.secho(f"File signed successfully: {output_p7s}", fg=typer.colors.GREEN)
        if verify:
            typer.secho("Verified: signature intact.", fg=typer.colors.GREEN)

    except Exception as exc:
        typer.secho(f"Error: {_format_error(exc)}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: sign-any-batch
# ---------------------------------------------------------------------------

@app.command("sign-any-batch")
def sign_any_batch(
    input_files: Optional[List[Path]] = typer.Argument(None, help="Files to sign (any type)."),
    output_dir: Path = typer.Option(..., "--output-dir", help="Directory where .p7s signatures will be saved."),
    input_dir: Optional[Path] = typer.Option(
        None, "--input-dir",
        help="Folder of files to sign. Can be combined with positional arguments.",
    ),
    glob: str = typer.Option(
        "*", "--glob",
        help="Glob pattern selecting files in --input-dir (e.g. '*.zip'). Default: all files.",
    ),
    recursive: bool = typer.Option(
        False, "--recursive",
        help="Recursively search for files in --input-dir.",
    ),
    pkcs11_lib: Pkcs11LibOpt = DEFAULT_PKCS11_LIB,
    token_label: TokenLabelOpt = None,
    cert_id: CertIdOpt = None,
    native: NativeOpt = False,
    reader: ReaderOpt = None,
    pin_source: PinSourceOpt = PinSource.prompt,
    pin_env_var: PinEnvVarOpt = None,
    pin_fd: PinFdOpt = None,
    tsa_url: TsaUrlOpt = None,
    tsa_user: TsaUserOpt = None,
    tsa_pass_env: TsaPassEnvOpt = None,
    tsa_header: TsaHeaderOpt = None,
    tsa_header_env: TsaHeaderEnvOpt = None,
    overwrite: OverwriteOpt = False,
    quiet: QuietOpt = False,
    verify: VerifyOpt = False,
) -> None:
    """Sign multiple files with a single PKCS#11 session (detached CAdES-BES .p7s).

    Each output is named ``<input-name>.p7s`` inside --output-dir; files found under
    --input-dir keep their relative subdirectory, so equally named files in different
    subfolders (with --recursive) do not collide."""
    try:
        timestamper = _build_timestamper(
            tsa_url=tsa_url,
            tsa_user=tsa_user,
            tsa_pass_env=tsa_pass_env,
            tsa_header=tsa_header,
            tsa_header_env=tsa_header_env,
        )

        # (input_file, output_p7s) jobs. Positional files are named by basename; files found
        # under --input-dir keep their relative subdirectory under --output-dir, so identically
        # named files in different subfolders (with --recursive) do not collide.
        jobs = [(p, output_dir / f"{p.name}.p7s") for p in (input_files or [])]

        if input_dir is not None:
            if not input_dir.is_dir():
                typer.secho(
                    f"--input-dir '{input_dir}' is not a valid directory.",
                    fg=typer.colors.RED,
                    err=True,
                )
                raise typer.Exit(code=1)
            pattern = f"**/{glob}" if recursive else glob
            for p in sorted(input_dir.glob(pattern)):
                if p.is_file():
                    rel = p.relative_to(input_dir).as_posix()
                    jobs.append((p, output_dir / f"{rel}.p7s"))

        if not jobs:
            typer.secho(
                "No input files specified. "
                "Use positional arguments or --input-dir.",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)

        _raise_on_output_collisions(jobs)
        output_dir.mkdir(parents=True, exist_ok=True)

        with _signing_session(
            native=native, reader=reader,
            pkcs11_lib=pkcs11_lib, token_label=token_label, cert_id=cert_id,
            pin_source=pin_source, pin_env_var=pin_env_var, pin_fd=pin_fd,
            tsa_url=tsa_url, quiet=quiet,
        ) as ctx:
            typer.echo(f"Files to sign:       {len(jobs)}")
            typer.echo("")

            pkcs11_signer = ctx.pyhanko_signer()

            ok_count = 0
            err_count = 0

            for input_file, output_p7s in jobs:
                try:
                    _sign_one_cms(
                        input_file=input_file,
                        output_p7s=output_p7s,
                        pkcs11_signer=pkcs11_signer,
                        timestamper=timestamper,
                        overwrite=overwrite,
                    )
                    if verify:
                        _verify_after_cms(input_file, output_p7s)
                    typer.secho(f"OK:    {output_p7s}", fg=typer.colors.GREEN)
                    ok_count += 1
                except Exception as exc:
                    typer.secho(f"ERROR: {input_file}: {_format_error(exc)}", fg=typer.colors.RED, err=True)
                    err_count += 1

        typer.echo("")
        typer.echo(f"Signed: {ok_count}/{len(jobs)}. Errors: {err_count}.")

        if err_count:
            raise typer.Exit(code=1)

    except typer.Exit:
        raise
    except Exception as exc:
        typer.secho(f"Error: {_format_error(exc)}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommands: sign / sign-batch (auto-detect the signature type)
# ---------------------------------------------------------------------------

def _detect_input_kind(path: Path) -> str:
    """Detect an UNSIGNED input file's kind for signing: "pdf", "xml" or "any" (arbitrary -> CAdES).

    Mirrors _detect_signature_kind's magic-byte logic, but the fallback is "any" (sign arbitrary
    bytes as a detached CAdES .p7s) instead of attempting a CMS parse. An empty file is "any"."""
    with path.open("rb") as f:
        start = f.read(1024).lstrip(b"\xef\xbb\xbf").lstrip()
    if start[:1] == b"<":
        return "xml"
    if start.startswith(b"%PDF-"):
        return "pdf"
    return "any"


def _resolve_sign_kind(path: Path, sign_as: SignAs) -> str:
    """Resolve the signature kind ("pdf" | "xml" | "any") for an input, honoring --as.

    With SignAs.auto the kind is detected by content; otherwise the requested type is forced
    (cades -> "any", the detached CAdES signer)."""
    if sign_as is SignAs.auto:
        return _detect_input_kind(path)
    return {SignAs.pdf: "pdf", SignAs.xml: "xml", SignAs.cades: "any"}[sign_as]


def _warn_pdf_only_options(kind, *, image, reason, location, contact_info, force,
                           page, field_name, x1, y1, x2, y2) -> None:
    """For a single `sign` on a non-PDF input, warn that the PDF-only appearance/field options are
    ignored. Mirrors verify's "Note: --original is ignored for a {KIND} file" pattern, and only fires
    when such an option was actually set (so a plain `sign x.xml` stays quiet)."""
    if kind == "pdf":
        return
    if (image is not None or reason is not None or location is not None or contact_info is not None
            or force or page != -1 or field_name != "Sig1"
            or (x1, y1, x2, y2) != (DEFAULT_X1, DEFAULT_Y1, DEFAULT_X2, DEFAULT_Y2)):
        typer.secho(
            "Note: PDF appearance and field options (--image, position, --field-name, --force, "
            f"--reason/--location/--contact-info) are ignored for a {kind.upper()} signature.",
            fg=typer.colors.YELLOW, err=True,
        )


_SIGN_KIND_LABEL = {"pdf": "PAdES (PDF)", "xml": "XAdES (XML)", "any": "CAdES (.p7s)"}


@app.command("sign")
def sign_cmd(
    input_file: Path = typer.Argument(
        ..., exists=True, readable=True, dir_okay=False,
        help="File to sign. The signature type is auto-detected: PDF -> PAdES, XML -> XAdES, "
             "anything else -> detached CAdES (.p7s)."),
    output: Optional[Path] = typer.Argument(
        None,
        help="Output path. Default per type: <input>_firmado.pdf / <input>_firmado.xml / <input>.p7s."),
    sign_as: Annotated[SignAs, typer.Option(
        "--as",
        help="Force the signature type instead of auto-detecting: pdf (PAdES), xml (XAdES), "
             "cades (detached .p7s). Default: auto.")] = SignAs.auto,
    pkcs11_lib: Pkcs11LibOpt = DEFAULT_PKCS11_LIB,
    token_label: TokenLabelOpt = None,
    cert_id: CertIdOpt = None,
    native: NativeOpt = False,
    reader: ReaderOpt = None,
    pin_source: PinSourceOpt = PinSource.prompt,
    pin_env_var: PinEnvVarOpt = None,
    pin_fd: PinFdOpt = None,
    field_name: FieldNameOpt = "Sig1",
    page: PageOpt = -1,
    x1: X1Opt = DEFAULT_X1,
    y1: Y1Opt = DEFAULT_Y1,
    x2: X2Opt = DEFAULT_X2,
    y2: Y2Opt = DEFAULT_Y2,
    timezone: TimezoneOpt = DEFAULT_TIMEZONE,
    reason: ReasonOpt = None,
    location: LocationOpt = None,
    contact_info: ContactInfoOpt = None,
    tsa_url: TsaUrlOpt = None,
    tsa_user: TsaUserOpt = None,
    tsa_pass_env: TsaPassEnvOpt = None,
    tsa_header: TsaHeaderOpt = None,
    tsa_header_env: TsaHeaderEnvOpt = None,
    overwrite: OverwriteOpt = False,
    force: ForceOpt = False,
    quiet: QuietOpt = False,
    verify: VerifyOpt = False,
    image: ImageOpt = None,
    image_mode: ImageModeOpt = ImageMode.background,
    image_opacity: ImageOpacityOpt = DEFAULT_IMAGE_OPACITY,
) -> None:
    """Sign a file with a Uruguayan cédula, auto-detecting the signature type.

    PDF -> PAdES (embedded), XML -> XAdES (enveloped), anything else -> detached CAdES (.p7s). Pass
    --as to force a type (for example --as cades to produce a detached .p7s over a PDF or XML). The
    PDF appearance and field options (position, --image, --field-name, ...) apply only to a PDF.
    """
    try:
        kind = _resolve_sign_kind(input_file, sign_as)

        if output is None:
            output = (input_file.with_name(input_file.name + ".p7s") if kind == "any"
                      else input_file.with_stem(input_file.stem + "_firmado"))

        if input_file.resolve() == output.resolve():
            raise RuntimeError("Input and output files are the same. Specify a different output path.")
        if output.exists() and not overwrite:
            raise RuntimeError(f"Output file already exists: {output}\nUse --overwrite to overwrite it.")

        if kind == "pdf":
            _warn_image_opacity_unused(image, image_mode, image_opacity)
            _validate_image(image)
            if x2 <= x1 or y2 <= y1:
                raise typer.BadParameter("Coordinates must satisfy x1 < x2 and y1 < y2.")
            if (x2 - x1) != APPEARANCE_WIDTH or (y2 - y1) != APPEARANCE_HEIGHT:
                typer.secho(
                    f"Warning: signature box ({x2 - x1}x{y2 - y1}) differs from the reference size "
                    f"({APPEARANCE_WIDTH}x{APPEARANCE_HEIGHT}). The appearance will be scaled.",
                    fg=typer.colors.YELLOW, err=True,
                )
        else:
            _warn_pdf_only_options(
                kind, image=image, reason=reason, location=location, contact_info=contact_info,
                force=force, page=page, field_name=field_name, x1=x1, y1=y1, x2=x2, y2=y2,
            )
        if kind != "any":
            _validate_timezone(timezone)

        timestamper = _build_timestamper(
            tsa_url=tsa_url, tsa_user=tsa_user, tsa_pass_env=tsa_pass_env,
            tsa_header=tsa_header, tsa_header_env=tsa_header_env,
        )

        with _signing_session(
            native=native, reader=reader,
            pkcs11_lib=pkcs11_lib, token_label=token_label, cert_id=cert_id,
            pin_source=pin_source, pin_env_var=pin_env_var, pin_fd=pin_fd,
            tsa_url=tsa_url, quiet=quiet,
        ) as ctx:

            if kind == "pdf":
                meta = signers.PdfSignatureMetadata(
                    field_name=field_name, reason=reason, location=location,
                    contact_info=contact_info, md_algorithm=None,
                )
                _sign_one_pdf(
                    input_pdf=input_file, output_pdf=output, pkcs11_signer=ctx.pyhanko_signer(),
                    signer_name=ctx.signer_name, issuer_name=ctx.issuer_name,
                    cert_serial=ctx.cert_serial,
                    timestamper=timestamper, meta=meta, page=page, x1=x1, y1=y1, x2=x2, y2=y2,
                    timezone=timezone, field_name=field_name, force=force, overwrite=overwrite,
                    image_path=image, image_mode=image_mode, image_opacity=image_opacity,
                )
            elif kind == "xml":
                _sign_one_xml(
                    input_xml=input_file, output_xml=output, cert=ctx.cert,
                    signer=ctx.raw_signer(),
                    signing_time=datetime.now(ZoneInfo(timezone)),
                    overwrite=overwrite, timestamper=timestamper,
                )
            else:
                _sign_one_cms(
                    input_file=input_file, output_p7s=output, pkcs11_signer=ctx.pyhanko_signer(),
                    timestamper=timestamper, overwrite=overwrite,
                )

        if verify:
            if kind == "pdf":
                _verify_after_pdf(output)
            elif kind == "xml":
                _verify_after_xml(output)
            else:
                _verify_after_cms(input_file, output)

        typer.secho(f"Signed as {_SIGN_KIND_LABEL[kind]}: {output}", fg=typer.colors.GREEN)
        if verify:
            typer.secho("Verified: signature intact.", fg=typer.colors.GREEN)

    except Exception as exc:
        typer.secho(f"Error: {_format_error(exc)}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: sign-batch
# ---------------------------------------------------------------------------

@app.command("sign-batch")
def sign_batch(
    input_files: Optional[List[Path]] = typer.Argument(None, help="Files to sign (any type)."),
    output_dir: Path = typer.Option(..., "--output-dir", help="Directory where signed outputs are saved."),
    suffix: str = typer.Option(
        "_firmado", "--suffix",
        help="Suffix for PDF/XML output names. CAdES outputs are named <name>.p7s."),
    input_dir: Optional[Path] = typer.Option(
        None, "--input-dir",
        help="Folder of files to sign. Can be combined with positional arguments."),
    recursive: bool = typer.Option(False, "--recursive", help="Recursively search --input-dir."),
    glob: str = typer.Option(
        "*", "--glob", help="Glob selecting files in --input-dir (default: all files)."),
    sign_as: Annotated[SignAs, typer.Option(
        "--as",
        help="Force one signature type for every file (pdf|xml|cades) instead of detecting each. "
             "Default: auto.")] = SignAs.auto,
    pkcs11_lib: Pkcs11LibOpt = DEFAULT_PKCS11_LIB,
    token_label: TokenLabelOpt = None,
    cert_id: CertIdOpt = None,
    native: NativeOpt = False,
    reader: ReaderOpt = None,
    pin_source: PinSourceOpt = PinSource.prompt,
    pin_env_var: PinEnvVarOpt = None,
    pin_fd: PinFdOpt = None,
    field_name: FieldNameOpt = "Sig1",
    page: PageOpt = -1,
    x1: X1Opt = DEFAULT_X1,
    y1: Y1Opt = DEFAULT_Y1,
    x2: X2Opt = DEFAULT_X2,
    y2: Y2Opt = DEFAULT_Y2,
    timezone: TimezoneOpt = DEFAULT_TIMEZONE,
    reason: ReasonOpt = None,
    location: LocationOpt = None,
    contact_info: ContactInfoOpt = None,
    tsa_url: TsaUrlOpt = None,
    tsa_user: TsaUserOpt = None,
    tsa_pass_env: TsaPassEnvOpt = None,
    tsa_header: TsaHeaderOpt = None,
    tsa_header_env: TsaHeaderEnvOpt = None,
    overwrite: OverwriteOpt = False,
    force: ForceOpt = False,
    quiet: QuietOpt = False,
    verify: VerifyOpt = False,
    image: ImageOpt = None,
    image_mode: ImageModeOpt = ImageMode.background,
    image_opacity: ImageOpacityOpt = DEFAULT_IMAGE_OPACITY,
) -> None:
    """Sign many files of mixed types in a single PKCS#11 session.

    Each file is dispatched by its detected type: PDF -> PAdES, XML -> XAdES, anything else ->
    detached CAdES (.p7s). PDF appearance options apply to the PDF files in the mix. Pass --as to
    force one type for every file. Per-file errors do not stop the batch; the command exits non-zero
    if any file failed.
    """
    try:
        _warn_image_opacity_unused(image, image_mode, image_opacity)
        _validate_image(image)
        _validate_timezone(timezone)
        if x2 <= x1 or y2 <= y1:
            raise typer.BadParameter("Coordinates must satisfy x1 < x2 and y1 < y2.")
        timestamper = _build_timestamper(
            tsa_url=tsa_url, tsa_user=tsa_user, tsa_pass_env=tsa_pass_env,
            tsa_header=tsa_header, tsa_header_env=tsa_header_env,
        )

        # Gather (input, base): base is None for positionals, input_dir for dir-sourced (so
        # _batch_output can preserve sub-directory structure).
        items: list[tuple[Path, Optional[Path]]] = [(p, None) for p in (input_files or [])]
        if input_dir is not None:
            if not input_dir.is_dir():
                typer.secho(f"--input-dir '{input_dir}' is not a valid directory.",
                            fg=typer.colors.RED, err=True)
                raise typer.Exit(code=1)
            pattern = f"**/{glob}" if recursive else glob
            for p in sorted(input_dir.glob(pattern)):
                if p.is_file():
                    items.append((p, input_dir))
        if not items:
            typer.secho("No input files specified. Use positional arguments or --input-dir.",
                        fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)

        # Resolve each input's kind and output path up front (a 1 KB read per file, no card needed),
        # so output-path collisions are caught before the PIN. A detection failure here becomes a
        # per-file error below, not an abort.
        jobs: list[tuple[Path, str, Path]] = []
        predetect_errors: list[tuple[Path, Exception]] = []
        for input_path, base in items:
            try:
                kind = _resolve_sign_kind(input_path, sign_as)
                if kind == "pdf":
                    output = _batch_output(input_path, base, output_dir, ".pdf", suffix)
                elif kind == "xml":
                    output = _batch_output(input_path, base, output_dir, ".xml", suffix)
                else:
                    rel = (input_path.relative_to(base).as_posix()
                           if base is not None else input_path.name)
                    output = output_dir / f"{rel}.p7s"
                jobs.append((input_path, kind, output))
            except Exception as exc:
                predetect_errors.append((input_path, exc))

        # Fail fast (before the PIN) if two inputs would write to the same output. Otherwise that
        # silently overwrites with --overwrite, or errors mid-batch without it. PDF/XML outputs are
        # named by stem+suffix+ext, so same-stem inputs of different extensions that resolve to the
        # same kind collide (the CAdES <name>.p7s naming cannot).
        _raise_on_output_collisions((input_path, output) for input_path, _kind, output in jobs)

        output_dir.mkdir(parents=True, exist_ok=True)

        with _signing_session(
            native=native, reader=reader,
            pkcs11_lib=pkcs11_lib, token_label=token_label, cert_id=cert_id,
            pin_source=pin_source, pin_env_var=pin_env_var, pin_fd=pin_fd,
            tsa_url=tsa_url, quiet=quiet,
        ) as ctx:
            typer.echo(f"Files to sign:       {len(items)}")
            typer.echo("")

            # A mixed batch needs both signers bound to this one open session/card: a pyHanko
            # Signer (PDF/CMS) and a raw signer (XML).
            pkcs11_signer = ctx.pyhanko_signer()
            raw_signer = ctx.raw_signer()
            meta = signers.PdfSignatureMetadata(
                field_name=field_name, reason=reason, location=location,
                contact_info=contact_info, md_algorithm=None,
            )

            ok_count = 0
            err_count = 0
            for input_path, kind, output in jobs:
                try:
                    if kind == "pdf":
                        _sign_one_pdf(
                            input_pdf=input_path, output_pdf=output, pkcs11_signer=pkcs11_signer,
                            signer_name=ctx.signer_name, issuer_name=ctx.issuer_name,
                            cert_serial=ctx.cert_serial,
                            timestamper=timestamper, meta=meta, page=page, x1=x1, y1=y1, x2=x2, y2=y2,
                            timezone=timezone, field_name=field_name, force=force, overwrite=overwrite,
                            image_path=image, image_mode=image_mode, image_opacity=image_opacity,
                        )
                        if verify:
                            _verify_after_pdf(output)
                    elif kind == "xml":
                        _sign_one_xml(
                            input_xml=input_path, output_xml=output, cert=ctx.cert, signer=raw_signer,
                            signing_time=datetime.now(ZoneInfo(timezone)),
                            overwrite=overwrite, timestamper=timestamper,
                        )
                        if verify:
                            _verify_after_xml(output)
                    else:
                        _sign_one_cms(
                            input_file=input_path, output_p7s=output, pkcs11_signer=pkcs11_signer,
                            timestamper=timestamper, overwrite=overwrite,
                        )
                        if verify:
                            _verify_after_cms(input_path, output)
                    typer.secho(f"OK:    {output}  ({kind})", fg=typer.colors.GREEN)
                    ok_count += 1
                except Exception as exc:
                    typer.secho(f"ERROR: {input_path}: {_format_error(exc)}",
                                fg=typer.colors.RED, err=True)
                    err_count += 1

            # Inputs whose type could not be detected up front are reported here as errors.
            for input_path, exc in predetect_errors:
                typer.secho(f"ERROR: {input_path}: {_format_error(exc)}",
                            fg=typer.colors.RED, err=True)
                err_count += 1

        typer.echo("")
        typer.echo(f"Signed: {ok_count}/{len(items)}. Errors: {err_count}.")
        if err_count:
            raise typer.Exit(code=1)

    except typer.Exit:
        raise
    except Exception as exc:
        typer.secho(f"Error: {_format_error(exc)}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Verification helpers (shared by verify-xml and verify-pdf)
# ---------------------------------------------------------------------------

def _resolve_trust_anchors(ca_file: Optional[Path], no_trust: bool):
    """Return (roots, intermediates): from --ca-file, else the cached national CAs, else the
    certificates bundled with the package, else (None, None) with a hint. Returns (None, None)
    when trust is skipped."""
    if no_trust:
        return None, None
    if ca_file is not None:
        certs = x509.load_pem_x509_certificates(ca_file.read_bytes())
        roots = [c for c in certs if c.subject == c.issuer]
        intermediates = [c for c in certs if c.subject != c.issuer]
        if not roots:
            raise RuntimeError("--ca-file has no self-signed root certificate.")
        return roots, intermediates
    cached_roots, cached_intermediates = load_cached_trust_anchors()
    if cached_roots:
        return cached_roots, cached_intermediates
    bundled_roots, bundled_intermediates = load_bundled_trust_anchors()
    if bundled_roots:
        return bundled_roots, bundled_intermediates
    # Reached only if the bundled trust anchors could not be loaded (e.g. a broken install),
    # since they are otherwise always present.
    typer.secho(
        "Note: the bundled trust anchors could not be loaded; checking signature integrity\n"
        "      only. Pass --ca-file with the national CAs, or run 'firmauy fetch-cas'.",
        fg=typer.colors.YELLOW,
        err=True,
    )
    return None, None


def _resolve_tsa_anchors(tsa_ca: Optional[Path]):
    """Return (roots, others) for validating an XAdES-T timestamp's TSA, loaded from --tsa-ca, or
    (None, None) if not given. Self-signed certs are anchors; the rest are path-building
    intermediates. With no self-signed cert, all are treated as anchors (the user chose to trust
    exactly this set)."""
    if tsa_ca is None:
        return None, None
    certs = x509.load_pem_x509_certificates(tsa_ca.read_bytes())
    if not certs:
        raise RuntimeError("--tsa-ca contains no certificates.")
    roots = [c for c in certs if c.subject == c.issuer]
    others = [c for c in certs if c.subject != c.issuer]
    if not roots:
        roots, others = certs, []
    return roots, others


def _display_name(fields: dict, redact: bool = False) -> str:
    """One-line human display of a structured signer/issuer name."""
    if redact and (fields.get("common_name") or fields.get("serial_number")):
        return "[REDACTED]"
    parts = [p for p in (fields.get("common_name"), fields.get("serial_number")) if p]
    return ", ".join(parts) if parts else "(unknown)"


def _print_verify_result(result, prefix: str = "", redact: bool = False) -> None:
    """Print one verification result (signer + per-check breakdown)."""
    if prefix:
        typer.echo(prefix)
    issuer = _redact_issuer(result.issuer, result.signer) if redact else result.issuer
    typer.echo(f"Signer:  {_display_name(result.signer, redact)}")
    typer.echo(f"Issuer:  {_display_name(issuer)}")
    typer.echo("")
    for c in result.checks:
        mark = "PASS" if c.ok else "FAIL"
        color = typer.colors.GREEN if c.ok else typer.colors.RED
        detail = _redact_detail(c.detail) if redact else c.detail
        typer.secho(f"  [{mark}] {c.name}" + (f"  ({detail})" if detail else ""), fg=color)
    typer.echo("")


_INDICATION_COLOR = {
    "VALID": typer.colors.GREEN,
    "INDETERMINATE": typer.colors.YELLOW,
    "INVALID": typer.colors.RED,
}
_INDICATION_RANK = {"VALID": 0, "INDETERMINATE": 1, "INVALID": 2}

# Public, versioned JSON contract for the verify commands (decoupled from the internal
# VerifyResult dataclass, so it can be refactored without breaking consumers).
_JSON_SCHEMA_VERSION = 1

# Signer fields hidden by --redact (personal data). The issuer is a public CA and is kept.
_REDACT_FIELDS = ("common_name", "serial_number", "certificate_serial")


def _redact_signer(signer: dict) -> dict:
    out = dict(signer)
    for k in _REDACT_FIELDS:
        if out.get(k):
            out[k] = "[REDACTED]"
    return out


def _redact_detail(detail: str) -> str:
    """A check ``detail`` is free text: a coverage name, a genTime, but also a raw chain-validation
    error that embeds the certificate subject DN (holder name + document number). For a shareable
    --redact output we cannot reliably tell which details carry personal data, so any non-empty
    detail is hidden; the check ``name`` and PASS/FAIL stay, which is what makes the report useful."""
    return "[REDACTED]" if detail else detail


def _redact_issuer(issuer: dict, signer: dict) -> dict:
    """The issuer of a cédula is a public CA (the Ministerio del Interior), so it is kept under
    --redact. But for a self-issued certificate the issuer *is* the holder, and keeping it would
    defeat --redact; redact the issuer's personal fields in that (only) case."""
    self_issued = (
        bool(issuer.get("common_name"))
        and issuer.get("common_name") == signer.get("common_name")
        and issuer.get("serial_number") == signer.get("serial_number")
    )
    if not self_issued:
        return issuer
    out = dict(issuer)
    for k in ("common_name", "serial_number"):
        if out.get(k):
            out[k] = "[REDACTED]"
    return out


def _result_to_json_obj(result, redact: bool) -> dict:
    return {
        "indication": result.indication,
        "signer": _redact_signer(result.signer) if redact else result.signer,
        "issuer": _redact_issuer(result.issuer, result.signer) if redact else result.issuer,
        "trusted": result.trusted,
        "checks": [
            {"name": c.name, "ok": c.ok, "detail": _redact_detail(c.detail) if redact else c.detail}
            for c in result.checks
        ],
    }


def _json_dumps(obj: dict, pretty: bool) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2 if pretty else None)


def _emit_verify(results: list, json_output: bool, pretty: bool = False, redact: bool = False) -> str:
    """Emit verification results and return the overall indication (worst of all signatures).

    With ``json_output`` a single JSON object is written to stdout; otherwise the human-readable
    per-check breakdown is printed. ``pretty`` indents the JSON; ``redact`` hides the signer's
    personal fields (issuer kept). Exit codes are decided by the caller from the returned
    indication, so they are identical in every mode.

        {"schema_version": 1, "redacted": false, "indication": "...", "signatures": [
            {"indication", "signer": {...}, "issuer": {...}, "trusted",
             "checks": [{"name","ok","detail"}]}]}
    """
    overall = max((r.indication for r in results), key=lambda ind: _INDICATION_RANK[ind])
    if json_output:
        payload = {
            "schema_version": _JSON_SCHEMA_VERSION,
            "redacted": redact,
            "indication": overall,
            "signatures": [_result_to_json_obj(r, redact) for r in results],
        }
        typer.echo(_json_dumps(payload, pretty))
    else:
        for i, result in enumerate(results, 1):
            prefix = f"--- Signature {i} of {len(results)} ---" if len(results) > 1 else ""
            _print_verify_result(result, prefix, redact)
        typer.secho(f"Indication: {overall}", fg=_INDICATION_COLOR[overall], bold=True)
    return overall


def _emit_verify_error(exc: Exception, json_output: bool, pretty: bool = False) -> None:
    """Report a hard error: a JSON ``{"error": ...}`` on stdout in --json mode (so stdout is
    always parseable), or a coloured message on stderr otherwise."""
    if json_output:
        typer.echo(_json_dumps({"schema_version": _JSON_SCHEMA_VERSION, "error": _format_error(exc)}, pretty))
    else:
        typer.secho(f"Error: {_format_error(exc)}", fg=typer.colors.RED, err=True)


_JSON_OPT_HELP = (
    "Emit the result as a single JSON object on stdout (schema_version 1); "
    "exit codes are unchanged."
)
_JSON_PRETTY_OPT_HELP = "Like --json but indented for humans (implies --json)."
_REDACT_OPT_HELP = (
    "Hide personal data (signer name, document and certificate serials) in the output, "
    "e.g. for sharing logs or issues."
)
_TSA_CA_OPT_HELP = (
    "PEM bundle of the trusted timestamping authority's certificate(s), for an XAdES-T XML. When "
    "given, the timestamp's TSA is validated and, on success, the signing certificate is evaluated "
    "at the trusted timestamp time (long-term validation). Without it the timestamp is only checked "
    "to bind to the signature (the TSA is not trusted). PDF/CMS timestamps use --ca-file instead."
)


# ---------------------------------------------------------------------------
# Subcommand: verify-xml
# ---------------------------------------------------------------------------

@app.command("verify-xml")
def verify_xml_cmd(
    input_xml: Path = typer.Argument(..., exists=True, readable=True, help="Signed XML to verify."),
    ca_file: Optional[Path] = typer.Option(
        None, "--ca-file",
        help="PEM bundle of trust anchors (root + intermediates). "
             "Defaults to the national CAs bundled with the package.",
    ),
    no_trust: bool = typer.Option(
        False, "--no-trust",
        help="Only check signature integrity (level 1); skip the certificate chain.",
    ),
    check_revocation: bool = typer.Option(
        False, "--check-revocation",
        help="Also check certificate revocation via CRL/OCSP (level 3). Requires network.",
    ),
    tsa_ca: Optional[Path] = typer.Option(
        None, "--tsa-ca", exists=True, readable=True, dir_okay=False, help=_TSA_CA_OPT_HELP),
    json_output: bool = typer.Option(False, "--json", help=_JSON_OPT_HELP),
    json_pretty: bool = typer.Option(False, "--json-pretty", help=_JSON_PRETTY_OPT_HELP),
    redact: bool = typer.Option(False, "--redact", help=_REDACT_OPT_HELP),
) -> None:
    """Verify a signed XAdES XML: signature integrity, and (unless --no-trust) the
    certificate chain up to the Uruguayan national root.

    Indication: VALID (integrity + trusted chain), INDETERMINATE (integrity OK but
    chain not trusted/not checked), INVALID (signature broken or document modified).
    Note: revocation (CRL/OCSP) is not checked. For XAdES-BES (no timestamp) the signing time is
    self-asserted, so validity is evaluated at verification time; with --tsa-ca a XAdES-T timestamp
    is trust-validated and the certificate is evaluated at the trusted timestamp time instead.
    """
    try:
        json_output = json_output or json_pretty
        if check_revocation and no_trust:
            raise RuntimeError("--check-revocation requires the certificate chain; remove --no-trust.")

        roots, intermediates = _resolve_trust_anchors(ca_file, no_trust)
        tsa_roots, tsa_others = _resolve_tsa_anchors(tsa_ca)

        results = verify_xml(
            input_xml.read_bytes(),
            trust_roots=roots,
            intermediates=intermediates,
            check_revocation=check_revocation,
            tsa_trust_roots=tsa_roots,
            tsa_other_certs=tsa_others,
        )

        overall = _emit_verify(results, json_output, pretty=json_pretty, redact=redact)
        if overall == "INVALID":
            raise typer.Exit(code=1)
        if overall == "INDETERMINATE":
            raise typer.Exit(code=2)

    except typer.Exit:
        raise
    except Exception as exc:
        _emit_verify_error(exc, json_output, pretty=json_pretty)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: verify-pdf
# ---------------------------------------------------------------------------

@app.command("verify-pdf")
def verify_pdf_cmd(
    input_pdf: Path = typer.Argument(..., exists=True, readable=True, help="Signed PDF to verify."),
    ca_file: Optional[Path] = typer.Option(
        None, "--ca-file",
        help="PEM bundle of trust anchors (root + intermediates). "
             "Defaults to the national CAs bundled with the package.",
    ),
    no_trust: bool = typer.Option(
        False, "--no-trust",
        help="Only check signature integrity; skip the certificate chain.",
    ),
    check_revocation: bool = typer.Option(
        False, "--check-revocation",
        help="Also check certificate revocation via CRL/OCSP. Requires network.",
    ),
    json_output: bool = typer.Option(False, "--json", help=_JSON_OPT_HELP),
    json_pretty: bool = typer.Option(False, "--json-pretty", help=_JSON_PRETTY_OPT_HELP),
    redact: bool = typer.Option(False, "--redact", help=_REDACT_OPT_HELP),
) -> None:
    """Verify the signatures in a PDF (PAdES): integrity, coverage, and (unless --no-trust)
    the certificate chain up to the Uruguayan national root.

    Same indication model as verify-xml (VALID / INDETERMINATE / INVALID); with multiple
    signatures, the overall indication is the worst one. Exit: 0 VALID, 1 INVALID, 2 INDETERMINATE.
    """
    try:
        json_output = json_output or json_pretty
        if check_revocation and no_trust:
            raise RuntimeError("--check-revocation requires the certificate chain; remove --no-trust.")

        roots, intermediates = _resolve_trust_anchors(ca_file, no_trust)

        results = verify_pdf(
            input_pdf,
            trust_roots=roots,
            intermediates=intermediates,
            check_revocation=check_revocation,
        )

        overall = _emit_verify(results, json_output, pretty=json_pretty, redact=redact)
        if overall == "INVALID":
            raise typer.Exit(code=1)
        if overall == "INDETERMINATE":
            raise typer.Exit(code=2)

    except typer.Exit:
        raise
    except Exception as exc:
        _emit_verify_error(exc, json_output, pretty=json_pretty)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: verify-any
# ---------------------------------------------------------------------------

@app.command("verify-any")
def verify_any_cmd(
    input_file: Path = typer.Argument(..., exists=True, readable=True, dir_okay=False, help="Original file that was signed."),
    p7s_file: Optional[Path] = typer.Argument(None, help="Detached signature (.p7s). Default: <input>.p7s"),
    ca_file: Optional[Path] = typer.Option(
        None, "--ca-file",
        help="PEM bundle of trust anchors (root + intermediates). "
             "Defaults to the national CAs bundled with the package.",
    ),
    no_trust: bool = typer.Option(
        False, "--no-trust",
        help="Only check signature integrity; skip the certificate chain.",
    ),
    check_revocation: bool = typer.Option(
        False, "--check-revocation",
        help="Also check certificate revocation via CRL/OCSP. Requires network.",
    ),
    json_output: bool = typer.Option(False, "--json", help=_JSON_OPT_HELP),
    json_pretty: bool = typer.Option(False, "--json-pretty", help=_JSON_PRETTY_OPT_HELP),
    redact: bool = typer.Option(False, "--redact", help=_REDACT_OPT_HELP),
) -> None:
    """Verify a detached CAdES/.p7s signature over a file: integrity and (unless
    --no-trust) the certificate chain up to the Uruguayan national root.

    The original file and its detached signature are both required. Same indication
    model as verify-xml/verify-pdf (VALID / INDETERMINATE / INVALID).
    Exit: 0 VALID, 1 INVALID, 2 INDETERMINATE.
    """
    if p7s_file is None:
        p7s_file = input_file.with_name(input_file.name + ".p7s")
    try:
        json_output = json_output or json_pretty
        if check_revocation and no_trust:
            raise RuntimeError("--check-revocation requires the certificate chain; remove --no-trust.")
        if not p7s_file.exists():
            raise RuntimeError(
                f"Detached signature not found: {p7s_file}\n"
                "Pass the .p7s path explicitly as the second argument."
            )

        roots, intermediates = _resolve_trust_anchors(ca_file, no_trust)

        # Stream the (possibly large) signed file instead of loading it into memory; only the
        # small detached signature is read whole.
        with input_file.open("rb") as data:
            result = verify_cms(
                data,
                p7s_file.read_bytes(),
                trust_roots=roots,
                intermediates=intermediates,
                check_revocation=check_revocation,
            )

        overall = _emit_verify([result], json_output, pretty=json_pretty, redact=redact)
        if overall == "INVALID":
            raise typer.Exit(code=1)
        if overall == "INDETERMINATE":
            raise typer.Exit(code=2)

    except typer.Exit:
        raise
    except Exception as exc:
        _emit_verify_error(exc, json_output, pretty=json_pretty)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: verify (auto-detect)
# ---------------------------------------------------------------------------

# A detached CMS/.p7s is small (signature + certs, a few KB). Cap how much _detect_signature_kind
# reads when probing for CMS, so a large unrelated file is not slurped whole just to fail the parse.
_CMS_DETECT_MAX_BYTES = 8 * 1024 * 1024


def _detect_signature_kind(path: Path) -> str:
    """Detect a signed file's format by content: "pdf", "xml" (XAdES) or "cms" (detached
    .p7s in DER). Raises ValueError if none match.

    Only a 1 KB prefix is read to recognise PDF or XML; for the CMS (DER) case the read is bounded to
    _CMS_DETECT_MAX_BYTES -- a detached ``.p7s`` is small, so a larger file is not a detached
    signature and is not read whole into memory."""
    from asn1crypto import cms as asn1cms

    with path.open("rb") as f:
        head = f.read(1024)
        if not head:
            raise ValueError("file is empty")
        # Logical start: skip a UTF-8 BOM and any leading whitespace.
        start = head.lstrip(b"\xef\xbb\xbf").lstrip()
        if start[:1] == b"<":
            return "xml"
        # The PDF header must be at the (logical) start, not merely somewhere in the first KB, so
        # an XML or CMS that only *contains* the bytes "%PDF-" is not misdetected as a PDF.
        if start.startswith(b"%PDF-"):
            return "pdf"
        # Not PDF/XML: read the rest (bounded) and try to parse it as detached CMS (DER). The +1
        # lets an over-cap file produce len(raw) > cap so it is skipped rather than parsed truncated.
        raw = head + f.read(max(0, _CMS_DETECT_MAX_BYTES - len(head)) + 1)
    if len(raw) <= _CMS_DETECT_MAX_BYTES:
        try:
            ci = asn1cms.ContentInfo.load(raw)
            if ci["content_type"].native == "signed_data":
                return "cms"
        except Exception:
            pass
    raise ValueError("could not detect the signature type (not a PDF, XAdES XML or CMS/.p7s)")


def _detached_original(p7s_path: Path) -> Optional[Path]:
    """The original file a detached .p7s signs, by the '<x>.p7s -> <x>' convention."""
    return p7s_path.with_suffix("") if p7s_path.suffix == ".p7s" else None


@app.command("verify")
def verify_cmd(
    input_file: Path = typer.Argument(..., exists=True, readable=True, dir_okay=False,
                                      help="Signed file: PDF, XAdES XML or detached CMS/.p7s (auto-detected by content)."),
    original: Optional[Path] = typer.Option(
        None, "--original",
        help="For a detached .p7s only: the original file it signs "
             "(default: the .p7s path without that suffix).",
    ),
    ca_file: Optional[Path] = typer.Option(
        None, "--ca-file",
        help="PEM bundle of trust anchors (root + intermediates). "
             "Defaults to the national CAs bundled with the package.",
    ),
    no_trust: bool = typer.Option(
        False, "--no-trust",
        help="Only check signature integrity; skip the certificate chain.",
    ),
    check_revocation: bool = typer.Option(
        False, "--check-revocation",
        help="Also check certificate revocation via CRL/OCSP. Requires network.",
    ),
    tsa_ca: Optional[Path] = typer.Option(
        None, "--tsa-ca", exists=True, readable=True, dir_okay=False, help=_TSA_CA_OPT_HELP),
    json_output: bool = typer.Option(False, "--json", help=_JSON_OPT_HELP),
    json_pretty: bool = typer.Option(False, "--json-pretty", help=_JSON_PRETTY_OPT_HELP),
    redact: bool = typer.Option(False, "--redact", help=_REDACT_OPT_HELP),
) -> None:
    """Verify a signed file, auto-detecting its format (PDF / XAdES XML / detached CMS .p7s)
    and dispatching to the matching verifier.

    Same checks, flags, indication model and exit codes as the specific verify-* commands
    (0 VALID, 1 INVALID, 2 INDETERMINATE). A detached .p7s also needs its original file:
    by default the '<x>.p7s -> <x>' name is used, or pass --original. --tsa-ca applies only to a
    XAdES-T XML.
    """
    try:
        json_output = json_output or json_pretty
        if check_revocation and no_trust:
            raise RuntimeError("--check-revocation requires the certificate chain; remove --no-trust.")

        kind = _detect_signature_kind(input_file)

        # For a detached .p7s, locate the original up front (before resolving trust anchors, so a
        # missing original fails fast). --original is meaningful only here.
        orig = None
        if kind == "cms":
            orig = original or _detached_original(input_file)
            if orig is None or not orig.exists():
                raise RuntimeError(
                    "detached .p7s signature needs its original file; pass it with --original"
                    + (f" (looked for '{orig}')" if orig is not None else "")
                )
        elif original is not None:
            typer.secho(
                f"Note: --original is ignored for a {kind.upper()} file "
                "(it only applies to a detached .p7s).",
                fg=typer.colors.YELLOW, err=True,
            )

        if tsa_ca is not None and kind != "xml":
            typer.secho(
                f"Note: --tsa-ca is ignored for a {kind.upper()} file "
                "(it applies to a XAdES-T XML; PDF/CMS timestamps use --ca-file).",
                fg=typer.colors.YELLOW, err=True,
            )

        roots, intermediates = _resolve_trust_anchors(ca_file, no_trust)

        if kind == "pdf":
            results = verify_pdf(input_file, trust_roots=roots, intermediates=intermediates,
                                 check_revocation=check_revocation)
        elif kind == "xml":
            tsa_roots, tsa_others = _resolve_tsa_anchors(tsa_ca)
            results = verify_xml(input_file.read_bytes(), trust_roots=roots,
                                 intermediates=intermediates, check_revocation=check_revocation,
                                 tsa_trust_roots=tsa_roots, tsa_other_certs=tsa_others)
        else:  # cms / detached .p7s
            with orig.open("rb") as data:
                results = [verify_cms(data, input_file.read_bytes(), trust_roots=roots,
                                      intermediates=intermediates, check_revocation=check_revocation)]

        overall = _emit_verify(results, json_output, pretty=json_pretty, redact=redact)
        if overall == "INVALID":
            raise typer.Exit(code=1)
        if overall == "INDETERMINATE":
            raise typer.Exit(code=2)

    except typer.Exit:
        raise
    except Exception as exc:
        _emit_verify_error(exc, json_output, pretty=json_pretty)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: fetch-cas
# ---------------------------------------------------------------------------

@app.command("fetch-cas")
def fetch_cas_cmd(
    from_file: Optional[List[Path]] = typer.Option(
        None, "--from-file",
        exists=True, readable=True, dir_okay=False,
        help="PEM/DER file(s) to seed the cache from instead of downloading. Any "
             "certificate matching a pinned fingerprint (national root and/or the "
             "Ministerio del Interior intermediate) is used; anything not supplied is "
             "downloaded. Useful when the intermediate's source is unreachable (its "
             "official server is decommissioned). Repeatable; bundles are accepted.",
    ),
) -> None:
    """Optional: refresh the national CA certificates from the network.

    Not normally needed: verification already works offline using the certificates bundled
    with the package. This only re-downloads them into a per-user cache (which takes precedence
    over the bundled copies). Each certificate is verified against a pinned fingerprint before
    caching, and the intermediate is checked to be signed by the root, so the cache can only
    ever hold the same pinned certificates. The root downloads reliably; the Ministerio del
    Interior intermediate's official server is decommissioned, so it falls back to a Certificate
    Transparency mirror, or pass a local copy with --from-file.
    """
    try:
        acrn_path, mica_path = fetch_cas(
            progress=lambda msg: typer.secho(msg, fg=typer.colors.YELLOW, err=True),
            source_files=from_file,
        )
        typer.secho(f"National CAs cached in {cache_dir()}", fg=typer.colors.GREEN)
        typer.echo(f"  root:         {acrn_path.name}")
        typer.echo(f"  intermediate: {mica_path.name}")
        typer.echo("\nThe verify commands will now use these cached certificates instead of the bundled copies.")
    except Exception as exc:
        typer.secho(f"Error: {_format_error(exc)}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: doctor
# ---------------------------------------------------------------------------

_PCSCD_SOCKETS = ("/run/pcscd/pcscd.comm", "/var/run/pcscd/pcscd.comm")


def _doctor_emit(checks: list, json_output: bool, pretty: bool = False) -> bool:
    """Print the diagnostic checks; return True if there are no FAILs (WARN does not fail)."""
    ok = all(c["status"] != "FAIL" for c in checks)
    if json_output:
        typer.echo(_json_dumps({"schema_version": _JSON_SCHEMA_VERSION, "ok": ok, "checks": checks}, pretty))
        return ok
    colors = {"PASS": typer.colors.GREEN, "WARN": typer.colors.YELLOW, "FAIL": typer.colors.RED}
    for c in checks:
        line = f"{c['status']:<4}  {c['name']}"
        if c.get("detail"):
            line += f": {c['detail']}"
        typer.secho(line, fg=colors[c["status"]])
        if c.get("fix"):
            typer.secho(f"      → {c['fix']}", fg=typer.colors.CYAN)
    typer.echo("")
    if not ok:
        typer.secho("Some checks failed; address the FAIL items above.", fg=typer.colors.RED, bold=True)
    elif all(c["status"] == "PASS" for c in checks):
        typer.secho("All checks passed.", fg=typer.colors.GREEN, bold=True)
    else:
        typer.secho("No blocking failures (see the warnings above).", fg=typer.colors.YELLOW, bold=True)
    return ok


@app.command("doctor")
def doctor_cmd(
    pkcs11_lib: str = typer.Option(DEFAULT_PKCS11_LIB, "--pkcs11-lib", help="Path to the PKCS#11 module to check."),
    json_output: bool = typer.Option(False, "--json", help=_JSON_OPT_HELP),
    json_pretty: bool = typer.Option(False, "--json-pretty", help=_JSON_PRETTY_OPT_HELP),
) -> None:
    """Diagnose the local environment for signing with the cédula.

    Reports PASS / WARN / FAIL for each prerequisite, with a remediation hint. Needs no PIN.
    Exit code: 0 if there are no FAILs, 1 otherwise (warnings do not fail)."""
    import platform
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _pkg_version

    checks: list = []

    def add(status: str, name: str, detail: str = "", fix: Optional[str] = None) -> None:
        checks.append({"status": status, "name": name, "detail": detail, "fix": fix})

    try:
        v = _pkg_version("firmauy")
    except PackageNotFoundError:
        v = "unknown"
    add("PASS", "firmauy", f"{v} (Python {platform.python_version()})")

    lib = None
    if Path(pkcs11_lib).exists():
        add("PASS", "PKCS#11 module present", pkcs11_lib)
        try:
            lib = load_pkcs11_lib(pkcs11_lib)
            add("PASS", "PKCS#11 module loads")
        except Exception as exc:
            add("FAIL", "PKCS#11 module loads", _format_error(exc),
                fix="The module is present but could not be initialised; check the middleware install.")
    else:
        add("FAIL", "PKCS#11 module present", f"not found: {pkcs11_lib}",
            fix="Install the middleware (Arch: yay -S cedula-uruguay-pkcs11), or pass --pkcs11-lib.")

    if any(Path(s).exists() for s in _PCSCD_SOCKETS):
        add("PASS", "pcscd running")
    elif shutil.which("pcscd"):
        add("WARN", "pcscd running", "installed but not running",
            fix="Start it: sudo systemctl enable --now pcscd")
    else:
        add("WARN", "pcscd running", "not found",
            fix="Install the smart-card stack: sudo pacman -S pcsclite ccid")

    if lib is not None:
        try:
            tokens = list(lib.get_tokens())
        except Exception:
            tokens = []
        if tokens:
            label = (getattr(tokens[0], "label", "") or "").strip() or "<no label>"
            extra = f" (+{len(tokens) - 1} more)" if len(tokens) > 1 else ""
            add("PASS", "cédula token detected", f"{label}{extra}")
        else:
            add("WARN", "cédula token detected", "no card found",
                fix="Insert the cédula and check the reader connection / pcscd.")

    roots, intermediates = load_bundled_trust_anchors()
    if roots and intermediates:
        add("PASS", "bundled national CA certificates", "root + intermediate loaded")
    else:
        add("FAIL", "bundled national CA certificates", "not loadable",
            fix="The package install looks broken; reinstall firmauy.")

    if not _doctor_emit(checks, json_output or json_pretty, pretty=json_pretty):
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: list-readers
# ---------------------------------------------------------------------------

@app.command("list-readers")
def list_readers_cmd() -> None:
    """List all available PC/SC smart card readers."""
    try:
        available = list_readers()
        if not available:
            typer.secho(
                "No PC/SC readers found. Is pcscd running and a reader connected?",
                fg=typer.colors.YELLOW,
                err=True,
            )
            raise typer.Exit(code=1)
        for i, reader in enumerate(available):
            typer.echo(f"{i}  {reader}")
    except typer.Exit:
        raise
    except Exception as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: fetch-identity
# ---------------------------------------------------------------------------

@app.command("fetch-identity")
def fetch_identity_cmd(
    reader_name: Annotated[
        Optional[str],
        typer.Option(
            "--reader",
            help=(
                "PC/SC reader name (as shown by list-readers). "
                "Auto-detected when exactly one reader is present."
            ),
        ),
    ] = None,
    json_output: bool = typer.Option(False, "--json", help=_JSON_OPT_HELP),
    json_pretty: bool = typer.Option(False, "--json-pretty", help=_JSON_PRETTY_OPT_HELP),
    redact: bool = typer.Option(
        False,
        "--redact",
        help="Replace all biographical fields with [REDACTED] (for sharing output).",
    ),
) -> None:
    """Read biographical data from the cédula via a PC/SC reader.

    No PIN required: the AIS applet data (names, birth date, MRZ, etc.) is
    public and accessible without card authentication.

    Note: do not run while a PKCS#11 session (sign-* commands) is active on
    the same card -- both go through pcscd and may conflict.
    """
    try:
        json_output = json_output or json_pretty
        conn = open_reader(reader_name)
        try:
            card = read_card(conn)
        finally:
            try:
                conn.disconnect()
            except Exception:
                pass
        if json_output:
            payload = {
                "schema_version": _JSON_SCHEMA_VERSION,
                "redacted": redact,
                **card_to_json_obj(card, redact=redact),
            }
            typer.echo(_json_dumps(payload, json_pretty))
        else:
            typer.echo(format_card_human(card, redact=redact))
    except Exception as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: fetch-photo
# ---------------------------------------------------------------------------

@app.command("fetch-photo")
def fetch_photo_cmd(
    output: Annotated[
        Path,
        typer.Argument(
            help='Output JPEG path, or "-" to stream the raw JPEG to stdout (for pipes/redirects). '
                 "Default: cedula_foto.jpg"
        ),
    ] = Path("cedula_foto.jpg"),
    reader_name: Annotated[
        Optional[str],
        typer.Option(
            "--reader",
            help="PC/SC reader name (as shown by list-readers). "
                 "Auto-detected when exactly one reader is present.",
        ),
    ] = None,
    overwrite: bool = typer.Option(
        False, "--overwrite", help="Allow overwriting an existing output file."
    ),
    json_output: bool = typer.Option(False, "--json", help=_JSON_OPT_HELP),
    json_pretty: bool = typer.Option(False, "--json-pretty", help=_JSON_PRETTY_OPT_HELP),
    redact: bool = typer.Option(
        False,
        "--redact",
        help="In --json output, drop the image and any value that could fingerprint or correlate "
             "the cardholder (SHA-256, byte count), keeping only format and pixel dimensions.",
    ),
) -> None:
    """Save the cardholder's photo (a JPEG) from the cédula, via a PC/SC reader.

    No PIN required: the photo (AIS file 7004) is public, like the biographical data. By default the
    image is written to a file; pass "-" as the output to stream the raw JPEG to stdout instead, so it
    can be piped or redirected (e.g. `firmauy fetch-photo - | feh -`, or `firmauy fetch-photo - >
    cedula_foto.jpg`). Streaming to an interactive terminal is refused, to avoid dumping binary to the screen.

    With --json (or --json-pretty) a self-describing record is written to stdout instead: format, MIME
    type, pixel dimensions, byte count, SHA-256 and the base64-encoded image. --redact drops the image
    and the correlatable values, leaving only the non-identifying shape of the file.

    Note: do not run while a PKCS#11 session (sign-* commands) is active on the same card; both go
    through pcscd and may conflict.
    """
    to_stdout = str(output) == "-"
    json_output = json_output or json_pretty
    try:
        if json_output:
            # --json prints a text record to stdout; a binary file path or "-" would be ambiguous.
            if output != Path("cedula_foto.jpg"):
                raise RuntimeError(
                    "--json / --json-pretty write the photo record to stdout and cannot be combined "
                    "with a file path or '-'. Redirect instead, e.g. "
                    "`firmauy fetch-photo --json > cedula_foto.json`."
                )
        elif to_stdout:
            if sys.stdout.isatty():
                raise RuntimeError(
                    "Refusing to write binary JPEG to a terminal. Redirect or pipe it, e.g. "
                    "`firmauy fetch-photo - > cedula_foto.jpg` or `firmauy fetch-photo - | feh -`."
                )
        elif output.exists() and not overwrite:
            raise RuntimeError(
                f"Output file already exists: {output}\nUse --overwrite to overwrite it."
            )
        conn = open_reader(reader_name)
        try:
            photo = read_photo(conn)
        finally:
            try:
                conn.disconnect()
            except Exception:
                pass
        if json_output:
            payload = {
                "schema_version": _JSON_SCHEMA_VERSION,
                "redacted": redact,
                **photo_to_json_obj(photo, redact=redact),
            }
            typer.echo(_json_dumps(payload, json_pretty))
        elif to_stdout:
            sys.stdout.buffer.write(photo)
            sys.stdout.buffer.flush()
            # Status goes to stderr so it never corrupts the JPEG stream on stdout.
            typer.secho(f"Photo streamed to stdout ({len(photo)} bytes).",
                        fg=typer.colors.GREEN, err=True)
        else:
            ensure_output_parent(output)
            output.write_bytes(photo)
            typer.secho(f"Photo saved: {output} ({len(photo)} bytes)", fg=typer.colors.GREEN)
    except Exception as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: validate-ci
# ---------------------------------------------------------------------------

@app.command("validate-ci")
def validate_ci_cmd(
    ci: Annotated[
        str,
        typer.Argument(
            help='Cédula number, with or without separators (e.g. "1.234.567-8" or "12345678").'
        ),
    ],
    complete: bool = typer.Option(
        False,
        "--complete",
        help="Treat the input as a cédula body without its check digit, and print the completed number.",
    ),
    json_output: bool = typer.Option(False, "--json", help=_JSON_OPT_HELP),
    json_pretty: bool = typer.Option(False, "--json-pretty", help=_JSON_PRETTY_OPT_HELP),
    redact: bool = typer.Option(
        False,
        "--redact",
        help="In --json validation output, drop the cédula number, keeping only the validity flag.",
    ),
) -> None:
    """Validate (or complete) a Uruguayan cédula's check digit. No card or PIN needed.

    This is a purely arithmetic consistency check of the number (the standard weighted check digit).
    It does NOT validate identity, the existence or current validity of the person, the validity of
    the document, or the authenticity of a card; it only catches typos and malformed numbers.

    Exit codes: 0 valid, 1 invalid, 2 malformed input (with --complete: 0 on success, 2 on
    malformed input).
    """
    json_output = json_output or json_pretty
    if complete and redact:
        raise typer.BadParameter(
            "--redact has no effect with --complete (the completed cédula is the output)."
        )

    try:
        if complete:
            full = complete_ci(ci)
            if json_output:
                typer.echo(_json_dumps({
                    "schema_version": _JSON_SCHEMA_VERSION,
                    "redacted": False,
                    "input": ci,
                    "body": full[:-1],
                    "check_digit": full[-1],
                    "complete": full,
                }, json_pretty))
            else:
                typer.echo(full)
            return

        result = validate_ci(ci)
    except ValueError as exc:
        if json_output:
            typer.echo(_json_dumps(
                {"schema_version": _JSON_SCHEMA_VERSION, "error": _format_error(exc)}, json_pretty))
        else:
            typer.secho(f"Error: {_format_error(exc)}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    if json_output:
        if redact:
            payload = {
                "schema_version": _JSON_SCHEMA_VERSION,
                "redacted": True,
                "valid": result["valid"],
            }
        else:
            payload = {
                "schema_version": _JSON_SCHEMA_VERSION,
                "redacted": False,
                "valid": result["valid"],
                "input": ci,
                "normalized": result["normalized"],
                "body": result["body"],
                "check_digit": result["check_digit"],
                "expected_check_digit": result["expected_check_digit"],
            }
        typer.echo(_json_dumps(payload, json_pretty))
    elif result["valid"]:
        typer.secho(
            f"VALID: {result['normalized']} (check digit {result['check_digit']})",
            fg=typer.colors.GREEN,
        )
    else:
        typer.secho(
            f"INVALID: {result['normalized']} "
            f"(check digit {result['check_digit']}, expected {result['expected_check_digit']})",
            fg=typer.colors.RED,
        )
    if not result["valid"]:
        raise typer.Exit(code=1)
