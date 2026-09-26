#!/usr/bin/env python3
# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Annotated, Iterable, List, Optional
from zoneinfo import ZoneInfo

import pkcs11
import typer
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from pyhanko.sign import signers

from firmauy.appearance import ensure_output_parent
from firmauy.card_reader import (
    card_to_json_obj,
    format_card_human,
    list_readers,
    photo_to_json_obj,
    read_card,
    read_photo,
)
from firmauy.cert_utils import (
    _cert_digital_signature,
    _cert_record,
    _redact_cert_record,
    cert_not_after,
    get_common_name,
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
    StampCorner,
    StampFields,
)
from firmauy.pin import PinSource, get_pin
from firmauy.pkcs11_utils import (
    find_token,
    iter_cert_objects,
    load_pkcs11_lib,
    token_to_dict,
)
from firmauy.national_ca import (
    cache_dir,
    fetch_cas,
)
from firmauy.pdf_verify import verify_pdf
from firmauy.xml_verify import verify_xml
from firmauy.cms_verify import MAX_CMS_BYTES, verify_cms
from firmauy.errors import OutputCommittedError
from firmauy._shared import (
    _INDICATION_RANK,
    _collect_doctor_checks,
    _detached_original,
    _detect_signature_kind,
    _format_error,
    _resolve_trust_anchors,
    _resolve_tsa_anchors,
    read_bounded,
)
from firmauy.signing import (
    _build_timestamper,
    _card_connection,
    _resolve_sign_kind,
    _sign_one_cms,
    _sign_one_pdf,
    _sign_one_xml,
    _signing_session,
    _verify_after_cms,
    _verify_after_pdf,
    _verify_after_xml,
)

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
            "cédula signing flow does not require it. Credentials require https, "
            "whether they arrive through --tsa-user / --tsa-header or inside the URL. "
            "A secret placed in a query parameter cannot be told apart from any other "
            "parameter and is not detected, so do not put one there."
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
CornerOpt = Annotated[Optional[StampCorner], typer.Option("--corner", help="Place the visible signature in a corner of the page, resolved against that page's real size: bottom-left, bottom-right, top-left, top-right. Overrides --x1/--y1/--x2/--y2 as a position, keeping the box's size.")]
MarginOpt = Annotated[float, typer.Option("--margin", min=0.0, help="Points between the stamp and the two page edges of --corner. Default 20.")]
NoStampTitleOpt = Annotated[bool, typer.Option("--no-stamp-title", help="Leave \"Firma electronica avanzada, UY\" out of the visible stamp.")]
NoStampSignerOpt = Annotated[bool, typer.Option("--no-stamp-signer", help="Leave \"Firmado por\" out of the visible stamp.")]
NoStampDocumentOpt = Annotated[bool, typer.Option("--no-stamp-document", help="Leave \"Documento\" (the certificate serial) out of the visible stamp.")]
NoStampDateOpt = Annotated[bool, typer.Option("--no-stamp-date", help="Leave \"Fecha\" out of the visible stamp.")]
NoStampIssuerOpt = Annotated[bool, typer.Option("--no-stamp-issuer", help="Leave the issuing authority out of the visible stamp.")]
NativeOpt = Annotated[bool, typer.Option("--native", help="Sign natively over PC/SC APDUs instead of PKCS#11: talk to the cédula directly, with no PKCS#11 middleware (--pkcs11-lib/--token-label are then ignored, and --cert-id is rejected, as the card has a single signing certificate). Experimental, not AGESIC-certified. Needs pcscd and a reader, not the PKCS#11 module.")]
ReaderOpt = Annotated[Optional[str], typer.Option("--reader", help="PC/SC reader name (as shown by list-readers) for --native. Auto-detected when exactly one reader is present.")]
AllowHybridXrefOpt = Annotated[bool, typer.Option("--allow-hybrid-xref", help="Sign PDFs that use hybrid cross-reference sections (opens the PDF non-strict). Off by default: such PDFs are rejected because the incremental signature may not be equivalent for all readers -- normalize with `qpdf in.pdf out.pdf` instead. Use at your own risk.")]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _warn(msg: str) -> None:
    """Print a warning/note line to stderr. This is the ``notify`` sink the signing engine calls,
    so its warnings surface on the terminal; the public API passes no sink and stays silent."""
    typer.secho(msg, fg=typer.colors.YELLOW, err=True)


def _error_code(exc: Exception) -> str:
    """Return a stable machine-readable code for a CLI error."""
    return {
        "FileNotFoundError": "file_not_found",
        "OutputExistsError": "output_exists",
        "IncorrectPinError": "incorrect_pin",
        "PinLockedError": "pin_locked",
        "PinError": "pin_error",
        "CertificateNotFoundError": "certificate_not_found",
        "CertificateNotValidError": "certificate_not_valid",
        "SigningKeyNotFoundError": "signing_key_not_found",
    }.get(type(exc).__name__, "operation_failed")


def _emit_error(exc: Exception, json_output: bool) -> None:
    if json_output:
        typer.echo(_json_dumps({
            "schema_version": _JSON_SCHEMA_VERSION,
            "ok": False,
            "error_code": _error_code(exc),
            "error": _format_error(exc),
        }, False))
    else:
        typer.secho(f"Error: {_format_error(exc)}", fg=typer.colors.RED, err=True)


def _print_signing_info(ctx, *, tsa_url: Optional[str], quiet: bool = False) -> None:
    """Print the aligned signer/token identity block shared by every sign-* command, from the
    display fields the signing session collected (the session itself prints nothing).

    ``ctx.source_caption`` labels the first line: "Token" for the PKCS#11 backend, "Reader" for the
    native PC/SC backend; ``ctx.key_id`` is None in native mode, omitting that line. Skipped
    entirely when ``quiet`` is set, to keep identifying data (signer name, certificate serial,
    PKCS#11 ID) out of automation/CI logs."""
    if quiet:
        return
    typer.echo(f"{ctx.source_caption + ':':<21}{ctx.source_display}")
    typer.echo(f"Signer:              {ctx.signer_name}")
    typer.echo(f"Issuer:              {ctx.issuer_name}")
    if ctx.key_id is not None:
        typer.echo(f"PKCS#11 ID:          {ctx.key_id.hex()}")
    typer.echo(f"Certificate serial:  {ctx.cert_serial}")
    if tsa_url:
        typer.echo(f"TSA:                 {tsa_url}")


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
    from firmauy.appearance import check_stamp_image
    try:
        check_stamp_image(image)
    except ValueError as exc:
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


def _batch_input_allowed(path: Path, input_dir: Path) -> bool:
    """Accept only regular, non-symlink files whose resolved path stays under ``input_dir``."""
    if not path.is_file() or path.is_symlink():
        return False
    try:
        return path.resolve(strict=True).is_relative_to(input_dir.resolve(strict=True))
    except OSError:
        return False


def _discover_batch_inputs(input_dir: Path, pattern: str) -> list[Path]:
    """The files under ``input_dir`` matching ``pattern`` that a batch signs, sorted.

    A symlink, or a file that resolves outside the directory, is skipped with a warning rather
    than in silence. Those used to be signed, so a batch that now drops them without a word looks
    like one that lost them, and the warning names the way to sign one on purpose: as an
    argument, where nothing is filtered. The filter itself exists because a link planted in a
    shared folder could otherwise get a file signed that nobody put there.
    """
    found = []
    for p in sorted(input_dir.glob(pattern)):
        if not p.is_file():          # directories and dangling links were never inputs
            continue
        if _batch_input_allowed(p, input_dir):
            found.append(p)
        else:
            _warn(f"Skipping {p}: a symlink, or a file outside --input-dir, is not signed from a "
                  "directory listing. Pass it as an argument to sign it on purpose.")
    return found


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


# ---------------------------------------------------------------------------
# Subcommand: list-tokens
# ---------------------------------------------------------------------------

@app.command("list-tokens")
def list_tokens(
    pkcs11_lib: str = typer.Option(
        DEFAULT_PKCS11_LIB, "--pkcs11-lib", help="Path to the PKCS#11 module.",
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit a JSON result."),
) -> None:
    """List all PKCS#11 tokens visible in the library."""
    try:
        lib = load_pkcs11_lib(pkcs11_lib)
        tokens = list(lib.get_tokens())
        if json_output:
            typer.echo(_json_dumps({
                "schema_version": _JSON_SCHEMA_VERSION,
                "tokens": [token_to_dict(token) for token in tokens],
            }, False))
            return
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
        _emit_error(exc, json_output)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: list-certs
# ---------------------------------------------------------------------------

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
        help="Emit the certificate list as a single JSON object (schema_version 2); with --pem, "
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
        _emit_error(exc, json_output)
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
    allow_hybrid_xref: AllowHybridXrefOpt = False,
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
    no_stamp_title: NoStampTitleOpt = False,
    no_stamp_signer: NoStampSignerOpt = False,
    no_stamp_document: NoStampDocumentOpt = False,
    no_stamp_date: NoStampDateOpt = False,
    no_stamp_issuer: NoStampIssuerOpt = False,
    corner: CornerOpt = None,
    margin: MarginOpt = 20.0,
    json_output: bool = typer.Option(False, "--json", help="Emit a JSON result."),
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
            notify=_warn,
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
            pin_provider=lambda: get_pin(pin_source, pin_env_var, pin_fd),
            notify=_warn,
        ) as ctx:
            _print_signing_info(ctx, tsa_url=tsa_url, quiet=quiet or json_output)

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
                stamp_fields=StampFields(title=not no_stamp_title, signer=not no_stamp_signer, document=not no_stamp_document, date=not no_stamp_date, issuer=not no_stamp_issuer),
                corner=corner, margin=margin,
                allow_hybrid_xref=allow_hybrid_xref, notify=_warn,
            )

        if verify:
            _verify_after_pdf(output_pdf)
        if json_output:
            typer.echo(_json_dumps({"schema_version": _JSON_SCHEMA_VERSION, "ok": True,
                                    "kind": "pades", "output": str(output_pdf),
                                    "verified": verify}, False))
        else:
            typer.secho(f"PDF signed successfully: {output_pdf}", fg=typer.colors.GREEN)
            if verify:
                typer.secho("Verified: signature intact and covers the whole file.", fg=typer.colors.GREEN)

    except Exception as exc:
        _emit_error(exc, json_output)
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
    allow_hybrid_xref: AllowHybridXrefOpt = False,
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
    no_stamp_title: NoStampTitleOpt = False,
    no_stamp_signer: NoStampSignerOpt = False,
    no_stamp_document: NoStampDocumentOpt = False,
    no_stamp_date: NoStampDateOpt = False,
    no_stamp_issuer: NoStampIssuerOpt = False,
    corner: CornerOpt = None,
    margin: MarginOpt = 20.0,
    json_output: bool = typer.Option(False, "--json", help="Emit a JSON result."),
) -> None:
    """Sign multiple PDFs with a single PKCS#11 session (batch mode)."""
    try:
        _warn_image_opacity_unused(image, image_mode, image_opacity)
        _validate_image(image)
        _validate_timezone(timezone)
        timestamper = _build_timestamper(
            notify=_warn,
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
            for p in _discover_batch_inputs(input_dir, pattern):
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
            pin_provider=lambda: get_pin(pin_source, pin_env_var, pin_fd),
            notify=_warn,
        ) as ctx:
            _print_signing_info(ctx, tsa_url=tsa_url, quiet=quiet or json_output)
            if not json_output:
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
            warn_count = 0

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
                        stamp_fields=StampFields(title=not no_stamp_title, signer=not no_stamp_signer, document=not no_stamp_document, date=not no_stamp_date, issuer=not no_stamp_issuer),
                        corner=corner, margin=margin,
                        allow_hybrid_xref=allow_hybrid_xref, notify=_warn,
                    )
                    if verify:
                        _verify_after_pdf(output_pdf)
                    if not json_output:
                        typer.secho(f"OK:    {output_pdf}", fg=typer.colors.GREEN)
                    ok_count += 1
                except OutputCommittedError as exc:
                    # Written, committed, only its mode is wrong. Counting it as an error said
                    # the file was not produced while it sat there complete, and the summary
                    # undercounted. It is signed, so it counts as signed, and the line says what
                    # still needs doing.
                    # The verification step runs after the signing call returns, so asking for
                    # it and landing here means it never ran. Saying OK would report a check
                    # that did not happen.
                    label = "SIGNED (not verified)" if verify else "SIGNED"
                    if not json_output:
                        typer.secho(f"{label}: {output_pdf}", fg=typer.colors.YELLOW)
                        typer.secho(f"WARN:  {_format_error(exc)}", fg=typer.colors.YELLOW, err=True)
                    ok_count += 1
                    warn_count += 1
                except Exception as exc:
                    if not json_output:
                        typer.secho(f"ERROR: {input_pdf}: {_format_error(exc)}", fg=typer.colors.RED, err=True)
                    err_count += 1

        if json_output:
            typer.echo(_json_dumps({"schema_version": _JSON_SCHEMA_VERSION, "ok": not (err_count or warn_count),
                                    "signed": ok_count, "total": len(jobs), "errors": err_count,
                                    "warnings": warn_count}, False))
        else:
            typer.echo("")
            typer.echo(f"Signed: {ok_count}/{len(jobs)}. Errors: {err_count}."
                       + (f" Needing a chmod: {warn_count}." if warn_count else ""))

        if err_count or warn_count:
            # A file needing a chmod was signed, so it is not an error, but the command did not
            # do everything it was asked to. Reporting success would let a script ship a document
            # whose permissions were never set.
            raise typer.Exit(code=1)

    except typer.Exit:
        raise
    except Exception as exc:
        _emit_error(exc, json_output)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# XML signing helpers (shared by sign-xml and sign-xml-batch)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# CMS / CAdES signing helper (shared by sign-any and sign-any-batch)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Post-sign self-check (--verify): re-verify the freshly produced signature for
# integrity and coverage (no trust), to catch a broken/corrupt output at once.
# ---------------------------------------------------------------------------


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
    json_output: bool = typer.Option(False, "--json", help="Emit a JSON result."),
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
            notify=_warn,
            tsa_url=tsa_url, tsa_user=tsa_user, tsa_pass_env=tsa_pass_env, tsa_header=tsa_header,
            tsa_header_env=tsa_header_env,
        )

        with _signing_session(
            native=native, reader=reader,
            pkcs11_lib=pkcs11_lib, token_label=token_label, cert_id=cert_id,
            pin_provider=lambda: get_pin(pin_source, pin_env_var, pin_fd),
            notify=_warn,
        ) as ctx:
            _print_signing_info(ctx, tsa_url=tsa_url, quiet=quiet or json_output)

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
        if json_output:
            typer.echo(_json_dumps({"schema_version": _JSON_SCHEMA_VERSION, "ok": True,
                                    "kind": "xades", "output": str(output_xml),
                                    "verified": verify}, False))
        else:
            typer.secho(f"XML signed successfully: {output_xml}", fg=typer.colors.GREEN)
            if verify:
                typer.secho("Verified: signature intact.", fg=typer.colors.GREEN)

    except Exception as exc:
        _emit_error(exc, json_output)
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
    json_output: bool = typer.Option(False, "--json", help="Emit a JSON result."),
) -> None:
    """Sign multiple XML documents with a single PKCS#11 session (XAdES-BES, or XAdES-T with --tsa-url)."""
    try:
        _validate_timezone(timezone)
        timestamper = _build_timestamper(
            notify=_warn,
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
            for p in _discover_batch_inputs(input_dir, pattern):
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
            pin_provider=lambda: get_pin(pin_source, pin_env_var, pin_fd),
            notify=_warn,
        ) as ctx:
            _print_signing_info(ctx, tsa_url=tsa_url, quiet=quiet or json_output)
            if not json_output:
                typer.echo(f"Files to sign:       {len(jobs)}")
                typer.echo("")

            raw_signer = ctx.raw_signer()

            ok_count = 0
            err_count = 0
            warn_count = 0

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
                    if not json_output:
                        typer.secho(f"OK:    {output_xml}", fg=typer.colors.GREEN)
                    ok_count += 1
                except OutputCommittedError as exc:
                    # Written, committed, only its mode is wrong. Counting it as an error said
                    # the file was not produced while it sat there complete, and the summary
                    # undercounted. It is signed, so it counts as signed, and the line says what
                    # still needs doing.
                    # The verification step runs after the signing call returns, so asking for
                    # it and landing here means it never ran. Saying OK would report a check
                    # that did not happen.
                    label = "SIGNED (not verified)" if verify else "SIGNED"
                    if not json_output:
                        typer.secho(f"{label}: {output_xml}", fg=typer.colors.YELLOW)
                        typer.secho(f"WARN:  {_format_error(exc)}", fg=typer.colors.YELLOW, err=True)
                    ok_count += 1
                    warn_count += 1
                except Exception as exc:
                    if not json_output:
                        typer.secho(f"ERROR: {input_xml}: {_format_error(exc)}", fg=typer.colors.RED, err=True)
                    err_count += 1

        if json_output:
            typer.echo(_json_dumps({"schema_version": _JSON_SCHEMA_VERSION, "ok": not (err_count or warn_count),
                                    "signed": ok_count, "total": len(jobs), "errors": err_count,
                                    "warnings": warn_count}, False))
        else:
            typer.echo("")
            typer.echo(f"Signed: {ok_count}/{len(jobs)}. Errors: {err_count}."
                       + (f" Needing a chmod: {warn_count}." if warn_count else ""))

        if err_count or warn_count:
            # A file needing a chmod was signed, so it is not an error, but the command did not
            # do everything it was asked to. Reporting success would let a script ship a document
            # whose permissions were never set.
            raise typer.Exit(code=1)

    except typer.Exit:
        raise
    except Exception as exc:
        _emit_error(exc, json_output)
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
    json_output: bool = typer.Option(False, "--json", help="Emit a JSON result."),
) -> None:
    """Sign any file with a Uruguayan cédula, producing a detached CAdES-BES
    signature (.p7s, CMS/PKCS#7). The original file is left untouched."""
    if output_p7s is None:
        output_p7s = input_file.with_name(input_file.name + ".p7s")
    try:
        timestamper = _build_timestamper(
            notify=_warn,
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
            pin_provider=lambda: get_pin(pin_source, pin_env_var, pin_fd),
            notify=_warn,
        ) as ctx:
            _print_signing_info(ctx, tsa_url=tsa_url, quiet=quiet or json_output)

            _sign_one_cms(
                input_file=input_file,
                output_p7s=output_p7s,
                pkcs11_signer=ctx.pyhanko_signer(),
                timestamper=timestamper,
                overwrite=overwrite,
            )

        if verify:
            _verify_after_cms(input_file, output_p7s)
        if json_output:
            typer.echo(_json_dumps({"schema_version": _JSON_SCHEMA_VERSION, "ok": True,
                                    "kind": "cades", "output": str(output_p7s),
                                    "verified": verify}, False))
        else:
            typer.secho(f"File signed successfully: {output_p7s}", fg=typer.colors.GREEN)
            if verify:
                typer.secho("Verified: signature intact.", fg=typer.colors.GREEN)

    except Exception as exc:
        _emit_error(exc, json_output)
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
    json_output: bool = typer.Option(False, "--json", help="Emit a JSON result."),
) -> None:
    """Sign multiple files with a single PKCS#11 session (detached CAdES-BES .p7s).

    Each output is named ``<input-name>.p7s`` inside --output-dir; files found under
    --input-dir keep their relative subdirectory, so equally named files in different
    subfolders (with --recursive) do not collide."""
    try:
        timestamper = _build_timestamper(
            notify=_warn,
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
            for p in _discover_batch_inputs(input_dir, pattern):
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
            pin_provider=lambda: get_pin(pin_source, pin_env_var, pin_fd),
            notify=_warn,
        ) as ctx:
            _print_signing_info(ctx, tsa_url=tsa_url, quiet=quiet or json_output)
            if not json_output:
                typer.echo(f"Files to sign:       {len(jobs)}")
                typer.echo("")

            pkcs11_signer = ctx.pyhanko_signer()

            ok_count = 0
            err_count = 0
            warn_count = 0

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
                    if not json_output:
                        typer.secho(f"OK:    {output_p7s}", fg=typer.colors.GREEN)
                    ok_count += 1
                except OutputCommittedError as exc:
                    # Written, committed, only its mode is wrong. Counting it as an error said
                    # the file was not produced while it sat there complete, and the summary
                    # undercounted. It is signed, so it counts as signed, and the line says what
                    # still needs doing.
                    # The verification step runs after the signing call returns, so asking for
                    # it and landing here means it never ran. Saying OK would report a check
                    # that did not happen.
                    label = "SIGNED (not verified)" if verify else "SIGNED"
                    if not json_output:
                        typer.secho(f"{label}: {output_p7s}", fg=typer.colors.YELLOW)
                        typer.secho(f"WARN:  {_format_error(exc)}", fg=typer.colors.YELLOW, err=True)
                    ok_count += 1
                    warn_count += 1
                except Exception as exc:
                    if not json_output:
                        typer.secho(f"ERROR: {input_file}: {_format_error(exc)}", fg=typer.colors.RED, err=True)
                    err_count += 1

        if json_output:
            typer.echo(_json_dumps({"schema_version": _JSON_SCHEMA_VERSION, "ok": not (err_count or warn_count),
                                    "signed": ok_count, "total": len(jobs), "errors": err_count,
                                    "warnings": warn_count}, False))
        else:
            typer.echo("")
            typer.echo(f"Signed: {ok_count}/{len(jobs)}. Errors: {err_count}."
                       + (f" Needing a chmod: {warn_count}." if warn_count else ""))

        if err_count or warn_count:
            # A file needing a chmod was signed, so it is not an error, but the command did not
            # do everything it was asked to. Reporting success would let a script ship a document
            # whose permissions were never set.
            raise typer.Exit(code=1)

    except typer.Exit:
        raise
    except Exception as exc:
        _emit_error(exc, json_output)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommands: sign / sign-batch (auto-detect the signature type)
# ---------------------------------------------------------------------------


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
    allow_hybrid_xref: AllowHybridXrefOpt = False,
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
    no_stamp_title: NoStampTitleOpt = False,
    no_stamp_signer: NoStampSignerOpt = False,
    no_stamp_document: NoStampDocumentOpt = False,
    no_stamp_date: NoStampDateOpt = False,
    no_stamp_issuer: NoStampIssuerOpt = False,
    corner: CornerOpt = None,
    margin: MarginOpt = 20.0,
    json_output: bool = typer.Option(False, "--json", help="Emit a JSON result."),
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
            notify=_warn,
            tsa_url=tsa_url, tsa_user=tsa_user, tsa_pass_env=tsa_pass_env,
            tsa_header=tsa_header, tsa_header_env=tsa_header_env,
        )

        with _signing_session(
            native=native, reader=reader,
            pkcs11_lib=pkcs11_lib, token_label=token_label, cert_id=cert_id,
            pin_provider=lambda: get_pin(pin_source, pin_env_var, pin_fd),
            notify=_warn,
        ) as ctx:
            _print_signing_info(ctx, tsa_url=tsa_url, quiet=quiet or json_output)

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
                    stamp_fields=StampFields(title=not no_stamp_title, signer=not no_stamp_signer, document=not no_stamp_document, date=not no_stamp_date, issuer=not no_stamp_issuer),
                    corner=corner, margin=margin,
                    allow_hybrid_xref=allow_hybrid_xref, notify=_warn,
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

        if json_output:
            typer.echo(_json_dumps({"schema_version": _JSON_SCHEMA_VERSION, "ok": True,
                                    "kind": kind, "output": str(output),
                                    "verified": verify}, False))
        else:
            typer.secho(f"Signed as {_SIGN_KIND_LABEL[kind]}: {output}", fg=typer.colors.GREEN)
            if verify:
                typer.secho("Verified: signature intact.", fg=typer.colors.GREEN)

    except Exception as exc:
        _emit_error(exc, json_output)
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
    allow_hybrid_xref: AllowHybridXrefOpt = False,
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
    no_stamp_title: NoStampTitleOpt = False,
    no_stamp_signer: NoStampSignerOpt = False,
    no_stamp_document: NoStampDocumentOpt = False,
    no_stamp_date: NoStampDateOpt = False,
    no_stamp_issuer: NoStampIssuerOpt = False,
    corner: CornerOpt = None,
    margin: MarginOpt = 20.0,
    json_output: bool = typer.Option(False, "--json", help="Emit a JSON result."),
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
            notify=_warn,
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
            for p in _discover_batch_inputs(input_dir, pattern):
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
            pin_provider=lambda: get_pin(pin_source, pin_env_var, pin_fd),
            notify=_warn,
        ) as ctx:
            _print_signing_info(ctx, tsa_url=tsa_url, quiet=quiet or json_output)
            if not json_output:
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
            warn_count = 0
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
                    stamp_fields=StampFields(title=not no_stamp_title, signer=not no_stamp_signer, document=not no_stamp_document, date=not no_stamp_date, issuer=not no_stamp_issuer),
                    corner=corner, margin=margin,
                            allow_hybrid_xref=allow_hybrid_xref, notify=_warn,
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
                    if not json_output:
                        typer.secho(f"OK:    {output}  ({kind})", fg=typer.colors.GREEN)
                    ok_count += 1
                except OutputCommittedError as exc:
                    # Written, committed, only its mode is wrong. Counting it as an error said
                    # the file was not produced while it sat there complete, and the summary
                    # undercounted. It is signed, so it counts as signed, and the line says what
                    # still needs doing.
                    # The verification step runs after the signing call returns, so asking for
                    # it and landing here means it never ran. Saying OK would report a check
                    # that did not happen.
                    label = "SIGNED (not verified)" if verify else "SIGNED"
                    if not json_output:
                        typer.secho(f"{label}: {output}  ({kind})", fg=typer.colors.YELLOW)
                        typer.secho(f"WARN:  {_format_error(exc)}", fg=typer.colors.YELLOW, err=True)
                    ok_count += 1
                    warn_count += 1
                except Exception as exc:
                    if not json_output:
                        typer.secho(f"ERROR: {input_path}: {_format_error(exc)}",
                                    fg=typer.colors.RED, err=True)
                    err_count += 1

            # Inputs whose type could not be detected up front are reported here as errors.
            for input_path, exc in predetect_errors:
                if not json_output:
                    typer.secho(f"ERROR: {input_path}: {_format_error(exc)}",
                                fg=typer.colors.RED, err=True)
                err_count += 1

        if json_output:
            typer.echo(_json_dumps({"schema_version": _JSON_SCHEMA_VERSION, "ok": not (err_count or warn_count),
                                    "signed": ok_count, "total": len(items), "errors": err_count,
                                    "warnings": warn_count}, False))
        else:
            typer.echo("")
            typer.echo(f"Signed: {ok_count}/{len(items)}. Errors: {err_count}."
                       + (f" Needing a chmod: {warn_count}." if warn_count else ""))
        if err_count or warn_count:
            # A file needing a chmod was signed, so it is not an error, but the command did not
            # do everything it was asked to. Reporting success would let a script ship a document
            # whose permissions were never set.
            raise typer.Exit(code=1)

    except typer.Exit:
        raise
    except Exception as exc:
        typer.secho(f"Error: {_format_error(exc)}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Verification helpers (shared by verify-xml and verify-pdf)
# ---------------------------------------------------------------------------

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

# Public, versioned JSON contract for the verify commands (decoupled from the internal
# VerifyResult dataclass, so it can be refactored without breaking consumers).
_JSON_SCHEMA_VERSION = 2

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


def _timestamp_to_json_obj(info) -> Optional[dict]:
    """The timestamp as data, so a consumer never has to read a check's wording to find out
    whether the stamp held. null when the signature carries none.

    ``trusted`` is null when no TSA anchors were supplied: the chain was not looked at, which is
    a third state and not a failure. Nothing here is redacted, since none of it is about the
    cardholder: it names the timestamping authority, not the signer.
    """
    if info is None:
        return None
    return {
        "present": info.present,
        "intact": info.intact,
        "valid": info.valid,
        "trusted": info.trusted,
        "gen_time": info.gen_time.isoformat() if info.gen_time else None,
        "tsa_common_name": info.tsa_common_name,
        "detail": info.detail,
    }


def _result_to_json_obj(result, redact: bool) -> dict:
    return {
        "indication": result.indication,
        "signer": _redact_signer(result.signer) if redact else result.signer,
        "issuer": _redact_issuer(result.issuer, result.signer) if redact else result.issuer,
        "trusted": result.trusted,
        "timestamp": _timestamp_to_json_obj(result.timestamp),
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

        {"schema_version": 2, "redacted": false, "indication": "...", "signatures": [
            {"indication", "signer": {...}, "issuer": {...}, "trusted",
             "timestamp": {...} | null,
             "checks": [{"name","ok","detail"}]}]}

    ``timestamp`` is new in 1.12.0 and the schema version stays at 2 on purpose: a key that was
    never there cannot break a consumer reading the keys it already knows, and the check rows
    were always documented as varying per format. Bumping the version would have forced every
    consumer to look at a change that does not affect them.
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
        typer.echo(_json_dumps({"schema_version": _JSON_SCHEMA_VERSION, "ok": False,
                                "error_code": _error_code(exc), "error": _format_error(exc)}, pretty))
    else:
        typer.secho(f"Error: {_format_error(exc)}", fg=typer.colors.RED, err=True)


_JSON_OPT_HELP = (
    "Emit the result as a single JSON object on stdout (schema_version 2); "
    "exit codes are unchanged."
)
_JSON_PRETTY_OPT_HELP = "Like --json but indented for humans (implies --json)."
_REDACT_OPT_HELP = (
    "Hide personal data (signer name, document and certificate serials) in the output, "
    "e.g. for sharing logs or issues."
)
_TSA_CA_OPT_HELP = (
    "PEM bundle of the trusted timestamping authority's certificate(s), for a PDF, a XAdES-T XML "
    "or a detached .p7s. When given, the timestamp's own chain is validated and the signing "
    "certificate is then evaluated at the sealed time rather than now, in every format. That is "
    "validation at the sealed time, not the AdES -LT/-LTA levels: no historical revocation "
    "evidence is embedded or consulted. "
    "Without it a timestamp is reported as present and unvalidated, which is neither trusted nor "
    "broken. Kept separate from --ca-file on purpose: those anchors decide who is accepted as "
    "having signed the document, and a timestamping authority has no business widening that."
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

        roots, intermediates = _resolve_trust_anchors(ca_file, no_trust, notify=_warn)
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
    tsa_ca: Optional[Path] = typer.Option(
        None, "--tsa-ca", exists=True, readable=True, dir_okay=False, help=_TSA_CA_OPT_HELP),
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

        roots, intermediates = _resolve_trust_anchors(ca_file, no_trust, notify=_warn)
        tsa_roots, tsa_others = _resolve_tsa_anchors(tsa_ca)

        results = verify_pdf(
            input_pdf,
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
    tsa_ca: Optional[Path] = typer.Option(
        None, "--tsa-ca", exists=True, readable=True, dir_okay=False, help=_TSA_CA_OPT_HELP),
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

        roots, intermediates = _resolve_trust_anchors(ca_file, no_trust, notify=_warn)
        tsa_roots, tsa_others = _resolve_tsa_anchors(tsa_ca)

        # Stream the (possibly large) signed file instead of loading it into memory; only the
        # small detached signature is read whole.
        with input_file.open("rb") as data:
            result = verify_cms(
                data,
                read_bounded(p7s_file, MAX_CMS_BYTES, "CMS signature"),
                trust_roots=roots,
                intermediates=intermediates,
                check_revocation=check_revocation,
                tsa_trust_roots=tsa_roots,
                tsa_other_certs=tsa_others,
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
    by default the '<x>.p7s -> <x>' name is used, or pass --original.
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

        roots, intermediates = _resolve_trust_anchors(ca_file, no_trust, notify=_warn)
        # Resolved for every format. This used to be XML-only, and a note here told the user that
        # --tsa-ca was ignored for a PDF and that "PDF/CMS timestamps use --ca-file", which was
        # the wrong advice as well as a dead option: --ca-file decides who may have *signed* the
        # document, and pointing it at a TSA to get a timestamp validated widens that.
        tsa_roots, tsa_others = _resolve_tsa_anchors(tsa_ca)

        if kind == "pdf":
            results = verify_pdf(input_file, trust_roots=roots, intermediates=intermediates,
                                 check_revocation=check_revocation,
                                 tsa_trust_roots=tsa_roots, tsa_other_certs=tsa_others)
        elif kind == "xml":
            results = verify_xml(input_file.read_bytes(), trust_roots=roots,
                                 intermediates=intermediates, check_revocation=check_revocation,
                                 tsa_trust_roots=tsa_roots, tsa_other_certs=tsa_others)
        else:  # cms / detached .p7s
            with orig.open("rb") as data:
                results = [verify_cms(data, read_bounded(input_file, MAX_CMS_BYTES, "CMS signature"), trust_roots=roots,
                                      intermediates=intermediates,
                                      check_revocation=check_revocation,
                                      tsa_trust_roots=tsa_roots, tsa_other_certs=tsa_others)]

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
             "downloaded. Useful when the intermediate's official source is unreachable. "
             "Repeatable; bundles are accepted.",
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit a JSON result."),
) -> None:
    """Optional: refresh the national CA certificates from the network.

    Not normally needed: verification already works offline using the certificates bundled
    with the package. This only re-downloads them into a per-user cache (which takes precedence
    over the bundled copies). Each certificate is verified against a pinned fingerprint before
    caching, and the intermediate is checked to be signed by the root, so the cache can only
    ever hold the same pinned certificates. If the Ministerio del Interior intermediate's official
    source is unreachable, fetch-cas falls back to a Certificate Transparency mirror, or you can
    pass a local copy with --from-file.
    """
    try:
        acrn_path, mica_path = fetch_cas(
            progress=None if json_output else lambda msg: typer.secho(msg, fg=typer.colors.YELLOW, err=True),
            source_files=from_file,
        )
        if json_output:
            typer.echo(_json_dumps({
                "schema_version": _JSON_SCHEMA_VERSION,
                "ok": True,
                "cache_dir": str(cache_dir()),
                "root": str(acrn_path),
                "intermediate": str(mica_path),
            }, False))
        else:
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
    native: bool = typer.Option(
        False, "--native",
        help="Diagnose the native PC/SC path used by --native signing (reader + card over "
             "PC/SC) instead of the PKCS#11 middleware module.",
    ),
    reader: Optional[str] = typer.Option(
        None, "--reader",
        help="PC/SC reader for --native (as shown by list-readers). Auto-detected when only one is present.",
    ),
    pkcs11_lib: str = typer.Option(
        DEFAULT_PKCS11_LIB, "--pkcs11-lib",
        help="Path to the PKCS#11 module to check (ignored with --native).",
    ),
    json_output: bool = typer.Option(False, "--json", help=_JSON_OPT_HELP),
    json_pretty: bool = typer.Option(False, "--json-pretty", help=_JSON_PRETTY_OPT_HELP),
) -> None:
    """Diagnose the local environment for signing with the cédula.

    Reports PASS / WARN / FAIL for each prerequisite, with a remediation hint. Needs no PIN.
    With --native, checks the PC/SC reader and card that native signing uses, instead of the
    PKCS#11 middleware module. Exit code: 0 if there are no FAILs, 1 otherwise (warnings do
    not fail)."""
    # Same pre-flight courtesy the sign commands get from the signing session: say so (on stderr,
    # so --json stdout stays clean) when an option does not apply to the chosen mode, instead of
    # silently ignoring it. Wording matches _check_backend_options for consistency.
    if native and pkcs11_lib != DEFAULT_PKCS11_LIB:
        _warn("Note: --pkcs11-lib is ignored with --native (no PKCS#11 module is used).")
    if not native and reader is not None:
        _warn("Note: --reader only applies to --native; it is ignored with the PKCS#11 backend.")
    checks = _collect_doctor_checks(native, reader, pkcs11_lib)
    if not _doctor_emit(checks, json_output or json_pretty, pretty=json_pretty):
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: list-readers
# ---------------------------------------------------------------------------

@app.command("list-readers")
def list_readers_cmd(
    json_output: bool = typer.Option(False, "--json", help="Emit a JSON result."),
) -> None:
    """List all available PC/SC smart card readers."""
    try:
        available = list_readers()
        if json_output:
            typer.echo(_json_dumps({
                "schema_version": _JSON_SCHEMA_VERSION,
                "readers": [str(reader) for reader in available],
            }, False))
            return
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
        with _card_connection(reader_name) as conn:
            card = read_card(conn)
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
        Optional[Path],
        typer.Argument(
            help='Output JPEG path, or "-" to stream the raw JPEG to stdout (for pipes/redirects). '
                 "Default: cedula_foto.jpg",
            show_default=False,
        ),
    ] = None,
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
        help="Requires --json / --json-pretty: drop the image and any value that could fingerprint "
             "or correlate the cardholder (SHA-256, byte count), keeping only format and pixel "
             "dimensions.",
    ),
) -> None:
    """Save the cardholder's photo (a JPEG) from the cédula, via a PC/SC reader.

    No PIN required: the photo (AIS file 7004) is public, like the biographical data. By default the
    image is written to a file; pass "-" as the output to stream the raw JPEG to stdout instead, so it
    can be piped or redirected (e.g. `firmauy fetch-photo - | feh -`, or `firmauy fetch-photo - >
    cedula_foto.jpg`). Streaming to an interactive terminal is refused, to avoid dumping binary to the screen.

    With --json (or --json-pretty) a self-describing record is written to stdout instead: format, MIME
    type, pixel dimensions, byte count, SHA-256 and the base64-encoded image. --redact drops the image
    and the correlatable values, leaving only the non-identifying shape of the file. Without --json,
    --redact is refused: the photo itself is the identifying data, so a redacted file or stream would
    have nothing to write.

    Note: do not run while a PKCS#11 session (sign-* commands) is active on the same card; both go
    through pcscd and may conflict.
    """
    to_stdout = output is not None and str(output) == "-"
    json_output = json_output or json_pretty
    # None means the argument was omitted, so an explicit path that merely spells out the default
    # is still detected (and refused) alongside --json.
    out_path = output if output is not None else Path("cedula_foto.jpg")
    try:
        if redact and not json_output:
            # The photo is the identifying data itself: honouring --redact on a file or stream
            # would write nothing, and ignoring it would save the full image after a privacy flag.
            raise RuntimeError(
                "--redact only applies to the --json / --json-pretty record. A redacted photo "
                "file or stream would have nothing to write. Use "
                "`firmauy fetch-photo --json --redact`."
            )
        if json_output:
            # --json prints a text record to stdout; a binary file path or "-" would be ambiguous.
            if output is not None:
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
        elif out_path.exists() and not overwrite:
            raise RuntimeError(
                f"Output file already exists: {out_path}\nUse --overwrite to overwrite it."
            )
        with _card_connection(reader_name) as conn:
            photo = read_photo(conn)
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
            ensure_output_parent(out_path)
            out_path.write_bytes(photo)
            typer.secho(f"Photo saved: {out_path} ({len(photo)} bytes)", fg=typer.colors.GREEN)
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
