#!/usr/bin/env python3
# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

import json
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Annotated, List, Optional
from zoneinfo import ZoneInfo

import pkcs11
import typer
from cryptography import x509
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

from cedula_uy_pdf_sign.appearance import ensure_output_parent, make_appearance_pdf
from cedula_uy_pdf_sign.cert_utils import get_common_name, normalize_issuer_name, cert_not_after
from cedula_uy_pdf_sign.constants import (
    APPEARANCE_HEIGHT,
    APPEARANCE_WIDTH,
    DEFAULT_PKCS11_LIB,
    DEFAULT_TIMEZONE,
    DEFAULT_X1,
    DEFAULT_X2,
    DEFAULT_Y1,
    DEFAULT_Y2,
)
from cedula_uy_pdf_sign.pin import PinSource, get_pin
from cedula_uy_pdf_sign.pkcs11_utils import (
    find_token,
    get_private_key,
    iter_cert_objects,
    load_pkcs11_lib,
    select_certificate,
)
from cedula_uy_pdf_sign.national_ca import (
    cache_dir,
    fetch_cas,
    load_bundled_trust_anchors,
    load_cached_trust_anchors,
)
from cedula_uy_pdf_sign.pdf_verify import verify_pdf
from cedula_uy_pdf_sign.xml_sign import sign_xml
from cedula_uy_pdf_sign.xml_verify import verify_xml
from cedula_uy_pdf_sign.cms_sign import sign_cms_detached
from cedula_uy_pdf_sign.cms_verify import verify_cms

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
            v = version("cedula-uy-pdf-sign")
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
TsaHeaderOpt = Annotated[Optional[List[str]], typer.Option("--tsa-header", help="Extra HTTP header sent to the TSA as 'Name: Value' (repeatable; e.g. a Bearer token or API key).")]
OverwriteOpt = Annotated[bool, typer.Option("--overwrite", help="Allow overwriting existing output file(s).")]
ForceOpt = Annotated[bool, typer.Option("--force", help="Continue even if the signature field already contains a signature (the resulting PDF may become invalid).")]
QuietOpt = Annotated[bool, typer.Option("--quiet", "-q", help="Do not print the signer identity block (name, issuer, certificate serial, PKCS#11 ID). Use in batch/automation to keep identifying data out of logs.")]
VerifyOpt = Annotated[bool, typer.Option("--verify", help="After signing, re-verify the produced signature (integrity and coverage, no trust); the command fails if it is not intact.")]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _print_signing_info(
    *,
    token_label_display: str,
    signer_name: str,
    issuer_name: str,
    key_id: bytes,
    cert_serial: str,
    tsa_url: Optional[str],
    quiet: bool = False,
) -> None:
    """Print the aligned signer/token summary shared by `sign-pdf` and `sign-pdf-batch`.

    Skipped entirely when ``quiet`` is set, to keep identifying data (signer name,
    certificate serial, PKCS#11 ID) out of automation/CI logs.
    """
    if quiet:
        return
    typer.echo(f"Token:               {token_label_display}")
    typer.echo(f"Signer:              {signer_name}")
    typer.echo(f"Issuer:              {issuer_name}")
    typer.echo(f"PKCS#11 ID:          {key_id.hex()}")
    typer.echo(f"Certificate serial:  {cert_serial}")
    if tsa_url:
        typer.echo(f"TSA:                 {tsa_url}")


def _build_timestamper(
    *,
    tsa_url: Optional[str],
    tsa_user: Optional[str],
    tsa_pass_env: Optional[str],
    tsa_header: Optional[List[str]],
):
    """Build an HTTPTimeStamper from the TSA options, or None when no --tsa-url is given.

    Supports HTTP Basic auth (``--tsa-user`` + ``--tsa-pass-env``) and arbitrary extra
    headers (``--tsa-header 'Name: Value'``, e.g. a Bearer token / API key) for credentialed
    RFC 3161 TSAs. The password is read from an environment variable, never taken on the
    command line. Raises ``typer.BadParameter`` on inconsistent options."""
    if tsa_url is None:
        if tsa_user or tsa_pass_env or tsa_header:
            raise typer.BadParameter(
                "--tsa-user / --tsa-pass-env / --tsa-header require --tsa-url."
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

    headers = None
    if tsa_header:
        headers = {}
        for item in tsa_header:
            name, sep, value = item.partition(":")
            if not sep or not name.strip():
                raise typer.BadParameter(
                    f"--tsa-header '{item}' must be in 'Name: Value' format."
                )
            headers[name.strip()] = value.strip()

    return HTTPTimeStamper(tsa_url, auth=auth, headers=headers)


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
) -> None:
    """Sign a single PDF. Raises on any error."""
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

            with output_pdf.open("wb") as outf:
                pdf_signer.sign_pdf(writer, output=outf)

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

@app.command("list-certs")
def list_certs(
    pkcs11_lib: str = typer.Option(
        DEFAULT_PKCS11_LIB, "--pkcs11-lib", help="Path to the PKCS#11 module.",
    ),
    token_label: Optional[str] = typer.Option(
        None, "--token-label",
        help="Exact PKCS#11 token label. If not provided, auto-detected.",
    ),
    pin_source: PinSource = typer.Option(
        PinSource.prompt, "--pin-source",
        help="How to obtain the PIN: prompt (default), env, stdin, fd.",
    ),
    pin_env_var: Optional[str] = typer.Option(
        None, "--pin-env-var",
        help="Environment variable holding the PIN (requires --pin-source env).",
    ),
    pin_fd: Optional[int] = typer.Option(
        None, "--pin-fd",
        help="File descriptor holding the PIN (requires --pin-source fd).",
    ),
) -> None:
    """List all certificates available on the token."""
    try:
        lib = load_pkcs11_lib(pkcs11_lib)
        token = find_token(lib, token_label)
        final_pin = get_pin(pin_source, pin_env_var, pin_fd)

        with token.open(user_pin=final_pin) as session:
            found = False
            for cert_obj in iter_cert_objects(session):
                try:
                    obj_id = cert_obj[pkcs11.Attribute.ID]
                    cert_der = cert_obj[pkcs11.Attribute.VALUE]
                    cert = x509.load_der_x509_certificate(cert_der)
                except Exception:
                    continue

                found = True
                subject_cn = get_common_name(cert.subject)
                issuer_cn = normalize_issuer_name(get_common_name(cert.issuer))
                serial = format(cert.serial_number, "X")
                not_after = cert_not_after(cert)
                try:
                    ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
                    digital_sig = "yes" if ku.value.digital_signature else "no"
                except x509.ExtensionNotFound:
                    digital_sig = "?"

                typer.echo(
                    f"ID:                {obj_id.hex()}\n"
                    f"Subject:           {subject_cn}\n"
                    f"Issuer:            {issuer_cn}\n"
                    f"Serial:            {serial}\n"
                    f"Valid until:       {not_after}\n"
                    f"Digital signature: {digital_sig}\n"
                )

            if not found:
                typer.echo("No certificates found in the token.")

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
    overwrite: OverwriteOpt = False,
    force: ForceOpt = False,
    quiet: QuietOpt = False,
    verify: VerifyOpt = False,
) -> None:
    """Sign a PDF with a Uruguayan cédula via PKCS#11 and pyHanko."""
    if output_pdf is None:
        output_pdf = input_pdf.with_stem(input_pdf.stem + "_firmado")
    try:
        # --- Pre-flight checks ---
        timestamper = _build_timestamper(
            tsa_url=tsa_url,
            tsa_user=tsa_user,
            tsa_pass_env=tsa_pass_env,
            tsa_header=tsa_header,
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
                token_label_display=token_label_display,
                signer_name=signer_name,
                issuer_name=issuer_name,
                key_id=key_id,
                cert_serial=cert_serial,
                tsa_url=tsa_url,
                quiet=quiet,
            )

            pkcs11_signer = PKCS11Signer(
                pkcs11_session=session,
                cert_id=key_id,
                key_id=key_id,
            )

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
                pkcs11_signer=pkcs11_signer,
                signer_name=signer_name,
                issuer_name=issuer_name,
                cert_serial=cert_serial,
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
    overwrite: OverwriteOpt = False,
    force: ForceOpt = False,
    quiet: QuietOpt = False,
    verify: VerifyOpt = False,
) -> None:
    """Sign multiple PDFs with a single PKCS#11 session (batch mode)."""
    try:
        timestamper = _build_timestamper(
            tsa_url=tsa_url,
            tsa_user=tsa_user,
            tsa_pass_env=tsa_pass_env,
            tsa_header=tsa_header,
        )

        all_pdfs: List[Path] = list(input_pdfs) if input_pdfs else []

        if input_dir is not None:
            if not input_dir.is_dir():
                typer.secho(
                    f"--input-dir '{input_dir}' is not a valid directory.",
                    fg=typer.colors.RED,
                    err=True,
                )
                raise typer.Exit(code=1)
            pattern = "**/*.pdf" if recursive else "*.pdf"
            all_pdfs += sorted(input_dir.glob(pattern))

        if not all_pdfs:
            typer.secho(
                "No input files specified. "
                "Use positional arguments or --input-dir.",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)

        input_pdfs = all_pdfs

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

        output_dir.mkdir(parents=True, exist_ok=True)

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
                token_label_display=token_label_display,
                signer_name=signer_name,
                issuer_name=issuer_name,
                key_id=key_id,
                cert_serial=cert_serial,
                tsa_url=tsa_url,
                quiet=quiet,
            )
            typer.echo(f"Files to sign:       {len(input_pdfs)}")
            typer.echo("")

            pkcs11_signer = PKCS11Signer(
                pkcs11_session=session,
                cert_id=key_id,
                key_id=key_id,
            )

            meta = signers.PdfSignatureMetadata(
                field_name=field_name,
                reason=reason,
                location=location,
                contact_info=contact_info,
                md_algorithm=None,
            )

            ok_count = 0
            err_count = 0

            for input_pdf in input_pdfs:
                output_pdf = output_dir / f"{input_pdf.stem}{suffix}.pdf"
                try:
                    _sign_one_pdf(
                        input_pdf=input_pdf,
                        output_pdf=output_pdf,
                        pkcs11_signer=pkcs11_signer,
                        signer_name=signer_name,
                        issuer_name=issuer_name,
                        cert_serial=cert_serial,
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
                    )
                    if verify:
                        _verify_after_pdf(output_pdf)
                    typer.secho(f"OK:    {output_pdf}", fg=typer.colors.GREEN)
                    ok_count += 1
                except Exception as exc:
                    typer.secho(f"ERROR: {input_pdf}: {_format_error(exc)}", fg=typer.colors.RED, err=True)
                    err_count += 1

        typer.echo("")
        typer.echo(f"Signed: {ok_count}/{len(input_pdfs)}. Errors: {err_count}.")

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
) -> None:
    """Sign a single XML (XAdES-BES, enveloped). Raises on any error."""
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
    )
    output_xml.write_bytes(signed)


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
    if output_p7s.exists() and not overwrite:
        raise RuntimeError(
            f"Output file already exists: {output_p7s}\n"
            "Use --overwrite to overwrite it."
        )
    ensure_output_parent(output_p7s)
    with input_file.open("rb") as f:
        p7s = sign_cms_detached(f, signer=pkcs11_signer, timestamper=timestamper)
    output_p7s.write_bytes(p7s)


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
    _check_post_sign(verify_xml(output_xml.read_bytes(), trust_roots=None))


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
    pin_source: PinSourceOpt = PinSource.prompt,
    pin_env_var: PinEnvVarOpt = None,
    pin_fd: PinFdOpt = None,
    timezone: TimezoneOpt = DEFAULT_TIMEZONE,
    overwrite: OverwriteOpt = False,
    quiet: QuietOpt = False,
    verify: VerifyOpt = False,
) -> None:
    """Sign an XML document with a Uruguayan cédula (XAdES-BES, enveloped)."""
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
                token_label_display=token_label_display,
                signer_name=signer_name,
                issuer_name=issuer_name,
                key_id=key_id,
                cert_serial=cert_serial,
                tsa_url=None,
                quiet=quiet,
            )

            _sign_one_xml(
                input_xml=input_xml,
                output_xml=output_xml,
                cert=cert,
                signer=_make_raw_signer(session, key_id),
                signing_time=datetime.now(ZoneInfo(timezone)),
                overwrite=overwrite,
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
    pin_source: PinSourceOpt = PinSource.prompt,
    pin_env_var: PinEnvVarOpt = None,
    pin_fd: PinFdOpt = None,
    timezone: TimezoneOpt = DEFAULT_TIMEZONE,
    overwrite: OverwriteOpt = False,
    quiet: QuietOpt = False,
    verify: VerifyOpt = False,
) -> None:
    """Sign multiple XML documents with a single PKCS#11 session (XAdES-BES, enveloped)."""
    try:
        all_xmls: List[Path] = list(input_xmls) if input_xmls else []

        if input_dir is not None:
            if not input_dir.is_dir():
                typer.secho(
                    f"--input-dir '{input_dir}' is not a valid directory.",
                    fg=typer.colors.RED,
                    err=True,
                )
                raise typer.Exit(code=1)
            pattern = "**/*.xml" if recursive else "*.xml"
            all_xmls += sorted(input_dir.glob(pattern))

        if not all_xmls:
            typer.secho(
                "No input files specified. "
                "Use positional arguments or --input-dir.",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)

        output_dir.mkdir(parents=True, exist_ok=True)

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
                token_label_display=token_label_display,
                signer_name=signer_name,
                issuer_name=issuer_name,
                key_id=key_id,
                cert_serial=cert_serial,
                tsa_url=None,
                quiet=quiet,
            )
            typer.echo(f"Files to sign:       {len(all_xmls)}")
            typer.echo("")

            raw_signer = _make_raw_signer(session, key_id)

            ok_count = 0
            err_count = 0

            for input_xml in all_xmls:
                output_xml = output_dir / f"{input_xml.stem}{suffix}.xml"
                try:
                    _sign_one_xml(
                        input_xml=input_xml,
                        output_xml=output_xml,
                        cert=cert,
                        signer=raw_signer,
                        signing_time=datetime.now(ZoneInfo(timezone)),
                        overwrite=overwrite,
                    )
                    if verify:
                        _verify_after_xml(output_xml)
                    typer.secho(f"OK:    {output_xml}", fg=typer.colors.GREEN)
                    ok_count += 1
                except Exception as exc:
                    typer.secho(f"ERROR: {input_xml}: {_format_error(exc)}", fg=typer.colors.RED, err=True)
                    err_count += 1

        typer.echo("")
        typer.echo(f"Signed: {ok_count}/{len(all_xmls)}. Errors: {err_count}.")

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
    pin_source: PinSourceOpt = PinSource.prompt,
    pin_env_var: PinEnvVarOpt = None,
    pin_fd: PinFdOpt = None,
    tsa_url: TsaUrlOpt = None,
    tsa_user: TsaUserOpt = None,
    tsa_pass_env: TsaPassEnvOpt = None,
    tsa_header: TsaHeaderOpt = None,
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
                token_label_display=token_label_display,
                signer_name=signer_name,
                issuer_name=issuer_name,
                key_id=key_id,
                cert_serial=cert_serial,
                tsa_url=tsa_url,
                quiet=quiet,
            )

            pkcs11_signer = PKCS11Signer(
                pkcs11_session=session,
                cert_id=key_id,
                key_id=key_id,
            )

            _sign_one_cms(
                input_file=input_file,
                output_p7s=output_p7s,
                pkcs11_signer=pkcs11_signer,
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
    pin_source: PinSourceOpt = PinSource.prompt,
    pin_env_var: PinEnvVarOpt = None,
    pin_fd: PinFdOpt = None,
    tsa_url: TsaUrlOpt = None,
    tsa_user: TsaUserOpt = None,
    tsa_pass_env: TsaPassEnvOpt = None,
    tsa_header: TsaHeaderOpt = None,
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

        output_dir.mkdir(parents=True, exist_ok=True)

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
                token_label_display=token_label_display,
                signer_name=signer_name,
                issuer_name=issuer_name,
                key_id=key_id,
                cert_serial=cert_serial,
                tsa_url=tsa_url,
                quiet=quiet,
            )
            typer.echo(f"Files to sign:       {len(jobs)}")
            typer.echo("")

            pkcs11_signer = PKCS11Signer(
                pkcs11_session=session,
                cert_id=key_id,
                key_id=key_id,
            )

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
    typer.echo(f"Signer:  {_display_name(result.signer, redact)}")
    typer.echo(f"Issuer:  {_display_name(result.issuer)}")
    typer.echo("")
    for c in result.checks:
        mark = "PASS" if c.ok else "FAIL"
        color = typer.colors.GREEN if c.ok else typer.colors.RED
        typer.secho(f"  [{mark}] {c.name}" + (f"  ({c.detail})" if c.detail else ""), fg=color)
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


def _result_to_json_obj(result, redact: bool) -> dict:
    return {
        "indication": result.indication,
        "signer": _redact_signer(result.signer) if redact else result.signer,
        "issuer": result.issuer,
        "trusted": result.trusted,
        "checks": [{"name": c.name, "ok": c.ok, "detail": c.detail} for c in result.checks],
    }


def _json_dumps(obj: dict, pretty: bool) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2 if pretty else None)


def _emit_verify(results: list, json_output: bool, pretty: bool = False, redact: bool = False) -> str:
    """Emit verification results and return the overall indication (worst of all signatures).

    With ``json_output`` a single JSON object is written to stdout; otherwise the human-readable
    per-check breakdown is printed. ``pretty`` indents the JSON; ``redact`` hides the signer's
    personal fields (issuer kept). Exit codes are decided by the caller from the returned
    indication, so they are identical in every mode.

        {"schema_version": 1, "indication": "...", "signatures": [
            {"indication", "signer": {...}, "issuer": {...}, "trusted",
             "checks": [{"name","ok","detail"}]}]}
    """
    overall = max((r.indication for r in results), key=lambda ind: _INDICATION_RANK[ind])
    if json_output:
        payload = {
            "schema_version": _JSON_SCHEMA_VERSION,
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
    json_output: bool = typer.Option(False, "--json", help=_JSON_OPT_HELP),
    json_pretty: bool = typer.Option(False, "--json-pretty", help=_JSON_PRETTY_OPT_HELP),
    redact: bool = typer.Option(False, "--redact", help=_REDACT_OPT_HELP),
) -> None:
    """Verify a signed XAdES XML: signature integrity, and (unless --no-trust) the
    certificate chain up to the Uruguayan national root.

    Indication: VALID (integrity + trusted chain), INDETERMINATE (integrity OK but
    chain not trusted/not checked), INVALID (signature broken or document modified).
    Note: revocation (CRL/OCSP) is not checked, and for XAdES-BES the signing time
    is self-asserted, so validity is evaluated at verification time.
    """
    try:
        json_output = json_output or json_pretty
        if check_revocation and no_trust:
            raise RuntimeError("--check-revocation requires the certificate chain; remove --no-trust.")

        roots, intermediates = _resolve_trust_anchors(ca_file, no_trust)

        result = verify_xml(
            input_xml.read_bytes(),
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

def _detect_signature_kind(path: Path) -> str:
    """Detect a signed file's format by content: "pdf", "xml" (XAdES) or "cms" (detached
    .p7s in DER). Raises ValueError if none match."""
    from asn1crypto import cms as asn1cms

    raw = path.read_bytes()
    if not raw:
        raise ValueError("file is empty")
    if raw[:1024].find(b"%PDF-") != -1:
        return "pdf"
    head = raw.lstrip(b"\xef\xbb\xbf").lstrip()      # skip a UTF-8 BOM and leading whitespace
    if head[:1] == b"<":
        return "xml"
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
        roots, intermediates = _resolve_trust_anchors(ca_file, no_trust)

        if kind == "pdf":
            results = verify_pdf(input_file, trust_roots=roots, intermediates=intermediates,
                                 check_revocation=check_revocation)
        elif kind == "xml":
            results = [verify_xml(input_file.read_bytes(), trust_roots=roots,
                                  intermediates=intermediates, check_revocation=check_revocation)]
        else:  # cms / detached .p7s
            orig = original or _detached_original(input_file)
            if orig is None or not orig.exists():
                raise RuntimeError(
                    "detached .p7s signature needs its original file; pass it with --original"
                    + (f" (looked for '{orig}')" if orig is not None else "")
                )
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
        typer.echo("\n'firmauy verify-xml' will now validate the chain to the national root.")
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
        v = _pkg_version("cedula-uy-pdf-sign")
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
