#!/usr/bin/env python3
# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

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
from cedula_uy_pdf_sign.national_ca import cache_dir, fetch_cas, load_cached_trust_anchors
from cedula_uy_pdf_sign.pdf_verify import verify_pdf
from cedula_uy_pdf_sign.xml_sign import sign_xml
from cedula_uy_pdf_sign.xml_verify import verify_xml

app = typer.Typer(
    help=(
        "Sign PDFs with Uruguayan ID card via PKCS#11 + pyHanko.\n\n"
        "Runs locally by default: no data is transmitted externally.\n"
        "(Note: TSA usage may involve external connections depending on configuration.)\n\n"
        "This project is not affiliated with or endorsed by AGESIC. "
        "No legal validity guaranteed. Use at your own risk."
    )
)


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
# Shared CLI option types (reused by `sign` and `sign-batch`)
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
OverwriteOpt = Annotated[bool, typer.Option("--overwrite", help="Allow overwriting existing output file(s).")]
ForceOpt = Annotated[bool, typer.Option("--force", help="Continue even if the signature field already contains a signature (the resulting PDF may become invalid).")]


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
) -> None:
    """Print the aligned signer/token summary shared by `sign` and `sign-batch`."""
    typer.echo(f"Token:               {token_label_display}")
    typer.echo(f"Signer:              {signer_name}")
    typer.echo(f"Issuer:              {issuer_name}")
    typer.echo(f"PKCS#11 ID:          {key_id.hex()}")
    typer.echo(f"Certificate serial:  {cert_serial}")
    if tsa_url:
        typer.echo(f"TSA:                 {tsa_url}")


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
# Subcommand: sign
# ---------------------------------------------------------------------------

@app.command()
def sign(
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
    overwrite: OverwriteOpt = False,
    force: ForceOpt = False,
) -> None:
    """Sign a PDF with a Uruguayan cédula via PKCS#11 and pyHanko."""
    if output_pdf is None:
        output_pdf = input_pdf.with_stem(input_pdf.stem + "_firmado")
    try:
        # --- Pre-flight checks ---
        if input_pdf.resolve() == output_pdf.resolve():
            raise RuntimeError(
                "Input and output files are the same. "
                "Specify a different output path."
            )

        # Fail-fast before prompting for the PIN. _sign_one_pdf re-checks this
        # right before writing (the authoritative guard, also used by sign-batch);
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
            )

            pkcs11_signer = PKCS11Signer(
                pkcs11_session=session,
                cert_id=key_id,
                key_id=key_id,
            )

            timestamper = HTTPTimeStamper(tsa_url) if tsa_url else None

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

        typer.secho(f"PDF signed successfully: {output_pdf}", fg=typer.colors.GREEN)

    except Exception as exc:
        typer.secho(f"Error: {_format_error(exc)}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: sign-batch
# ---------------------------------------------------------------------------

@app.command("sign-batch")
def sign_batch(
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
    overwrite: OverwriteOpt = False,
    force: ForceOpt = False,
) -> None:
    """Sign multiple PDFs with a single PKCS#11 session (batch mode)."""
    try:
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
            )
            typer.echo(f"Files to sign:       {len(input_pdfs)}")
            typer.echo("")

            pkcs11_signer = PKCS11Signer(
                pkcs11_session=session,
                cert_id=key_id,
                key_id=key_id,
            )

            timestamper = HTTPTimeStamper(tsa_url) if tsa_url else None

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
            )

            _sign_one_xml(
                input_xml=input_xml,
                output_xml=output_xml,
                cert=cert,
                signer=_make_raw_signer(session, key_id),
                signing_time=datetime.now(ZoneInfo(timezone)),
                overwrite=overwrite,
            )

        typer.secho(f"XML signed successfully: {output_xml}", fg=typer.colors.GREEN)

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
# Verification helpers (shared by verify-xml and verify-pdf)
# ---------------------------------------------------------------------------

def _resolve_trust_anchors(ca_file: Optional[Path], no_trust: bool):
    """Return (roots, intermediates): from --ca-file, else the cached national CAs,
    else (None, None) with a hint. Returns (None, None) when trust is skipped."""
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
    typer.secho(
        "Note: no trust anchors available, checking signature integrity only.\n"
        "      Run 'firmauy fetch-cas' to cache the national CAs, or pass --ca-file.",
        fg=typer.colors.YELLOW,
        err=True,
    )
    return None, None


def _print_verify_result(result, prefix: str = "") -> None:
    """Print one verification result (signer + per-check breakdown)."""
    if prefix:
        typer.echo(prefix)
    typer.echo(f"Signer:  {result.signer}")
    typer.echo(f"Issuer:  {result.issuer}")
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


# ---------------------------------------------------------------------------
# Subcommand: verify-xml
# ---------------------------------------------------------------------------

@app.command("verify-xml")
def verify_xml_cmd(
    input_xml: Path = typer.Argument(..., exists=True, readable=True, help="Signed XML to verify."),
    ca_file: Optional[Path] = typer.Option(
        None, "--ca-file",
        help="PEM bundle of trust anchors (root + intermediates). "
             "Defaults to the bundled Uruguayan national CAs.",
    ),
    no_trust: bool = typer.Option(
        False, "--no-trust",
        help="Only check signature integrity (level 1); skip the certificate chain.",
    ),
    check_revocation: bool = typer.Option(
        False, "--check-revocation",
        help="Also check certificate revocation via CRL/OCSP (level 3). Requires network.",
    ),
) -> None:
    """Verify a signed XAdES XML: signature integrity, and (unless --no-trust) the
    certificate chain up to the Uruguayan national root.

    Indication: VALID (integrity + trusted chain), INDETERMINATE (integrity OK but
    chain not trusted/not checked), INVALID (signature broken or document modified).
    Note: revocation (CRL/OCSP) is not checked, and for XAdES-BES the signing time
    is self-asserted, so validity is evaluated at verification time.
    """
    try:
        if check_revocation and no_trust:
            raise RuntimeError("--check-revocation requires the certificate chain; remove --no-trust.")

        roots, intermediates = _resolve_trust_anchors(ca_file, no_trust)

        result = verify_xml(
            input_xml.read_bytes(),
            trust_roots=roots,
            intermediates=intermediates,
            check_revocation=check_revocation,
        )

        _print_verify_result(result)
        typer.secho(f"Indication: {result.indication}",
                    fg=_INDICATION_COLOR[result.indication], bold=True)

        if result.indication == "INVALID":
            raise typer.Exit(code=1)
        if result.indication == "INDETERMINATE":
            raise typer.Exit(code=2)

    except typer.Exit:
        raise
    except Exception as exc:
        typer.secho(f"Error: {_format_error(exc)}", fg=typer.colors.RED, err=True)
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
             "Defaults to the cached national CAs (see 'firmauy fetch-cas').",
    ),
    no_trust: bool = typer.Option(
        False, "--no-trust",
        help="Only check signature integrity; skip the certificate chain.",
    ),
    check_revocation: bool = typer.Option(
        False, "--check-revocation",
        help="Also check certificate revocation via CRL/OCSP. Requires network.",
    ),
) -> None:
    """Verify the signatures in a PDF (PAdES): integrity, coverage, and (unless --no-trust)
    the certificate chain up to the Uruguayan national root.

    Same indication model as verify-xml (VALID / INDETERMINATE / INVALID); with multiple
    signatures, the overall indication is the worst one. Exit: 0 VALID, 1 INVALID, 2 INDETERMINATE.
    """
    try:
        if check_revocation and no_trust:
            raise RuntimeError("--check-revocation requires the certificate chain; remove --no-trust.")

        roots, intermediates = _resolve_trust_anchors(ca_file, no_trust)

        results = verify_pdf(
            input_pdf,
            trust_roots=roots,
            intermediates=intermediates,
            check_revocation=check_revocation,
        )

        for i, result in enumerate(results, 1):
            prefix = f"--- Signature {i} of {len(results)} ---" if len(results) > 1 else ""
            _print_verify_result(result, prefix)

        overall = max((r.indication for r in results), key=lambda ind: _INDICATION_RANK[ind])
        typer.secho(f"Indication: {overall}", fg=_INDICATION_COLOR[overall], bold=True)

        if overall == "INVALID":
            raise typer.Exit(code=1)
        if overall == "INDETERMINATE":
            raise typer.Exit(code=2)

    except typer.Exit:
        raise
    except Exception as exc:
        typer.secho(f"Error: {_format_error(exc)}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Subcommand: fetch-cas
# ---------------------------------------------------------------------------

@app.command("fetch-cas")
def fetch_cas_cmd() -> None:
    """Download and cache the Uruguayan national CA certificates for verification.

    The certificates are fetched from their official sources (AGESIC / UCE /
    Ministerio del Interior); the national root is verified against a pinned
    fingerprint before caching. This package does not redistribute the state CAs.
    """
    try:
        acrn_path, mica_path = fetch_cas()
        typer.secho(f"National CAs cached in {cache_dir()}", fg=typer.colors.GREEN)
        typer.echo(f"  root:         {acrn_path.name}")
        typer.echo(f"  intermediate: {mica_path.name}")
        typer.echo("\n'firmauy verify-xml' will now validate the chain to the national root.")
    except Exception as exc:
        typer.secho(f"Error: {_format_error(exc)}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
