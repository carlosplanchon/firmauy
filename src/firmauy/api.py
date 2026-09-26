# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Public library API for firmauy: sign, verify, read the cédula, introspect and diagnose.

These are thin, integration-friendly wrappers over the same logic the CLI uses. They
return the dataclasses from ``verify_common`` (and small report objects), never printed
output or process exit codes, so a GUI or another program can consume them directly.

The engine lives in domain modules shared with the CLI: the signing machinery in
``firmauy.signing`` (presentation-free), the verify and diagnostic helpers in
``firmauy._shared``. Nothing here imports the Typer command module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional, Union
from zoneinfo import ZoneInfo

from firmauy.cms_verify import verify_cms
from firmauy.pdf_verify import verify_pdf
from firmauy.verify_common import VerifyResult
from firmauy.xml_verify import verify_xml

# Domain exceptions, re-exported so API consumers can catch precise conditions (or the whole
# family through FirmaUYError) from one place. See firmauy.errors for the hierarchy.
from firmauy.errors import (
    BatchSignCancelled as BatchSignCancelled,
    BatchSignError as BatchSignError,
    CardNotFoundError as CardNotFoundError,
    CertificateError as CertificateError,
    CertificateNotFoundError as CertificateNotFoundError,
    CertificateNotValidError as CertificateNotValidError,
    DetachedOriginalRequiredError as DetachedOriginalRequiredError,
    FirmaUYError as FirmaUYError,
    IncorrectPinError as IncorrectPinError,
    OutputAccessControlError as OutputAccessControlError,
    OutputCommittedError as OutputCommittedError,
    OutputExistsError as OutputExistsError,
    PostSignVerificationError as PostSignVerificationError,
    PinError as PinError,
    PinLockedError as PinLockedError,
    ReaderNotFoundError as ReaderNotFoundError,
    SigningKeyNotFoundError as SigningKeyNotFoundError,
    TokenNotFoundError as TokenNotFoundError,
)

# The vocabulary of the signing arguments, here for the same reason as the exceptions: these
# belong to the public signatures, and a caller that wants to reject a bad value before touching
# the card should not have to reach past this module to name the valid ones. Free to import, since
# firmauy.constants pulls in the standard library's enum and dataclasses and nothing else.
from firmauy.constants import ImageMode as ImageMode
from firmauy.constants import SignAs as SignAs
from firmauy.constants import StampCorner as StampCorner
from firmauy.constants import (
    DEFAULT_IMAGE_OPACITY,
    DEFAULT_PKCS11_LIB,
    DEFAULT_TIMEZONE,
    DEFAULT_X1,
    DEFAULT_X2,
    DEFAULT_Y1,
    DEFAULT_Y2,
    StampFields,
)


@dataclass(frozen=True)
class VerifyReport:
    """Overall verdict plus the per-signature results."""

    indication: str  # VALID / INDETERMINATE / INVALID
    signatures: list[VerifyResult] = field(default_factory=list)


@dataclass(frozen=True)
class DoctorCheck:
    """One environment check: ``status`` is PASS / WARN / FAIL, ``fix`` a hint when not PASS.

    ``sensitive`` marks a check whose ``detail`` can carry the cardholder's own data (the token
    label is the holder's name with some PKCS#11 modules), so a consumer that must not leak it can
    decide without parsing the text.
    """

    status: str
    name: str
    detail: str = ""
    fix: Optional[str] = None
    sensitive: bool = False


@dataclass(frozen=True)
class DoctorReport:
    """Diagnostic result: ``ok`` is True when no check FAILed (a WARN does not fail)."""

    ok: bool
    checks: list[DoctorCheck] = field(default_factory=list)


@dataclass(frozen=True)
class SignReport:
    """Result of a successful signature: where it was written, who signed, and how.

    ``kind`` is the signature that was produced: ``"pades"`` (embedded in the PDF), ``"xades"``
    (embedded in the XML) or ``"cades"`` (a detached ``.p7s``); with :func:`sign`'s auto-detection
    this is how the caller learns what came out. ``backend`` is ``"native"`` (PC/SC) or
    ``"pkcs11"``; in the PKCS#11 case ``pkcs11_lib`` is the resolved module path that actually
    signed (e.g. the bundled middleware vs OpenSC's ``opensc-pkcs11.so``), None in native mode.
    ``verified`` is True when the fresh signature was re-checked (``verify=True``) and found
    intact. The trailing fields default for backward compatibility.
    """

    output_path: Path
    signer: str  # signer certificate common name
    issuer: str  # issuer certificate common name
    kind: str = ""
    backend: str = ""
    certificate_serial: str = ""
    verified: bool = False
    pkcs11_lib: Optional[str] = None


@dataclass(frozen=True)
class CiReport:
    """A cédula-number check-digit validation (a purely arithmetic consistency check, no identity)."""

    valid: bool
    normalized: str
    body: str
    check_digit: str
    expected_check_digit: str


@dataclass(frozen=True)
class CaBundle:
    """The national CA certificate files after a refresh: the two paths plus the cache directory."""

    root_path: Path
    intermediate_path: Path
    cache_dir: Path


@dataclass(frozen=True)
class IdentityReport:
    """The cédula's biographic data (read from the public AIS files, no PIN).

    Fields the card does not carry are ``None``. ``id_number_check_digit_valid`` is the arithmetic
    check-digit consistency of the cédula number (see :func:`validate_ci`).
    """

    lastnames: Optional[str] = None
    second_lastname: Optional[str] = None
    given_names: Optional[str] = None
    nationality: Optional[str] = None
    birth_date: Optional[str] = None
    birthplace: Optional[str] = None
    id_number: Optional[str] = None
    id_number_check_digit_valid: Optional[bool] = None
    issue_date: Optional[str] = None
    expiry_date: Optional[str] = None
    document_number: Optional[str] = None
    mrz: Optional[list] = None


@dataclass(frozen=True)
class PhotoReport:
    """The cardholder's photo: the raw JPEG bytes in ``data`` plus its metadata."""

    data: bytes
    format: str
    mime: str
    width: Optional[int]
    height: Optional[int]
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class TokenInfo:
    """A PKCS#11 token. Each field is the trimmed attribute, or ``None`` when the token leaves it empty."""

    label: Optional[str]
    manufacturer: Optional[str]
    model: Optional[str]
    serial: Optional[str]


@dataclass(frozen=True)
class CertInfo:
    """A certificate on a PKCS#11 token. ``subject``/``issuer`` are ``name_fields`` dicts (as in verify)."""

    id: str
    subject: dict
    issuer: dict
    certificate_serial: str
    not_after: str
    digital_signature: Optional[bool]
    pem: Optional[str] = None


@dataclass(frozen=True)
class PdfAppearance:
    """Where a PDF's visible stamp goes on the page, and which of its five lines it prints.

    The stamp is drawn on a page and is not the signature. Nothing here changes what is signed,
    what a verifier reads, or whether the file validates: a stamp with every line turned off and
    a signature that reaches the national root is still VALID, and a stamp that lists everything
    over a broken signature is still INVALID. What it changes is what a person sees when they
    open the document.

    Defaults reproduce exactly what firmauy drew before this class existed: the last page, a
    205x70 box in the bottom-left corner, all five lines, no image. That default box can land on
    top of a footer or the last lines of text, which is what ``x1``/``y1``/``x2``/``y2`` are for.

    ``image`` fills the box behind the text (``image_mode="background"``, faded to
    ``image_opacity``), beside it (``"side"``), or replaces it (``"only"``). ``show_document`` is
    the certificate's serial rather than the cédula number, so leaving it on identifies the
    certificate without printing somebody's national ID on every copy of the file.

    Values are checked here, on construction, rather than deep inside a signing call. A wrong
    coordinate or a missing image file is worth learning before the PIN is entered and the card
    has spent one of its tries.

    .. versionadded:: 1.16.0
    """

    page: int = -1                                  # -1 is the last page
    # A corner is resolved against that page's own MediaBox while the file is open, so it lands
    # correctly on any paper size. It keeps the box's size and changes only its place, which is
    # why the default corner reproduces the default coordinates exactly. None uses them as given.
    corner: Optional[str] = None
    margin: float = 20.0                            # points from the two edges of the corner
    x1: int = DEFAULT_X1
    y1: int = DEFAULT_Y1
    x2: int = DEFAULT_X2
    y2: int = DEFAULT_Y2
    image: Optional[Union[str, Path]] = None
    image_mode: str = ImageMode.background.value
    image_opacity: float = DEFAULT_IMAGE_OPACITY
    timezone: str = DEFAULT_TIMEZONE
    show_title: bool = True                         # "Firma electrónica avanzada, UY"
    show_signer: bool = True                        # "Firmado por: ..."
    show_document: bool = True                      # "Documento: ..." (the certificate serial)
    show_date: bool = True                          # "Fecha: ..."
    show_issuer: bool = True                        # the issuing authority's name

    def __post_init__(self) -> None:
        ImageMode(self.image_mode)                  # ValueError names the valid modes
        if self.corner is not None:
            StampCorner(self.corner)                # ValueError names the four corners
            if self.margin < 0:
                raise ValueError(f"margin cannot be negative, got {self.margin}")
        if not 0.0 <= self.image_opacity <= 1.0:
            raise ValueError(f"image_opacity must be between 0 and 1, got {self.image_opacity}")
        if self.x2 <= self.x1 or self.y2 <= self.y1:
            raise ValueError(
                f"the stamp box is empty or inverted: ({self.x1}, {self.y1}) to "
                f"({self.x2}, {self.y2}). x2 must exceed x1 and y2 must exceed y1.")
        # A zone is a lookup in the tz database, so a misspelt one is knowable here. It was not
        # looked up until the stamp was drawn, inside the signing call, after the PIN had been
        # verified: the ordering this method exists to prevent. Anything the lookup refuses is
        # refused, an unknown key as much as the empty or path-like strings ZoneInfo will not
        # look up, and as a ValueError, because an unknown zone arrives as a KeyError and a
        # caller checking arguments has no reason to expect one.
        try:
            ZoneInfo(self.timezone)
        except Exception as exc:
            raise ValueError(
                f"timezone {self.timezone!r} is not a valid IANA time zone: "
                f"{exc.args[0] if exc.args else exc}") from exc
        if self.image is not None:
            if not Path(self.image).is_file():
                raise FileNotFoundError(f"stamp image not found: {self.image}")
            # Otherwise decoded only when the stamp is drawn, inside the signing call and after
            # the PIN: the ordering this method exists to prevent.
            from firmauy.appearance import check_stamp_image

            try:
                check_stamp_image(self.image)
            except ValueError as exc:
                raise ValueError(f"stamp image {self.image} is not a usable image: {exc}") from exc

    def _pdf_kwargs(self) -> dict:
        """The arguments `_sign_one_pdf` takes for the appearance. Private on purpose: the shape
        of that internal is not something a caller should be able to depend on."""
        return dict(
            page=self.page, x1=self.x1, y1=self.y1, x2=self.x2, y2=self.y2,
            corner=StampCorner(self.corner) if self.corner is not None else None,
            margin=self.margin,
            timezone=self.timezone,
            image_path=Path(self.image) if self.image is not None else None,
            image_mode=ImageMode(self.image_mode),
            image_opacity=self.image_opacity,
            stamp_fields=StampFields(
                title=self.show_title, signer=self.show_signer, document=self.show_document,
                date=self.show_date, issuer=self.show_issuer,
            ),
        )


_DEFAULT_APPEARANCE = PdfAppearance()


def verify(
    path: Union[str, Path],
    *,
    original: Optional[Union[str, Path]] = None,
    ca_file: Optional[Union[str, Path]] = None,
    no_trust: bool = False,
    check_revocation: bool = False,
    tsa_ca: Optional[Union[str, Path]] = None,
) -> VerifyReport:
    """Verify a signed file (PDF, XAdES XML or detached CMS ``.p7s``), auto-detecting the format.

    Returns a :class:`VerifyReport` with the overall ``indication`` and the per-signature
    :class:`~firmauy.verify_common.VerifyResult` objects. Needs no card or PIN.

    For a detached ``.p7s``, ``original`` is the file it signs; by default the
    ``<x>.p7s -> <x>`` convention is used.

    ``tsa_ca`` holds the anchors an RFC 3161 signature timestamp's own chain is validated
    against, and applies to all three formats. It is deliberately separate from ``ca_file``:
    those decide who is accepted as having *signed* the document, and a TSA has no business
    widening that. Without it a timestamp is reported as present and unvalidated, which is
    neither trusted nor broken. Each result carries the outcome as
    :class:`~firmauy.verify_common.TimestampInfo` on ``.timestamp``; read that rather than
    parsing check names, whose wording differs per format.

    .. versionchanged:: 1.12.0
       ``tsa_ca`` used to apply to XML only, and the PDF and CMS verifiers discarded pyHanko's
       timestamp status entirely, so a broken timestamp went unmentioned.
    """
    from firmauy._shared import (
        _INDICATION_RANK,
        _detached_original,
        _detect_signature_kind,
        _resolve_trust_anchors,
        _resolve_tsa_anchors,
        read_bounded,
    )
    from firmauy.cms_verify import MAX_CMS_BYTES

    path = Path(path)
    kind = _detect_signature_kind(path)
    roots, intermediates = _resolve_trust_anchors(Path(ca_file) if ca_file else None, no_trust)

    # Resolved once for every format. It used to be worked out inside the XML branch only, so
    # --tsa-ca silently did nothing for a PDF or a .p7s: the option was accepted and ignored.
    tsa_roots, tsa_others = _resolve_tsa_anchors(Path(tsa_ca) if tsa_ca else None)

    if kind == "pdf":
        results = verify_pdf(path, trust_roots=roots, intermediates=intermediates,
                             check_revocation=check_revocation,
                             tsa_trust_roots=tsa_roots, tsa_other_certs=tsa_others)
    elif kind == "xml":
        results = verify_xml(path.read_bytes(), trust_roots=roots, intermediates=intermediates,
                             check_revocation=check_revocation,
                             tsa_trust_roots=tsa_roots, tsa_other_certs=tsa_others)
    else:  # cms / detached .p7s
        orig = Path(original) if original else _detached_original(path)
        if orig is None or not orig.exists():
            raise DetachedOriginalRequiredError(
                "detached .p7s needs its original file (pass original=...)",
                p7s_path=path, expected=orig,
            )
        with orig.open("rb") as data:
            results = [verify_cms(data, read_bounded(path, MAX_CMS_BYTES, "CMS signature"), trust_roots=roots,
                                  intermediates=intermediates, check_revocation=check_revocation,
                                  tsa_trust_roots=tsa_roots, tsa_other_certs=tsa_others)]

    overall = (max((r.indication for r in results), key=lambda ind: _INDICATION_RANK[ind])
               if results else "INDETERMINATE")
    return VerifyReport(indication=overall, signatures=list(results))


def run_doctor(
    *,
    native: bool = True,
    reader: Optional[Union[str, Path]] = None,
    pkcs11_lib: Optional[Union[str, Path]] = None,
) -> DoctorReport:
    """Diagnose the local signing environment and return the checks as data.

    Runs the same probes as the ``doctor`` command (firmauy version, pcscd, the smart-card
    backend and the bundled CA certificates), but prints nothing and never exits. Returns a
    :class:`DoctorReport`; ``report.ok`` is False when any check FAILed. Needs no card or PIN.

    ``native`` defaults to True (the PC/SC reader-and-card path that native signing uses),
    which is what the desktop app relies on; set it False to check the PKCS#11 middleware
    module at ``pkcs11_lib`` instead. ``reader`` selects a PC/SC reader for the native path.
    ``native`` picks the mode: with True, ``pkcs11_lib`` is not used; with False, ``reader``
    is not used.
    """
    from firmauy._shared import _collect_doctor_checks
    from firmauy.constants import DEFAULT_PKCS11_LIB

    lib = str(pkcs11_lib) if pkcs11_lib is not None else DEFAULT_PKCS11_LIB
    raw = _collect_doctor_checks(native, str(reader) if reader is not None else None, lib)
    checks = [
        DoctorCheck(c["status"], c["name"], c.get("detail", ""), c.get("fix"),
                    c.get("sensitive", False))
        for c in raw
    ]
    ok = all(c.status != "FAIL" for c in checks)
    return DoctorReport(ok=ok, checks=checks)


def _resolve_pin_args(pin, pin_provider):
    """Validate that exactly one of ``pin`` / ``pin_provider`` was given (and a direct ``pin`` is
    non-empty). Returns the pair to forward to the signing session."""
    if pin is None and pin_provider is None:
        raise ValueError("provide either pin= or pin_provider=")
    if pin is not None and pin_provider is not None:
        raise ValueError("provide pin= or pin_provider=, not both")
    if pin is not None and not pin:
        raise ValueError("a non-empty PIN is required to sign")
    return pin, pin_provider


def sign_file(
    path: Union[str, Path],
    pin: Optional[str] = None,
    *,
    pin_provider: Optional[Callable[[], str]] = None,
    output: Optional[Union[str, Path]] = None,
    native: bool = True,
    reader: Optional[Union[str, Path]] = None,
    pkcs11_lib: Optional[Union[str, Path]] = None,
    token_label: Optional[str] = None,
    cert_id: Optional[str] = None,
    tsa_url: Optional[str] = None,
    overwrite: bool = False,
    verify: bool = False,
) -> SignReport:
    """Sign ``path`` with the cédula, producing a detached CAdES-BES ``.p7s`` (CMS/PKCS#7).

    This is the programmatic form of ``sign-any``: the original file is left untouched and a
    detached signature is written next to it (``<path>.p7s`` by default, or ``output``). Returns
    a :class:`SignReport`; raises on any error, with the domain conditions typed
    (:class:`IncorrectPinError`, :class:`PinLockedError`, :class:`ReaderNotFoundError`,
    :class:`CardNotFoundError`, :class:`OutputExistsError`, ...) so a caller can branch on them.

    Supply the card's User PIN as ``pin`` (a string, directly) or as ``pin_provider`` (a zero-arg
    callable invoked only when the PIN is actually needed, i.e. after the PIN-free certificate read,
    so a GUI can prompt on demand). Exactly one of the two is required. Either way the PIN is used
    only after that read, so a reader or card problem cannot spend a card retry.

    ``native`` defaults to True (the PC/SC backend the desktop app uses), where ``reader`` picks a
    PC/SC reader. Set it False for a PKCS#11 module: ``pkcs11_lib`` is the module path (the bundled
    middleware by default, or e.g. OpenSC's ``opensc-pkcs11.so``), ``token_label`` picks a token and
    ``cert_id`` (hex) pins the signing certificate. ``tsa_url`` adds an RFC 3161 timestamp. With
    ``verify`` the fresh signature is re-checked for integrity (no trust) before returning.
    """
    from firmauy.signing import (
        _build_timestamper,
        _sign_one_cms,
        _signing_session,
        _verify_after_cms,
    )
    from firmauy.constants import DEFAULT_PKCS11_LIB

    pin, pin_provider = _resolve_pin_args(pin, pin_provider)

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"file to sign not found: {path}")
    out = Path(output) if output else path.with_name(path.name + ".p7s")
    if path.resolve() == out.resolve():
        raise ValueError("input and output are the same file; pass a different output=")

    timestamper = _build_timestamper(
        tsa_url=tsa_url, tsa_user=None, tsa_pass_env=None, tsa_header=None, tsa_header_env=None,
    )

    lib_path = str(pkcs11_lib) if pkcs11_lib is not None else DEFAULT_PKCS11_LIB
    with _signing_session(
        native=native, reader=str(reader) if reader is not None else None,
        pkcs11_lib=lib_path, token_label=token_label, cert_id=cert_id,
        pin=pin, pin_provider=pin_provider,
    ) as ctx:
        _sign_one_cms(
            input_file=path, output_p7s=out, pkcs11_signer=ctx.pyhanko_signer(),
            timestamper=timestamper, overwrite=overwrite,
        )
        signer, issuer, serial = ctx.signer_name, ctx.issuer_name, ctx.cert_serial

    if verify:
        _verify_after_cms(path, out)
    return SignReport(output_path=out, signer=signer, issuer=issuer, kind="cades",
                      backend="native" if native else "pkcs11",
                      certificate_serial=serial, verified=verify,
                      pkcs11_lib=None if native else lib_path)


def sign_pdf(
    path: Union[str, Path],
    pin: Optional[str] = None,
    *,
    pin_provider: Optional[Callable[[], str]] = None,
    output: Optional[Union[str, Path]] = None,
    native: bool = True,
    reader: Optional[Union[str, Path]] = None,
    pkcs11_lib: Optional[Union[str, Path]] = None,
    token_label: Optional[str] = None,
    cert_id: Optional[str] = None,
    reason: Optional[str] = None,
    location: Optional[str] = None,
    tsa_url: Optional[str] = None,
    overwrite: bool = False,
    verify: bool = False,
    appearance: Optional[PdfAppearance] = None,
) -> SignReport:
    """Sign a PDF with the cédula, producing a PAdES-signed PDF (the signature is embedded).

    This is the programmatic form of ``sign-pdf``: unlike :func:`sign_file` (which writes a
    detached ``.p7s``), the signature lives inside the returned PDF, with a visible appearance
    (signer, certificate serial and timestamp) stamped on the last page. The output defaults to
    ``<name>_firmado.pdf`` next to the input. Returns a :class:`SignReport`; raises on any error.

    ``pin`` and the backend selection (``native``/``reader`` or
    ``pkcs11_lib``/``token_label``/``cert_id``) behave as in :func:`sign_file`. ``reason`` and
    ``location`` fill the PAdES signature metadata. ``tsa_url`` adds an RFC 3161 timestamp. With
    ``verify`` the fresh signature is re-checked for integrity and whole-file coverage.
    """
    from pyhanko.sign import signers

    from firmauy.signing import (
        _build_timestamper,
        _check_pdf_size,
        _sign_one_pdf,
        _signing_session,
        _verify_after_pdf,
    )

    pin, pin_provider = _resolve_pin_args(pin, pin_provider)

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"PDF to sign not found: {path}")
    out = Path(output) if output else path.with_stem(path.stem + "_firmado")
    if path.resolve() == out.resolve():
        raise ValueError("input and output are the same file; pass a different output=")
    # Only the refusal reaches an API caller: there is no channel here for the warning.
    _check_pdf_size(path, verify=verify)

    timestamper = _build_timestamper(
        tsa_url=tsa_url, tsa_user=None, tsa_pass_env=None, tsa_header=None, tsa_header_env=None,
    )

    lib_path = str(pkcs11_lib) if pkcs11_lib is not None else DEFAULT_PKCS11_LIB
    with _signing_session(
        native=native, reader=str(reader) if reader is not None else None,
        pkcs11_lib=lib_path, token_label=token_label, cert_id=cert_id,
        pin=pin, pin_provider=pin_provider,
    ) as ctx:
        meta = signers.PdfSignatureMetadata(
            field_name="Sig1", reason=reason, location=location, md_algorithm=None,
        )
        _sign_one_pdf(
            input_pdf=path, output_pdf=out, pkcs11_signer=ctx.pyhanko_signer(),
            signer_name=ctx.signer_name, issuer_name=ctx.issuer_name, cert_serial=ctx.cert_serial,
            timestamper=timestamper, meta=meta,
            field_name="Sig1", force=False, overwrite=overwrite,
            **(appearance or _DEFAULT_APPEARANCE)._pdf_kwargs(),
        )
        signer, issuer, serial = ctx.signer_name, ctx.issuer_name, ctx.cert_serial

    if verify:
        _verify_after_pdf(out)
    return SignReport(output_path=out, signer=signer, issuer=issuer, kind="pades",
                      backend="native" if native else "pkcs11",
                      certificate_serial=serial, verified=verify,
                      pkcs11_lib=None if native else lib_path)


def sign_xml(
    path: Union[str, Path],
    pin: Optional[str] = None,
    *,
    pin_provider: Optional[Callable[[], str]] = None,
    output: Optional[Union[str, Path]] = None,
    native: bool = True,
    reader: Optional[Union[str, Path]] = None,
    pkcs11_lib: Optional[Union[str, Path]] = None,
    token_label: Optional[str] = None,
    cert_id: Optional[str] = None,
    tsa_url: Optional[str] = None,
    overwrite: bool = False,
    verify: bool = False,
) -> SignReport:
    """Sign an XML with the cédula, producing a XAdES-BES signature embedded in the XML.

    This is the programmatic form of ``sign-xml`` (XAdES-T when ``tsa_url`` is given). The output
    defaults to ``<name>_firmado.xml`` next to the input. Returns a :class:`SignReport`; raises on
    any error. ``pin`` and the backend selection behave as in :func:`sign_file`.
    """
    from datetime import datetime
    from zoneinfo import ZoneInfo

    from firmauy.signing import (
        _build_timestamper,
        _sign_one_xml,
        _signing_session,
        _verify_after_xml,
    )
    from firmauy.constants import DEFAULT_PKCS11_LIB, DEFAULT_TIMEZONE

    pin, pin_provider = _resolve_pin_args(pin, pin_provider)

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"XML to sign not found: {path}")
    out = Path(output) if output else path.with_stem(path.stem + "_firmado")
    if path.resolve() == out.resolve():
        raise ValueError("input and output are the same file; pass a different output=")

    timestamper = _build_timestamper(
        tsa_url=tsa_url, tsa_user=None, tsa_pass_env=None, tsa_header=None, tsa_header_env=None,
    )

    lib_path = str(pkcs11_lib) if pkcs11_lib is not None else DEFAULT_PKCS11_LIB
    with _signing_session(
        native=native, reader=str(reader) if reader is not None else None,
        pkcs11_lib=lib_path, token_label=token_label, cert_id=cert_id,
        pin=pin, pin_provider=pin_provider,
    ) as ctx:
        _sign_one_xml(
            input_xml=path, output_xml=out, cert=ctx.cert, signer=ctx.raw_signer(),
            signing_time=datetime.now(ZoneInfo(DEFAULT_TIMEZONE)), overwrite=overwrite,
            timestamper=timestamper,
        )
        signer, issuer, serial = ctx.signer_name, ctx.issuer_name, ctx.cert_serial

    if verify:
        _verify_after_xml(out)
    return SignReport(output_path=out, signer=signer, issuer=issuer, kind="xades",
                      backend="native" if native else "pkcs11",
                      certificate_serial=serial, verified=verify,
                      pkcs11_lib=None if native else lib_path)


def sign(
    path: Union[str, Path],
    pin: Optional[str] = None,
    *,
    pin_provider: Optional[Callable[[], str]] = None,
    sign_as: str = "auto",
    output: Optional[Union[str, Path]] = None,
    native: bool = True,
    reader: Optional[Union[str, Path]] = None,
    pkcs11_lib: Optional[Union[str, Path]] = None,
    token_label: Optional[str] = None,
    cert_id: Optional[str] = None,
    reason: Optional[str] = None,
    location: Optional[str] = None,
    tsa_url: Optional[str] = None,
    overwrite: bool = False,
    verify: bool = False,
    appearance: Optional[PdfAppearance] = None,
) -> SignReport:
    """Sign a file with the cédula, picking the signature type from the content.

    This is the programmatic form of the ``sign`` command and the natural single entry point for a
    GUI: with ``sign_as="auto"`` (default) a PDF is signed as PAdES, an XML as XAdES, and anything
    else as a detached CAdES ``.p7s``. Set ``sign_as`` to ``"pdf"``, ``"xml"`` or ``"cades"`` to
    force a type. ``reason``/``location`` only apply when the resolved type is a PDF. Returns a
    :class:`SignReport`; raises on any error.
    """
    from firmauy.signing import _resolve_sign_kind

    pin, pin_provider = _resolve_pin_args(pin, pin_provider)

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"file to sign not found: {path}")

    kind = _resolve_sign_kind(path, SignAs(sign_as))  # "pdf" | "xml" | "any"
    common = dict(
        output=output, native=native, reader=reader, pkcs11_lib=pkcs11_lib,
        token_label=token_label, cert_id=cert_id, tsa_url=tsa_url,
        overwrite=overwrite, verify=verify,
    )
    if kind == "pdf":
        # reason, location and appearance are the three that only mean something for a PDF, so
        # they travel on this branch alone rather than in `common`.
        return sign_pdf(path, pin, pin_provider=pin_provider, reason=reason, location=location,
                        appearance=appearance, **common)
    if kind == "xml":
        return sign_xml(path, pin, pin_provider=pin_provider, **common)
    return sign_file(path, pin, pin_provider=pin_provider, **common)


def sign_files(
    paths: Iterable[Union[str, Path]],
    pin: Optional[str] = None,
    *,
    pin_provider: Optional[Callable[[], str]] = None,
    sign_as: str = "auto",
    output_dir: Optional[Union[str, Path]] = None,
    native: bool = True,
    reader: Optional[Union[str, Path]] = None,
    pkcs11_lib: Optional[Union[str, Path]] = None,
    token_label: Optional[str] = None,
    cert_id: Optional[str] = None,
    reason: Optional[str] = None,
    location: Optional[str] = None,
    tsa_url: Optional[str] = None,
    overwrite: bool = False,
    verify: bool = False,
    progress: Optional[Callable[[int, Path, Path], None]] = None,
    should_continue: Optional[Callable[[], bool]] = None,
    appearance: Optional[PdfAppearance] = None,
) -> list[SignReport]:
    """Sign several files in a single signing session (one card session, one PIN check for all).

    Each file's type is resolved like :func:`sign`. Signing every file through one
    ``_signing_session`` avoids the N PIN verifications that calling :func:`sign` in a loop would
    cause. ``output_dir`` writes the results there (flat, default name per type) instead of next to
    each input. Returns a list of :class:`SignReport`, one per input, in order.

    ``progress`` is called after each input finishes, including any post-sign verification that
    was asked for, with ``(index, input_path, output_path)``, where ``index`` is 0-based into
    ``paths``. It runs on the calling thread, inside the card session, so it should return quickly
    and must not touch the card.

    Finishing, not merely writing: an output whose self-check failed has been written and does not
    reach the callback, on purpose, for the same reason it is not in ``completed``. It is not
    finished work. The one exception is
    :class:`~firmauy.errors.OutputCommittedError`, where only the final permissions could not be
    set: the signature is committed and the callback runs.

    ``should_continue`` is asked, before each file, whether to keep going; returning False raises
    :class:`BatchSignCancelled` with the same partial result. It is only consulted between files:
    a signature is written whole or not at all, so a long batch stops at the next boundary rather
    than part-way through a document. A batch of one large PDF therefore cannot be interrupted,
    which is the honest answer and the one a caller should show. Like ``progress``, it runs on the
    calling thread inside the card session, so it must return quickly and must not touch the card.

    Fail-fast, but not silently: the first file that fails raises :class:`BatchSignError`, whose
    ``completed`` holds a report per finished output and whose ``failed_index`` and
    ``failed_path`` say where it stopped. Those outputs stay on disk because they are real
    signatures, and a caller that can say "2 of 7 were signed" is worth much more than one that
    can only say it failed. The failed file can itself be in ``completed`` when the failure came
    after its output was finished, and a file left behind by a failed post-sign verification is
    deliberately not: see :class:`~firmauy.errors.BatchSignError` for both.

    .. versionchanged:: 1.11.0
       Added ``should_continue``.

    .. versionchanged:: 1.10.0
       Added ``progress``, and a partial batch now raises :class:`BatchSignError` instead of
       letting the underlying error through with the completed work lost.
    """
    from datetime import datetime
    from zoneinfo import ZoneInfo

    from pyhanko.sign import signers

    from firmauy.signing import (
        _build_timestamper,
        _check_pdf_size,
        _output_path_for,
        _resolve_sign_kind,
        _sign_one_cms,
        _sign_one_pdf,
        _sign_one_xml,
        _signing_session,
        _verify_after_cms,
        _verify_after_pdf,
        _verify_after_xml,
    )

    pin, pin_provider = _resolve_pin_args(pin, pin_provider)
    # Resolved once for the whole batch rather than per file: every PDF in a batch gets the same
    # stamp, and building it here means a bad image path fails before the card is touched instead
    # of part-way through, with some files already signed.
    stamp = (appearance or _DEFAULT_APPEARANCE)._pdf_kwargs()

    items = [Path(p) for p in paths]
    if not items:
        return []
    for p in items:
        if not p.exists():
            raise FileNotFoundError(f"file to sign not found: {p}")
    sa = SignAs(sign_as)
    if verify:
        # A PDF past what verify_pdf reads would be signed and then fail its own check, so it is
        # refused here, before the PIN. A file whose type cannot be detected is left to the loop
        # below, which reports it where it always has.
        for p in items:
            try:
                is_pdf = _resolve_sign_kind(p, sa) == "pdf"
            except Exception:
                continue
            if is_pdf:
                _check_pdf_size(p, verify=True)
    out_dir = Path(output_dir) if output_dir is not None else None
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)

    timestamper = _build_timestamper(
        tsa_url=tsa_url, tsa_user=None, tsa_pass_env=None, tsa_header=None, tsa_header_env=None,
    )

    reports: list[SignReport] = []
    lib_path = str(pkcs11_lib) if pkcs11_lib is not None else DEFAULT_PKCS11_LIB
    with _signing_session(
        native=native, reader=str(reader) if reader is not None else None,
        pkcs11_lib=lib_path, token_label=token_label, cert_id=cert_id,
        pin=pin, pin_provider=pin_provider,
    ) as ctx:
        def _report(out, kind, *, verified):
            return SignReport(
                output_path=out, signer=ctx.signer_name, issuer=ctx.issuer_name,
                kind={"pdf": "pades", "xml": "xades", "any": "cades"}[kind],
                backend="native" if native else "pkcs11",
                certificate_serial=ctx.cert_serial, verified=verified,
                pkcs11_lib=None if native else lib_path,
            )

        def _announce(index, source, out):
            """Run the caller's progress callback. Returns what it raised, rather than letting
            that replace this function's own account of what it did.

            `progress` is the caller's code and can have bugs in it. When it does, whatever it
            raised used to come out of here in place of everything else: the reports for files
            already on disk, and, worse, the OutputCommittedError saying a file exists and must
            not be signed a second time. A broken progress bar is not a reason to lose that.
            """
            if progress is None:
                return None
            try:
                progress(index, source, out)
            except Exception as callback_error:
                return callback_error
            return None

        for index, p in enumerate(items):
            # Asked between files, never inside one: an output is written whole or not at all,
            # so there is no point where stopping could leave a truncated signature behind.
            try:
                stop = should_continue is not None and not should_continue()
            except Exception as callback_error:
                # Same rule as `progress`: a callback that raises does not cost the caller the
                # record of what was already signed.
                raise BatchSignError(
                    f"batch stopped before {p} (file {index + 1} of {len(items)}): the "
                    f"should_continue callback raised {callback_error!r}",
                    completed=reports, failed_index=index, failed_path=p,
                    callback_error=callback_error,
                ) from callback_error
            if stop:
                raise BatchSignCancelled(
                    f"batch cancelled before {p} (file {index + 1} of {len(items)}); "
                    f"{len(reports)} already signed",
                    completed=reports, stopped_before=index,
                )
            try:
                kind = _resolve_sign_kind(p, sa)
                out = _output_path_for(p, kind, out_dir)
                if kind == "pdf":
                    meta = signers.PdfSignatureMetadata(
                        field_name="Sig1", reason=reason, location=location, md_algorithm=None,
                    )
                    _sign_one_pdf(
                        input_pdf=p, output_pdf=out, pkcs11_signer=ctx.pyhanko_signer(),
                        signer_name=ctx.signer_name, issuer_name=ctx.issuer_name,
                        cert_serial=ctx.cert_serial, timestamper=timestamper, meta=meta,
                        field_name="Sig1", force=False, overwrite=overwrite,
                        **stamp,
                    )
                    if verify:
                        _verify_after_pdf(out)
                elif kind == "xml":
                    _sign_one_xml(
                        input_xml=p, output_xml=out, cert=ctx.cert, signer=ctx.raw_signer(),
                        signing_time=datetime.now(ZoneInfo(DEFAULT_TIMEZONE)),
                        overwrite=overwrite, timestamper=timestamper,
                    )
                    if verify:
                        _verify_after_xml(out)
                else:
                    _sign_one_cms(
                        input_file=p, output_p7s=out, pkcs11_signer=ctx.pyhanko_signer(),
                        timestamper=timestamper, overwrite=overwrite,
                    )
                    if verify:
                        _verify_after_cms(p, out)
            except Exception as exc:
                # Everything already written is a real signature. Hand it over rather than let it
                # vanish with the exception: the caller needs it to say what actually happened.
                #
                # OutputCommittedError means this file is written too, only with the wrong mode,
                # so it belongs in the list for exactly the same reason. Leaving it out reported
                # that the file did not exist while it sat on disk complete, which is the one
                # thing `completed` promises not to do. The exception stays the cause, so `path`
                # and `final_mode` remain available to whoever repairs the mode. `verified` is
                # False on that last report whatever `verify` asked for, because the failure
                # happens inside the signing call and the verification step never runs.
                callback_error = None
                if isinstance(exc, OutputCommittedError):
                    reports.append(_report(out, kind, verified=False))
                    # `progress` is documented as running after each output is written, and this
                    # output is written. Skipping it left a progress bar showing nothing done
                    # while the file existed and `completed` already counted it.
                    callback_error = _announce(index, p, out)
                raise BatchSignError(
                    f"batch stopped at {p} (file {index + 1} of {len(items)}): {exc}",
                    completed=reports, failed_index=index, failed_path=p,
                    callback_error=callback_error,
                ) from exc

            reports.append(_report(out, kind, verified=verify))
            callback_error = _announce(index, p, out)
            if callback_error is not None:
                raise BatchSignError(
                    f"batch stopped after {p} (file {index + 1} of {len(items)}): the progress "
                    f"callback raised {callback_error!r}. The signature itself was written.",
                    completed=reports, failed_index=index, failed_path=p,
                    callback_error=callback_error,
                ) from callback_error
    return reports


def output_path_for(
    path: Union[str, Path],
    *,
    sign_as: str = "auto",
    output_dir: Optional[Union[str, Path]] = None,
) -> Path:
    """Where :func:`sign` and :func:`sign_files` would write the signature for ``path``.

    An embedded signature (PDF, XML) keeps the input's extension and gets ``_firmado`` on the
    stem; a detached one appends ``.p7s`` to the whole name, so ``data.bin`` becomes
    ``data.bin.p7s``. With ``output_dir`` the result goes there, flat.

    This exists so a caller can warn about an existing output *before* asking for the PIN,
    without reimplementing a rule that would then drift from where the file actually lands. With
    the default ``sign_as="auto"`` the file is read to detect its type, so it must exist; pass an
    explicit type to ask about a file that is not there yet.

    .. versionadded:: 1.10.0
    """
    from firmauy.signing import _output_path_for, _resolve_sign_kind

    p = Path(path)
    kind = _resolve_sign_kind(p, SignAs(sign_as))
    return _output_path_for(p, kind, Path(output_dir) if output_dir is not None else None)


# ---------------------------------------------------------------------------
# Utilities: cédula-number validation and national CA certificates (no card)
# ---------------------------------------------------------------------------


def validate_ci(text: str) -> CiReport:
    """Validate a complete cédula number by its check digit (arithmetic consistency only).

    This is NOT an identity or document check: it only verifies the number's check digit is
    internally consistent, catching typos and malformed numbers. Needs no card. Raises
    ``ValueError`` if ``text`` is not a usable cédula string (non-digits, empty, or wrong length).
    """
    from firmauy.ci import validate_ci as _validate_ci

    return CiReport(**_validate_ci(text))


def complete_ci(body: str) -> str:
    """Return the full cédula number for a body without its check digit (appends the check digit).

    Needs no card. Raises ``ValueError`` if ``body`` is malformed or longer than 7 digits.
    """
    from firmauy.ci import complete_ci as _complete_ci

    return _complete_ci(body)


def fetch_cas(
    *,
    source_files: Optional[list[Union[str, Path]]] = None,
    progress: Optional[Callable[[str], None]] = None,
) -> CaBundle:
    """Refresh the national CA certificates (AGESIC root + Ministerio del Interior intermediate).

    Downloads each certificate, pins it by fingerprint, caches it per-user and returns the paths.
    Verification already works offline with the bundled anchors, so this is optional (it just
    refreshes the cache). ``source_files`` seeds certificates from local PEM/DER files instead of the
    network (the fingerprint pin makes the origin irrelevant). ``progress`` receives human-readable
    status lines. Raises on a fingerprint mismatch.
    """
    from firmauy.national_ca import cache_dir
    from firmauy.national_ca import fetch_cas as _fetch_cas

    root_path, intermediate_path = _fetch_cas(
        progress=progress,
        source_files=[str(f) for f in source_files] if source_files else None,
    )
    return CaBundle(root_path=root_path, intermediate_path=intermediate_path, cache_dir=cache_dir())


# ---------------------------------------------------------------------------
# Reading the cédula (PC/SC, no PIN)
# ---------------------------------------------------------------------------


def fetch_identity(*, reader: Optional[Union[str, Path]] = None) -> IdentityReport:
    """Read the cédula's biographic data over PC/SC (names, dates, number, MRZ). Needs no PIN.

    Returns an :class:`IdentityReport`; fields the card does not carry are ``None``. Do not call this
    while a PKCS#11 signing session is open on the same card (both go through pcscd and can conflict).
    Raises if no reader or card is available. It does blocking card I/O, so run it off the UI thread.
    """
    from firmauy.card_reader import card_to_json_obj, open_reader, read_card

    conn = open_reader(str(reader) if reader is not None else None)
    try:
        obj = card_to_json_obj(read_card(conn))
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass
    return IdentityReport(**obj)


def fetch_photo(*, reader: Optional[Union[str, Path]] = None) -> PhotoReport:
    """Read the cardholder's photo (JPEG) over PC/SC. Needs no PIN.

    Returns a :class:`PhotoReport` with the raw JPEG in ``data``. Same reader and session caveats as
    :func:`fetch_identity`. Raises if no reader or card is available, or the card carries no photo.
    """
    from firmauy.card_reader import open_reader, photo_to_json_obj
    from firmauy.card_reader import read_photo as _read_photo

    conn = open_reader(str(reader) if reader is not None else None)
    try:
        photo = _read_photo(conn)
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass
    meta = photo_to_json_obj(photo)
    return PhotoReport(
        data=photo, format=meta["format"], mime=meta["mime"],
        width=meta.get("width"), height=meta.get("height"),
        size_bytes=meta["bytes"], sha256=meta["sha256"],
    )


# ---------------------------------------------------------------------------
# Introspection: readers, tokens and certificates (no PIN unless the token asks)
# ---------------------------------------------------------------------------


def list_readers() -> list[str]:
    """List the available PC/SC readers by name. Needs no card or PIN.

    The returned names are exactly what the ``reader=`` argument of the signing and reading
    functions accepts. Raises if the smart-card stack (pcscd) is unavailable.
    """
    from firmauy.card_reader import list_readers as _list_readers

    return [str(r) for r in _list_readers()]


def list_tokens(*, pkcs11_lib: Optional[Union[str, Path]] = None) -> list[TokenInfo]:
    """List the PKCS#11 tokens the module exposes. Needs no PIN.

    ``pkcs11_lib`` is the module path (the bundled middleware by default). Raises if the module
    cannot be loaded.
    """
    from firmauy.constants import DEFAULT_PKCS11_LIB
    from firmauy.pkcs11_utils import load_pkcs11_lib, token_to_dict

    lib = load_pkcs11_lib(str(pkcs11_lib) if pkcs11_lib is not None else DEFAULT_PKCS11_LIB)
    return [TokenInfo(**token_to_dict(t)) for t in lib.get_tokens()]


def list_certs(
    *,
    pkcs11_lib: Optional[Union[str, Path]] = None,
    token_label: Optional[str] = None,
    cert_id: Optional[str] = None,
    pin: Optional[str] = None,
    include_pem: bool = False,
) -> list[CertInfo]:
    """List the certificates on a PKCS#11 token. Needs no PIN unless the token requires a login.

    ``token_label`` picks a token (auto-detected when only one is present). ``cert_id`` (hex) keeps
    only the matching certificate. ``pin`` logs in when the token hides its certificates behind one
    (most cédula tokens do not). ``include_pem`` adds the PEM to each result. Returns a list of
    :class:`CertInfo`.
    """
    import pkcs11
    from cryptography import x509

    from firmauy.cert_utils import _cert_record
    from firmauy.constants import DEFAULT_PKCS11_LIB
    from firmauy.pkcs11_utils import find_token, iter_cert_objects, load_pkcs11_lib

    lib = load_pkcs11_lib(str(pkcs11_lib) if pkcs11_lib is not None else DEFAULT_PKCS11_LIB)
    token = find_token(lib, token_label)
    wanted = cert_id.lower().replace(":", "").replace(" ", "") if cert_id else None

    out: list[CertInfo] = []
    with token.open(user_pin=pin) as session:
        for cert_obj in iter_cert_objects(session):
            try:
                obj_id = cert_obj[pkcs11.Attribute.ID].hex()
                cert = x509.load_der_x509_certificate(cert_obj[pkcs11.Attribute.VALUE])
            except Exception:
                continue
            if wanted is not None and obj_id.lower() != wanted:
                continue
            out.append(CertInfo(**_cert_record(obj_id, cert, include_pem=include_pem)))
    return out
