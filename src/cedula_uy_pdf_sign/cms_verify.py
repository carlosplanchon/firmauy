# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""CAdES / detached CMS (.p7s) verification — the verify side of ``cms_sign``.

Tiered like the XML/PDF verifiers:

- **Level 1** (offline, always): signature integrity — the signed bytes hash to the
  embedded ``messageDigest`` and the signature is cryptographically valid.
- **Level 2** (offline, default): certificate chain to a trusted root (RFC 5280).
- **Level 3** (``check_revocation=True``): CRL/OCSP. Needs network.

A detached CMS signature has no PDF-style *coverage* notion: it signs exactly the
bytes it is verified against, so integrity already implies full coverage.
"""

import asyncio
import logging
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import IO, Optional, Union

from asn1crypto import cms as asn1cms
from asn1crypto import x509 as asn1x509
from cryptography.hazmat.primitives.serialization import Encoding
from pyhanko.sign.validation import async_validate_detached_cms
from pyhanko_certvalidator import ValidationContext

from cedula_uy_pdf_sign.verify_common import Check, VerifyResult

# pyHanko logs a full traceback at WARNING when it cannot build a trust path. That is
# an *expected* outcome here — no trust anchors (--no-trust / no cached CAs) or a chain
# that does not reach a trusted root — which we already surface cleanly as
# INDETERMINATE through the checks below. Keep that traceback out of the terminal.
_PYHANKO_PATH_LOGGER = "pyhanko.sign.validation.generic_cms"


@contextmanager
def _muted_path_building_warnings():
    logger = logging.getLogger(_PYHANKO_PATH_LOGGER)
    prev_level = logger.level
    logger.setLevel(logging.ERROR)
    try:
        yield
    finally:
        logger.setLevel(prev_level)


def _to_asn1(certs):
    return [asn1x509.Certificate.load(c.public_bytes(Encoding.DER)) for c in (certs or [])]


def _load_signed_data(p7s_bytes: bytes) -> asn1cms.SignedData:
    """Parse a DER-encoded ``.p7s`` into its CMS SignedData. Raises ValueError if it
    is not a CMS SignedData structure."""
    try:
        ci = asn1cms.ContentInfo.load(p7s_bytes)
        content_type = ci["content_type"].native
    except Exception as exc:
        raise ValueError(f"not a valid CMS/.p7s structure: {exc}") from exc
    if content_type != "signed_data":
        raise ValueError(f"not a CMS SignedData (.p7s): content type is '{content_type}'")
    return ci["content"]


def _map_status(status, trust_evaluated: bool) -> VerifyResult:
    intact = bool(getattr(status, "intact", False))
    valid = bool(getattr(status, "valid", False))
    trusted = bool(getattr(status, "trusted", False))

    checks = [
        Check("signature intact (signed bytes unmodified)", intact),
        Check("signature cryptographically valid", valid),
    ]
    if trust_evaluated:
        checks.append(Check("certificate chain to trusted root", trusted,
                            "" if trusted else "not trusted"))

    cert = getattr(status, "signing_cert", None)
    signer = cert.subject.human_friendly if cert is not None else ""
    issuer = cert.issuer.human_friendly if cert is not None else ""

    if not (intact and valid):
        indication = "INVALID"
    elif trust_evaluated:
        indication = "VALID" if trusted else "INDETERMINATE"
    else:
        indication = "INDETERMINATE"   # integrity OK, trust not evaluated

    return VerifyResult(indication, checks, signer, issuer, trusted)


def verify_cms(
    input_data: Union[bytes, IO],
    p7s_bytes: bytes,
    *,
    trust_roots: Optional[list] = None,
    intermediates: Optional[list] = None,
    at_time: Optional[datetime] = None,
    check_revocation: bool = False,
) -> VerifyResult:
    """Verify a detached CAdES/.p7s signature (``p7s_bytes``) over ``input_data``.

    With ``trust_roots`` it also validates the certificate chain (level 2); with
    ``check_revocation=True`` it also checks CRL/OCSP (level 3, needs network).
    Otherwise only integrity is checked (level 1)."""
    signed_data = _load_signed_data(p7s_bytes)
    at = at_time or datetime.now(timezone.utc)

    vc = None
    if trust_roots:
        vc = ValidationContext(
            trust_roots=_to_asn1(trust_roots),
            other_certs=_to_asn1(intermediates),
            allow_fetching=check_revocation,
            revocation_mode="hard-fail" if check_revocation else "soft-fail",
            moment=at,
        )

    with _muted_path_building_warnings():
        status = asyncio.run(
            async_validate_detached_cms(input_data, signed_data, signer_validation_context=vc)
        )
    return _map_status(status, bool(trust_roots))
