# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""PAdES / PDF signature verification, wrapping pyHanko's validator.

Tiered like the XML verifier:
- Level 1: signature integrity (intact + cryptographically valid).
- Level 2: certificate chain to a trusted root (RFC 5280, via pyhanko_certvalidator).
- Level 3 (`check_revocation=True`): CRL/OCSP. Needs network.

Beyond the XML case, a PDF signature also has a *coverage* level: whether it covers
the whole file or content was added afterwards. That is surfaced and factored in.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

from firmauy.cert_utils import name_fields, to_asn1_certs
from firmauy.verify_common import Check, VerifyResult, muted_path_building_warnings


def _map_status(status, trust_evaluated: bool) -> VerifyResult:
    intact = bool(getattr(status, "intact", False))
    valid = bool(getattr(status, "valid", False))
    trusted = bool(getattr(status, "trusted", False))
    coverage = getattr(status, "coverage", None)
    cov_name = coverage.name if coverage is not None else "UNKNOWN"
    cov_ok = cov_name == "ENTIRE_FILE"

    checks = [
        Check("signature intact (covered bytes unmodified)", intact),
        Check("signature cryptographically valid", valid),
        Check("coverage (whole file)", cov_ok, cov_name),
    ]
    if trust_evaluated:
        checks.append(Check("certificate chain to trusted root", trusted,
                            "" if trusted else "not trusted"))

    cert = getattr(status, "signing_cert", None)
    if cert is not None:
        signer = {**name_fields(cert.subject), "certificate_serial": format(cert.serial_number, "X")}
        issuer = name_fields(cert.issuer)
    else:
        signer, issuer = {}, {}

    if not (intact and valid):
        indication = "INVALID"
    elif not cov_ok:
        indication = "INDETERMINATE"   # valid, but does not cover the whole file
    elif trust_evaluated:
        indication = "VALID" if trusted else "INDETERMINATE"
    else:
        indication = "INDETERMINATE"   # integrity OK, trust not evaluated

    return VerifyResult(indication, checks, signer, issuer, trusted)


def verify_pdf(
    pdf_path,
    *,
    trust_roots: Optional[list] = None,
    intermediates: Optional[list] = None,
    at_time: Optional[datetime] = None,
    check_revocation: bool = False,
) -> list:
    """Verify every signature in a PDF. Returns a list of VerifyResult (one per
    signature). With `trust_roots`, also validates the chain (level 2); with
    `check_revocation=True`, also CRL/OCSP (level 3)."""
    at = at_time or datetime.now(timezone.utc)
    if trust_roots:
        vc = ValidationContext(
            trust_roots=to_asn1_certs(trust_roots),
            other_certs=to_asn1_certs(intermediates),
            allow_fetching=check_revocation,
            revocation_mode="hard-fail" if check_revocation else "soft-fail",
            moment=at,
        )
    else:
        vc = ValidationContext(allow_fetching=False, revocation_mode="soft-fail", moment=at)

    results = []
    with open(Path(pdf_path), "rb") as f:
        reader = PdfFileReader(f)
        hybrid = reader.xrefs.hybrid_xrefs_present
        if hybrid:
            # pyHanko refuses to validate hybrid cross-reference PDFs in strict mode, but such a
            # signature can still be valid (these are accepted by the official AGESIC validator, and
            # firmauy can produce them with `sign --allow-hybrid-xref`). Re-open non-strict so we can
            # actually check it; normal (non-hybrid) PDFs stay strict.
            f.seek(0)
            reader = PdfFileReader(f, strict=False)
        sigs = list(reader.embedded_signatures)
        if not sigs:
            return [VerifyResult("INVALID", [Check("signature present", False, "no signatures in PDF")])]
        with muted_path_building_warnings():
            for emb in sigs:
                status = validate_pdf_signature(emb, vc)
                result = _map_status(status, bool(trust_roots))
                if hybrid:
                    result.checks.append(Check(
                        "hybrid cross-reference sections: validated in relaxed mode", True,
                        "pyHanko rejects these in strict mode; the signature itself is unaffected",
                    ))
                results.append(result)
    return results
