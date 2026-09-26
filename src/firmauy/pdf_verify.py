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
from firmauy.verify_common import (
    CHAIN_CHECK,
    Check,
    VerifyResult,
    muted_path_building_warnings,
    no_trust_context,
    note_refused_fetches,
    note_trusted_time,
    revocation_fetcher_backend,
    timestamp_of,
)

MAX_PDF_BYTES = 128 * 1024 * 1024



def _map_status(status, trust_evaluated: bool, info=None, ts_check=None) -> VerifyResult:
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
        checks.append(Check(CHAIN_CHECK, trusted, "" if trusted else "not trusted"))

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
    elif ts_check is not None and not ts_check.ok:
        # A timestamp is an unsigned attribute, so a bad one never makes the signature INVALID.
        # It does hold the result at INDETERMINATE, which is what the XAdES path has always done:
        # saying VALID with a row underneath admitting the token is broken is a mixed message,
        # and the word is the part somebody remembers.
        indication = "INDETERMINATE"
    elif trust_evaluated:
        indication = "VALID" if trusted else "INDETERMINATE"
    else:
        indication = "INDETERMINATE"   # integrity OK, trust not evaluated

    if ts_check is not None:
        checks.append(ts_check)

    return VerifyResult(indication, checks, signer, issuer, trusted, info)



def _tsa_context(tsa_trust_roots, tsa_other_certs, at):
    """A validation context for the timestamp alone, or None when no anchors were given.

    Deliberately separate from the signer's. ``trust_roots`` decides who is accepted as having
    *signed* the document, so folding a TSA's root into it to make a timestamp validate would
    quietly widen that, which is a security change and not a convenience. pyHanko takes the two
    contexts as separate arguments for this reason.

    ``at`` is the token's own genTime, supplied by the caller, and not the verification time. A
    TSA responder certificate is short-lived by design and the documents it stamps are not, so
    judging it now means every timestamp turns untrusted the day that certificate expires, which
    is the one thing a timestamp exists to prevent. This is what XAdES already did; PAdES and
    CAdES judged at ``at_time`` until 1.12.1, so the same token flipped from trusted to untrusted
    with nothing about the file having changed.

    Optimistic without an archive timestamp, and knowingly so: a genTime is self-asserted, so
    strictly this needs proof the token existed before the certificate expired, which only a
    later timestamp can give (the AdES -LTA level, out of scope here). The exposure is a TSA key
    compromised after expiry, which is a smaller problem than every -T signature decaying on a
    schedule.
    """
    if not tsa_trust_roots:
        return None
    return ValidationContext(
        trust_roots=to_asn1_certs(tsa_trust_roots),
        other_certs=to_asn1_certs(tsa_other_certs),
        allow_fetching=False,
        revocation_mode="soft-fail",
        moment=at,
    )


def verify_pdf(
    pdf_path,
    *,
    trust_roots: Optional[list] = None,
    intermediates: Optional[list] = None,
    at_time: Optional[datetime] = None,
    check_revocation: bool = False,
    tsa_trust_roots: Optional[list] = None,
    tsa_other_certs: Optional[list] = None,
    allow_private_network: bool = False,
) -> list:
    """Verify every signature in a PDF. Returns a list of VerifyResult (one per
    signature). With `trust_roots`, also validates the chain (level 2); with
    `check_revocation=True`, also CRL/OCSP (level 3), fetched under the outbound policy
    (:mod:`firmauy.outbound`), which ``allow_private_network`` relaxes for internal mirrors.

    ``tsa_trust_roots`` validates an RFC 3161 signature timestamp's own chain. Without it the
    timestamp is reported as present and unvalidated rather than as trusted or as broken. With it,
    a token that fully validates also fixes *when* the signing certificate is evaluated: at the
    trusted genTime rather than now, so a signature does not stop verifying the day the signer's
    certificate expires. That is the whole purpose of a timestamp, and until 1.13.0 only the XAdES
    verifier honoured it."""
    pdf_path = Path(pdf_path)
    if pdf_path.stat().st_size > MAX_PDF_BYTES:
        raise ValueError(f"PDF exceeds the {MAX_PDF_BYTES} byte limit; refusing to parse it")
    at = at_time or datetime.now(timezone.utc)

    def signer_context(moment, backend):
        if not trust_roots:
            return no_trust_context(moment)
        return ValidationContext(
            trust_roots=to_asn1_certs(trust_roots),
            other_certs=to_asn1_certs(intermediates),
            allow_fetching=check_revocation,
            revocation_mode="hard-fail" if check_revocation else "soft-fail",
            fetcher_backend=backend,
            moment=moment,
        )

    results = []
    with open(pdf_path, "rb") as f:
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
                # Per signature, not once for the file: each carries its own token and its own
                # genTime, and a PDF signed twice months apart would otherwise have the second
                # signature's certificates judged at the first one's moment.
                info, ts_check, trusted_time = timestamp_of(
                    emb.signer_info, tsa_trust_roots, tsa_other_certs)
                ts_vc = _tsa_context(tsa_trust_roots, tsa_other_certs,
                                     (info.gen_time if info else None) or at)
                # Only a *trusted* token moves the moment. An untrusted genTime is a claim by a
                # stranger, and letting it choose the day the signing certificate is checked on
                # would hand that choice to whoever could alter the file.
                # One backend per signature: its own fetch budget, its own record of refusals.
                backend = (revocation_fetcher_backend(check_revocation, allow_private_network)
                           if trust_roots else None)
                status = validate_pdf_signature(emb, signer_context(trusted_time or at, backend),
                                                ts_vc)
                result = _map_status(status, bool(trust_roots), info, ts_check)
                note_trusted_time(result.checks, trusted_time)
                note_refused_fetches(result.checks, backend)
                if hybrid:
                    result.checks.append(Check(
                        "hybrid cross-reference sections: validated in relaxed mode", True,
                        "pyHanko rejects these in strict mode; the signature itself is unaffected",
                    ))
                results.append(result)
    return results
