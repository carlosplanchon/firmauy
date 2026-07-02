# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Standards-based XAdES-BES verification (the verify side of `xml_sign`).

Tiered, mirroring the DSS indication model:

- **Level 1** (offline, always): signature integrity (SignedInfo signature + each
  Reference digest) plus the XAdES SigningCertificate binding.
- **Level 2** (offline, default): certificate chain to a trusted root + validity dates.

Revocation (CRL/OCSP) is out of scope for this prototype (level 3, future).

C14N and digest helpers are imported from `xml_sign` on purpose: verification MUST
canonicalize exactly like signing, so there is a single source of truth.
"""

import base64
import hashlib
import re
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from lxml import etree

from firmauy.cert_utils import name_fields, to_asn1_cert, to_asn1_certs
from firmauy.verify_common import Check, VerifyResult, muted_path_building_warnings
from firmauy.xml_sign import (
    SIGNED_PROPS_TYPE,
    _c14n,
    _compute_enveloped_digest,
    _ds,
    _sha256_b64,
    _xades,
)


def _leaf_cert(sig) -> tuple:
    """Load the leaf certificate from a single <ds:Signature>'s KeyInfo. Scoped to `sig` (not the
    whole document) so each signature in a multi-signature document uses its own certificate."""
    el = sig.find(f".//{_ds('X509Certificate')}")
    if el is None or not el.text:
        raise ValueError("no X509Certificate in KeyInfo")
    der = base64.b64decode(re.sub(r"\s+", "", el.text))
    return x509.load_der_x509_certificate(der), der


def _verify_chain(leaf, intermediates, roots, at_time, check_revocation=False) -> tuple[bool, str]:
    """Full RFC 5280 path validation via pyhanko_certvalidator.

    Validates the chain to a trusted root (signatures, validity, basicConstraints,
    keyUsage, name chaining, etc.).

    - Level 2 (default): no revocation (`allow_fetching=False`, `soft-fail`).
    - Level 3 (`check_revocation=True`): fetch CRL/OCSP and `hard-fail` (revoked or
      unavailable revocation info fails the chain). Requires network.
    """
    import asyncio

    from pyhanko_certvalidator import CertificateValidator, ValidationContext

    vc = ValidationContext(
        trust_roots=to_asn1_certs(roots),
        other_certs=to_asn1_certs(intermediates),
        allow_fetching=check_revocation,
        revocation_mode="hard-fail" if check_revocation else "soft-fail",
        moment=at_time,
    )
    validator = CertificateValidator(
        to_asn1_cert(leaf),
        intermediate_certs=to_asn1_certs(intermediates),
        validation_context=vc,
    )
    try:
        asyncio.run(validator.async_validate_path())
        detail = "RFC 5280 path validated to trusted root"
        if check_revocation:
            detail += " (revocation checked: not revoked)"
        return True, detail
    except Exception as exc:
        return False, f"{type(exc).__name__}: {str(exc)[:120]}"


# Check name when no --tsa-ca was given: the token *binds* to this signature, but the TSA's own
# certificate is NOT validated, so the genTime is only what the (unverified) TSA asserts. The name
# and detail say so explicitly, so a passing check is never mistaken for trusted, verified time.
TS_CHECK_NAME = "signature timestamp present (XAdES-T, TSA not trust-validated)"
# Check name when --tsa-ca was given and the RFC 3161 token validated against it: trusted time.
TS_CHECK_NAME_TRUSTED = "signature timestamp (XAdES-T, TSA chain validated)"


def _verify_timestamp(sig, tsa_trust_roots=None, tsa_other_certs=None) -> Optional[tuple]:
    """Verify a XAdES-T <SignatureTimeStamp>, returning ``(Check, trusted_time)``; None when the
    signature carries no timestamp.

    Always checks that the RFC 3161 token *binds* to this signature (its messageImprint equals the
    digest of the canonicalized <ds:SignatureValue>).

    Without ``tsa_trust_roots`` the TSA certificate is NOT validated, so the genTime is only what
    the (unverified) TSA asserts and ``trusted_time`` is None: an attacker able to alter the file
    could substitute a token from any TSA with an arbitrary genTime and still pass the binding.

    With ``tsa_trust_roots`` (from --tsa-ca) the token's SignedData is fully validated via pyHanko
    (token signature + messageImprint + TSA chain with the timeStamping EKU). On success the genTime
    is trusted and returned as ``trusted_time``, so the caller can evaluate the signing certificate
    at that time (long-term validation)."""
    from asn1crypto import cms as asn1cms

    ets = sig.find(f".//{_xades('SignatureTimeStamp')}/{_xades('EncapsulatedTimeStamp')}")
    if ets is None or not ets.text:
        return None

    sv = sig.find(_ds("SignatureValue"))
    try:
        token_der = base64.b64decode(re.sub(r"\s+", "", ets.text))
        signed_data = asn1cms.ContentInfo.load(token_der)["content"]
        tst_info = signed_data["encap_content_info"]["content"].parsed
        mi = tst_info["message_imprint"]
        algo = mi["hash_algorithm"]["algorithm"].native
        expected = hashlib.new(algo, _c14n(sv)).digest()
        gen_time = tst_info["gen_time"].native
    except Exception as exc:
        return Check(TS_CHECK_NAME, False, f"could not parse timestamp: {str(exc)[:80]}"), None

    if tsa_trust_roots:
        return _validate_tsa_token(signed_data, sv, gen_time, tsa_trust_roots, tsa_other_certs)

    # No --tsa-ca: binding only, and honest that the TSA was not validated.
    if mi["hashed_message"].native == expected:
        return Check(TS_CHECK_NAME, True,
                     f"genTime {gen_time.isoformat()} (asserted by the TSA, not verified)"), None
    return Check(TS_CHECK_NAME, False, "timestamp does not match the signature value"), None


def _validate_tsa_token(signed_data, sv, gen_time, tsa_trust_roots, tsa_other_certs) -> tuple:
    """Validate an RFC 3161 token against the --tsa-ca anchors via pyHanko's
    ``validate_tst_signed_data`` (token signature + messageImprint + TSA chain). Returns
    ``(Check, trusted_time)``; ``trusted_time`` is the genTime only when fully trusted."""
    import asyncio

    from pyhanko.sign.validation.generic_cms import validate_tst_signed_data
    from pyhanko.sign.validation.status import TimestampSignatureStatus
    from pyhanko_certvalidator import ValidationContext

    def imprint(hash_algo: str) -> bytes:
        return hashlib.new(hash_algo, _c14n(sv)).digest()

    try:
        vc = ValidationContext(
            trust_roots=to_asn1_certs(tsa_trust_roots),
            other_certs=to_asn1_certs(tsa_other_certs),
            allow_fetching=False,
            revocation_mode="soft-fail",
            moment=gen_time,   # validate the TSA certificate at the time it claims to have signed
        )
        with muted_path_building_warnings():
            kwargs = asyncio.run(validate_tst_signed_data(signed_data, vc, imprint))
        status = TimestampSignatureStatus(**kwargs)
    except Exception as exc:
        return Check(TS_CHECK_NAME_TRUSTED, False, f"TSA validation error: {str(exc)[:80]}"), None

    if status.intact and status.valid and status.trusted:
        return Check(TS_CHECK_NAME_TRUSTED, True, f"genTime {gen_time.isoformat()} (trusted)"), gen_time
    if not status.intact:
        reason = "timestamp does not match the signature value"
    elif not status.valid:
        reason = "timestamp token signature is invalid"
    else:
        reason = "TSA certificate does not chain to the --tsa-ca anchor(s)"
    return Check(TS_CHECK_NAME_TRUSTED, False, reason), None


def verify_xml(
    xml_bytes: bytes,
    *,
    trust_roots: Optional[list] = None,
    intermediates: Optional[list] = None,
    at_time: Optional[datetime] = None,
    check_revocation: bool = False,
    tsa_trust_roots: Optional[list] = None,
    tsa_other_certs: Optional[list] = None,
) -> list[VerifyResult]:
    """Verify every <ds:Signature> in a XAdES-BES/-T document, returning one VerifyResult per
    signature (like verify_pdf) -- or a single INVALID result if the document carries none. The
    caller aggregates them (worst indication wins).

    If `trust_roots` is given, each signature's certificate chain is also validated (level 2); with
    `check_revocation=True` it also checks CRL/OCSP (level 3, needs network). Otherwise only
    integrity (level 1). With `tsa_trust_roots` (from --tsa-ca) a XAdES-T timestamp's TSA is
    validated; on success the signing certificate is evaluated at the trusted genTime instead of now
    (long-term validation)."""
    root = etree.fromstring(xml_bytes)
    sigs = root.findall(_ds("Signature"))
    if not sigs:
        return [VerifyResult("INVALID", [Check("signature present", False, "no <ds:Signature>")])]
    return [
        _verify_signature(
            root, sig, trust_roots=trust_roots, intermediates=intermediates, at_time=at_time,
            check_revocation=check_revocation, tsa_trust_roots=tsa_trust_roots,
            tsa_other_certs=tsa_other_certs,
        )
        for sig in sigs
    ]


def _verify_signature(
    root,
    sig,
    *,
    trust_roots: Optional[list] = None,
    intermediates: Optional[list] = None,
    at_time: Optional[datetime] = None,
    check_revocation: bool = False,
    tsa_trust_roots: Optional[list] = None,
    tsa_other_certs: Optional[list] = None,
) -> VerifyResult:
    """Verify one already-located <ds:Signature> element. The document-level enveloped digest is
    computed over `root` (all signatures stripped, per this tool's enveloped convention), while
    every other check is scoped to `sig`, so a multi-signature document verifies each independently."""
    checks: list = []

    si = sig.find(_ds("SignedInfo"))
    sv_el = sig.find(_ds("SignatureValue"))
    if si is None or sv_el is None or not (sv_el.text or "").strip():
        missing = "SignedInfo" if si is None else "SignatureValue"
        return VerifyResult("INVALID", [Check("signature structure", False, f"malformed: no <ds:{missing}>")])
    refs = si.findall(_ds("Reference"))
    try:
        cert, cert_der = _leaf_cert(sig)
    except ValueError as exc:
        return VerifyResult("INVALID", [Check("signing certificate", False, str(exc))])

    ref_doc = next((r for r in refs if (r.get("URI") or "") == "" and r.get("Type") is None), None)
    ref_props = next((r for r in refs if r.get("Type") == SIGNED_PROPS_TYPE), None)

    # 1. document (enveloped) reference digest. A Reference is only well-formed with a
    # <ds:DigestValue> child; a malformed one (present but empty) is a failed check, never an
    # uncaught AttributeError -- verify_xml is routinely handed untrusted input.
    dv_doc = ref_doc.find(_ds("DigestValue")) if ref_doc is not None else None
    if ref_doc is not None and dv_doc is not None:
        got = _compute_enveloped_digest(root)
        stated = (dv_doc.text or "").strip()
        checks.append(Check("document digest (reference)", got == stated))
    else:
        detail = "no enveloped reference" if ref_doc is None else "reference has no DigestValue"
        checks.append(Check("document digest (reference)", False, detail))

    # 2. SignedProperties reference digest (same null-safety as the enveloped reference above).
    sp = sig.find(f"{_ds('Object')}/{_xades('QualifyingProperties')}/{_xades('SignedProperties')}")
    dv_props = ref_props.find(_ds("DigestValue")) if ref_props is not None else None
    if ref_props is not None and sp is not None and dv_props is not None:
        got = _sha256_b64(_c14n(sp))
        stated = (dv_props.text or "").strip()
        checks.append(Check("signed-properties digest", got == stated))
    else:
        checks.append(Check("signed-properties digest", False, "missing SignedProperties reference"))

    # 3. SignedInfo signature (RSA-SHA256). The b64decode is inside the try so a malformed
    # SignatureValue is a failed check (INVALID), not an uncaught exception.
    try:
        sigval = base64.b64decode(re.sub(r"\s+", "", sv_el.text))
        cert.public_key().verify(sigval, _c14n(si), padding.PKCS1v15(), hashes.SHA256())
        checks.append(Check("SignedInfo signature (RSA-SHA256)", True))
    except Exception as exc:
        checks.append(Check("SignedInfo signature (RSA-SHA256)", False, str(exc)[:80]))

    # 4. XAdES SigningCertificate binding (CertDigest == sha256(cert)). Required by XAdES-BES, so a
    # missing binding is a failed check, not silently skipped: without it the signed properties do
    # not commit to *which* certificate signed, weakening the cert-to-signature binding.
    cd = sig.find(f".//{_xades('CertDigest')}/{_ds('DigestValue')}")
    if cd is not None:
        ok = (cd.text or "").strip() == _sha256_b64(cert_der)
        checks.append(Check("SigningCertificate binding", ok))
    else:
        checks.append(Check("SigningCertificate binding", False,
                            "missing (no XAdES SigningCertificate)"))

    # Core integrity (the checks above) decides INVALID. The XAdES-T timestamp is an *unsigned*
    # property, so a problem with it must never make the core signature INVALID nor block chain
    # validation; at worst it holds the result at INDETERMINATE.
    level1_ok = all(c.ok for c in checks)

    ts_result = _verify_timestamp(sig, tsa_trust_roots, tsa_other_certs)   # None for plain XAdES-BES
    trusted_time = None
    if ts_result is not None:
        ts_check, trusted_time = ts_result
        checks.append(ts_check)
        timestamp_ok = ts_check.ok
    else:
        timestamp_ok = True

    # Level 2: certificate chain. With a trust-validated timestamp (--tsa-ca) the signing
    # certificate is evaluated at the trusted genTime (long-term validation), else at at_time/now.
    trusted = False
    if level1_ok and trust_roots:
        at = trusted_time or at_time or datetime.now(timezone.utc)
        ok, detail = _verify_chain(cert, intermediates or [], trust_roots, at, check_revocation)
        if ok and trusted_time is not None:
            detail = f"{detail}; evaluated at trusted genTime {trusted_time.isoformat()}"
        checks.append(Check("certificate chain to trusted root", ok, detail))
        trusted = ok

    if not level1_ok:
        indication = "INVALID"
    elif not timestamp_ok:
        indication = "INDETERMINATE"  # signature intact, but the timestamp does not check out
    elif trust_roots:
        indication = "VALID" if trusted else "INDETERMINATE"
    else:
        indication = "INDETERMINATE"  # integrity OK, trust not evaluated

    return VerifyResult(
        indication=indication,
        checks=checks,
        signer={**name_fields(cert.subject), "certificate_serial": format(cert.serial_number, "X")},
        issuer=name_fields(cert.issuer),
        trusted=trusted,
    )
