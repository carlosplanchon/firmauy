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
import re
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from lxml import etree

from firmauy.cert_utils import name_fields, to_asn1_cert, to_asn1_certs
from firmauy.verify_common import (
    CHAIN_CHECK,
    Check,
    TimestampInfo,
    VerifyResult,
    evaluate_timestamp,
    note_trusted_time,
)
from firmauy.xml_sign import (
    MAX_XML_BYTES,
    SIGNED_PROPS_TYPE,
    _c14n,
    _compute_enveloped_digest,
    _ds,
    _secure_parser,
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
    """Verify a XAdES-T <SignatureTimeStamp>, returning ``(Check, trusted_time, TimestampInfo)``;
    None when the signature carries no timestamp.

    The token's SignedData is validated either way (its own signature, and the messageImprint
    against the digest of the canonicalized <ds:SignatureValue>). What ``--tsa-ca`` adds is the
    chain: with anchors the TSA certificate is validated against them, with the timeStamping EKU,
    at the genTime. On success the genTime counts as trusted time and comes back as
    ``trusted_time``, so the caller can evaluate the signing certificate at that moment
    (validation at the sealed time, not the AdES -LT/-LTA levels).

    Without anchors ``trusted_time`` is None and the genTime is only what an unvalidated TSA
    asserts: whoever could alter the file could substitute a token from any TSA carrying any
    genTime and still pass the binding. Saying so is what TS_CHECK_NAME is for.
    """
    from asn1crypto import cms as asn1cms

    ets = sig.find(f".//{_xades('SignatureTimeStamp')}/{_xades('EncapsulatedTimeStamp')}")
    if ets is None or not ets.text:
        return None

    name = TS_CHECK_NAME_TRUSTED if tsa_trust_roots else TS_CHECK_NAME
    sv = sig.find(_ds("SignatureValue"))
    try:
        token_der = base64.b64decode(re.sub(r"\s+", "", ets.text))
        signed_data = asn1cms.ContentInfo.load(token_der)["content"]
        tst_info = signed_data["encap_content_info"]["content"].parsed
        gen_time = tst_info["gen_time"].native
    except Exception as exc:
        detail = f"could not parse timestamp: {str(exc)[:80]}"
        # No gen_time: a token this broken never got to state one. trusted stays None because
        # nothing was ever put to the anchors, which is true whether or not anchors were given.
        return (Check(name, False, detail), None,
                TimestampInfo(present=True, intact=False, valid=False, detail=detail))

    # The shared judgement, so all three formats answer this the same way and in the same words.
    # What differs here is only what the messageImprint covers: the canonicalized
    # <ds:SignatureValue> element, where PDF and CMS use the raw signature bytes.
    info, check, trusted_time = evaluate_timestamp(
        signed_data, gen_time, _c14n(sv),
        present_name=TS_CHECK_NAME, trusted_name=TS_CHECK_NAME_TRUSTED,
        tsa_trust_roots=tsa_trust_roots, tsa_other_certs=tsa_other_certs,
    )
    return check, trusted_time, info


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
    (validation at the sealed time, not the AdES -LT/-LTA levels)."""
    if len(xml_bytes) > MAX_XML_BYTES:
        raise ValueError(
            f"XML input exceeds the {MAX_XML_BYTES} byte limit; refusing to parse it"
        )
    root = etree.fromstring(xml_bytes, parser=_secure_parser())
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
    computed over `root` with `sig` removed and every other signature left in place, which is the
    enveloped transform as XMLDSig 6.6.4 defines it, and every other check is scoped to `sig`, so
    a multi-signature document verifies each independently. A later enveloped signature covers
    the earlier ones, so one appended to a signed document leaves the earlier digest no longer
    matching: that is the specification's verdict, and `sign_xml` refuses to produce such a file."""
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
        got = _compute_enveloped_digest(root, sig)
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
    timestamp = None
    if ts_result is not None:
        # The same structure the PDF and CMS verifiers return, so a consumer can read one field
        # instead of knowing which format it is holding and which check names that format uses.
        ts_check, trusted_time, timestamp = ts_result
        checks.append(ts_check)
        timestamp_ok = ts_check.ok
    else:
        timestamp_ok = True

    # Level 2: certificate chain. With a trust-validated timestamp (--tsa-ca) the signing
    # certificate is evaluated at the trusted genTime, else at at_time/now. That is validation at
    # the sealed time and not the AdES -LT/-LTA levels: no historical revocation evidence.
    trusted = False
    if level1_ok and trust_roots:
        at = trusted_time or at_time or datetime.now(timezone.utc)
        ok, detail = _verify_chain(cert, intermediates or [], trust_roots, at, check_revocation)
        checks.append(Check(CHAIN_CHECK, ok, detail))
        note_trusted_time(checks, trusted_time)
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
        timestamp=timestamp,
    )
