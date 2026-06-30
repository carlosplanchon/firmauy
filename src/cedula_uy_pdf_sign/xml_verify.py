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
from cryptography.hazmat.primitives.serialization import Encoding
from lxml import etree

from cedula_uy_pdf_sign.cert_utils import name_fields
from cedula_uy_pdf_sign.verify_common import Check, VerifyResult
from cedula_uy_pdf_sign.xml_sign import (
    SIGNED_PROPS_TYPE,
    _c14n,
    _compute_enveloped_digest,
    _ds,
    _sha256_b64,
    _xades,
)


def _leaf_cert(root) -> tuple:
    el = root.find(f".//{_ds('X509Certificate')}")
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

    from asn1crypto import x509 as asn1x509
    from pyhanko_certvalidator import CertificateValidator, ValidationContext

    def to_asn1(c):
        return asn1x509.Certificate.load(c.public_bytes(Encoding.DER))

    vc = ValidationContext(
        trust_roots=[to_asn1(r) for r in roots],
        other_certs=[to_asn1(c) for c in intermediates],
        allow_fetching=check_revocation,
        revocation_mode="hard-fail" if check_revocation else "soft-fail",
        moment=at_time,
    )
    validator = CertificateValidator(
        to_asn1(leaf),
        intermediate_certs=[to_asn1(c) for c in intermediates],
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


# The XAdES-T timestamp check only proves the RFC 3161 token *binds* to this signature; it does
# NOT validate the TSA's certificate (no trusted timestamping list exists for the Uruguayan
# cédula, and the token is an unsigned property anyway). The name and detail say so explicitly,
# so a passing check is never mistaken for trusted, verified time.
TS_CHECK_NAME = "signature timestamp present (XAdES-T, TSA not trust-validated)"


def _verify_timestamp(sig) -> Optional[Check]:
    """If a XAdES-T <SignatureTimeStamp> is present, check that its RFC 3161 token binds to the
    signature: its messageImprint must equal the digest of the canonicalized <ds:SignatureValue>.
    Returns None for a plain XAdES-BES signature (no timestamp).

    This confirms the timestamp covers *this* signature; it does NOT validate the TSA's own
    certificate chain. So the genTime is only what the (unverified) TSA asserts: an attacker who
    can alter the file can substitute a token from any TSA with an arbitrary genTime and still pass
    this check. The check name and detail flag that explicitly; trusted time would require
    validating the token against a trusted TSA (a future --tsa-ca)."""
    from asn1crypto import cms as asn1cms

    ets = sig.find(f".//{_xades('SignatureTimeStamp')}/{_xades('EncapsulatedTimeStamp')}")
    if ets is None or not ets.text:
        return None
    try:
        token_der = base64.b64decode(re.sub(r"\s+", "", ets.text))
        tst_info = asn1cms.ContentInfo.load(token_der)["content"]["encap_content_info"]["content"].parsed
        mi = tst_info["message_imprint"]
        algo = mi["hash_algorithm"]["algorithm"].native
        sv = sig.find(_ds("SignatureValue"))
        expected = hashlib.new(algo, _c14n(sv)).digest()
        gen_time = tst_info["gen_time"].native
    except Exception as exc:
        return Check(TS_CHECK_NAME, False, f"could not parse timestamp: {str(exc)[:80]}")
    if mi["hashed_message"].native == expected:
        return Check(TS_CHECK_NAME, True,
                     f"genTime {gen_time.isoformat()} (asserted by the TSA, not verified)")
    return Check(TS_CHECK_NAME, False, "timestamp does not match the signature value")


def verify_xml(
    xml_bytes: bytes,
    *,
    trust_roots: Optional[list] = None,
    intermediates: Optional[list] = None,
    at_time: Optional[datetime] = None,
    check_revocation: bool = False,
) -> VerifyResult:
    """Verify a XAdES-BES enveloped signature. If `trust_roots` is given, also
    validate the certificate chain (level 2); with `check_revocation=True` it also
    checks CRL/OCSP (level 3, needs network). Otherwise only integrity (level 1)."""
    checks: list = []
    root = etree.fromstring(xml_bytes)
    sig = root.find(_ds("Signature"))
    if sig is None:
        return VerifyResult("INVALID", [Check("signature present", False, "no <ds:Signature>")])

    si = sig.find(_ds("SignedInfo"))
    sv_el = sig.find(_ds("SignatureValue"))
    if si is None or sv_el is None or not (sv_el.text or "").strip():
        missing = "SignedInfo" if si is None else "SignatureValue"
        return VerifyResult("INVALID", [Check("signature structure", False, f"malformed: no <ds:{missing}>")])
    refs = si.findall(_ds("Reference"))
    try:
        cert, cert_der = _leaf_cert(root)
    except ValueError as exc:
        return VerifyResult("INVALID", [Check("signing certificate", False, str(exc))])

    ref_doc = next((r for r in refs if (r.get("URI") or "") == "" and r.get("Type") is None), None)
    ref_props = next((r for r in refs if r.get("Type") == SIGNED_PROPS_TYPE), None)

    # 1. document (enveloped) reference digest
    if ref_doc is not None:
        got = _compute_enveloped_digest(root, sig)
        stated = (ref_doc.find(_ds("DigestValue")).text or "").strip()
        checks.append(Check("document digest (reference)", got == stated))
    else:
        checks.append(Check("document digest (reference)", False, "no enveloped reference"))

    # 2. SignedProperties reference digest
    sp = sig.find(f"{_ds('Object')}/{_xades('QualifyingProperties')}/{_xades('SignedProperties')}")
    if ref_props is not None and sp is not None:
        got = _sha256_b64(_c14n(sp))
        stated = (ref_props.find(_ds("DigestValue")).text or "").strip()
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

    ts_check = _verify_timestamp(sig)   # None for plain XAdES-BES
    if ts_check is not None:
        checks.append(ts_check)
    timestamp_ok = ts_check is None or ts_check.ok

    # Level 2: certificate chain
    trusted = False
    if level1_ok and trust_roots:
        at = at_time or datetime.now(timezone.utc)
        ok, detail = _verify_chain(cert, intermediates or [], trust_roots, at, check_revocation)
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
