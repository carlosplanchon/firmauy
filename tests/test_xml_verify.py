"""Robustness of verify_xml against malformed / adversarial XAdES structures.

A verifier is routinely handed untrusted input, so a structurally broken signature must produce
a clean INVALID indication, never an uncaught internal exception (e.g. AttributeError)."""

from cedula_uy_pdf_sign.xml_verify import verify_xml

DS = "xmlns:ds='http://www.w3.org/2000/09/xmldsig#'"


def _invalid(xml: bytes):
    result = verify_xml(xml, trust_roots=None)
    assert result.indication == "INVALID", [(c.name, c.detail) for c in result.checks]
    return result


def test_no_signature_is_invalid():
    _invalid(b"<?xml version='1.0'?><root/>")


def test_signature_without_signedinfo_is_invalid_not_crash():
    # Previously raised AttributeError: 'NoneType' object has no attribute 'findall'.
    _invalid(f"<root><ds:Signature {DS}></ds:Signature></root>".encode())


def test_signature_without_signaturevalue_is_invalid():
    _invalid(
        f"<root><ds:Signature {DS}><ds:SignedInfo></ds:SignedInfo>"
        f"</ds:Signature></root>".encode()
    )


def test_signature_with_empty_signaturevalue_is_invalid():
    _invalid(
        f"<root><ds:Signature {DS}><ds:SignedInfo></ds:SignedInfo>"
        f"<ds:SignatureValue>   </ds:SignatureValue></ds:Signature></root>".encode()
    )


def test_signature_without_certificate_is_invalid():
    _invalid(
        f"<root><ds:Signature {DS}><ds:SignedInfo></ds:SignedInfo>"
        f"<ds:SignatureValue>QUJD</ds:SignatureValue></ds:Signature></root>".encode()
    )


def test_missing_signing_certificate_binding_is_flagged():
    # A XAdES signature lacking the SigningCertificate binding must not pass it silently (#7):
    # the check is present and failed.
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509.oid import NameOID
    from lxml import etree

    from cedula_uy_pdf_sign.xml_sign import _xades, sign_xml

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "X")])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365)).sign(key, hashes.SHA256())
    )
    signed = sign_xml(
        b"<?xml version='1.0'?><r><d>x</d></r>", cert=cert,
        signer=lambda d: key.sign(d, padding.PKCS1v15(), hashes.SHA256()), signing_time=now,
    )
    root = etree.fromstring(signed)
    sc = root.find(f".//{_xades('SigningCertificate')}")
    sc.getparent().remove(sc)

    result = verify_xml(etree.tostring(root), trust_roots=None)
    binding = next((c for c in result.checks if "SigningCertificate binding" in c.name), None)
    assert binding is not None and not binding.ok   # flagged, not silently skipped
    assert result.indication == "INVALID"
