"""Robustness of verify_xml against malformed / adversarial XAdES structures.

A verifier is routinely handed untrusted input, so a structurally broken signature must produce
a clean INVALID indication, never an uncaught internal exception (e.g. AttributeError)."""

import base64

import pytest
from cryptography.hazmat.primitives.serialization import Encoding

from firmauy.xml_sign import MAX_XML_BYTES
from firmauy.xml_verify import verify_xml

DS = "xmlns:ds='http://www.w3.org/2000/09/xmldsig#'"
XADES = "xmlns:xades='http://uri.etsi.org/01903/v1.3.2#'"
SPROPS_TYPE = "http://uri.etsi.org/01903#SignedProperties"
SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"


def _invalid(xml: bytes):
    # verify_xml returns one result per signature; these fixtures carry zero or one, so [0] is the
    # (worst and only) result.
    result = verify_xml(xml, trust_roots=None)[0]
    assert result.indication == "INVALID", [(c.name, c.detail) for c in result.checks]
    return result


def _cert_b64(cert) -> str:
    """Base64 DER of a real certificate, so the malformed docs get past _leaf_cert and reach the
    Reference-digest checks (the point under test)."""
    return base64.b64encode(cert.public_bytes(Encoding.DER)).decode()


def test_no_signature_is_invalid():
    _invalid(b"<?xml version='1.0'?><root/>")


def test_oversized_xml_is_rejected_before_parsing():
    xml = b"<root>" + b"x" * MAX_XML_BYTES + b"</root>"

    with pytest.raises(ValueError, match="exceeds the .* byte limit"):
        verify_xml(xml, trust_roots=None)


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

    from firmauy.xml_sign import _xades, sign_xml

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

    result = verify_xml(etree.tostring(root), trust_roots=None)[0]
    binding = next((c for c in result.checks if "SigningCertificate binding" in c.name), None)
    assert binding is not None and not binding.ok   # flagged, not silently skipped
    assert result.indication == "INVALID"


def test_document_reference_without_digestvalue_is_invalid_not_crash(cert_valid):
    # A <ds:Reference URI=""> present but missing its <ds:DigestValue> child previously raised
    # AttributeError: 'NoneType' object has no attribute 'text'. It must be a clean INVALID.
    b64 = _cert_b64(cert_valid)
    xml = (
        f"<root {DS}><ds:Signature><ds:SignedInfo>"
        f"<ds:Reference URI=''><ds:DigestMethod Algorithm='{SHA256}'/></ds:Reference>"
        f"</ds:SignedInfo><ds:SignatureValue>QUJD</ds:SignatureValue>"
        f"<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{b64}</ds:X509Certificate>"
        f"</ds:X509Data></ds:KeyInfo></ds:Signature></root>"
    ).encode()
    result = _invalid(xml)
    doc = next((c for c in result.checks if c.name == "document digest (reference)"), None)
    assert doc is not None and not doc.ok and doc.detail == "reference has no DigestValue"


def test_signedprops_reference_without_digestvalue_is_invalid_not_crash(cert_valid):
    # Same missing-DigestValue class, on the SignedProperties reference (the other .find(...).text).
    b64 = _cert_b64(cert_valid)
    xml = (
        f"<root {DS} {XADES}><ds:Signature><ds:SignedInfo>"
        f"<ds:Reference Type='{SPROPS_TYPE}' URI='#sp1'>"
        f"<ds:DigestMethod Algorithm='{SHA256}'/></ds:Reference>"
        f"</ds:SignedInfo><ds:SignatureValue>QUJD</ds:SignatureValue>"
        f"<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{b64}</ds:X509Certificate>"
        f"</ds:X509Data></ds:KeyInfo>"
        f"<ds:Object><xades:QualifyingProperties><xades:SignedProperties Id='sp1'/>"
        f"</xades:QualifyingProperties></ds:Object></ds:Signature></root>"
    ).encode()
    result = _invalid(xml)   # must not raise
    sp = next((c for c in result.checks if c.name == "signed-properties digest"), None)
    assert sp is not None and not sp.ok


# --- multiple signatures: one result per <ds:Signature> (parity with verify_pdf) --------------

def _throwaway_signer(cn: str):
    """A self-signed certificate whose CN is `cn`, a callable that signs with its key, and now."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365)).sign(key, hashes.SHA256())
    )
    return cert, (lambda d: key.sign(d, padding.PKCS1v15(), hashes.SHA256())), now


def _sign_with_cn(xml_bytes: bytes, cn: str) -> bytes:
    """Sign `xml_bytes` (enveloped XAdES) with a throwaway self-signed cert whose CN is `cn`."""
    from firmauy.xml_sign import sign_xml

    cert, signer, now = _throwaway_signer(cn)
    return sign_xml(xml_bytes, cert=cert, signer=signer, signing_time=now)


def _countersign_with_cn(signed_xml: bytes, cn: str) -> bytes:
    """Append a second enveloped signature the way the specification describes it: over the
    document as it now is, first signature included. `sign_xml` refuses to build this file, for
    the reason the tests below show, so this reaches past it to the builder."""
    from lxml import etree

    from firmauy.xml_sign import _secure_parser, _sign_root

    cert, signer, now = _throwaway_signer(cn)
    root = etree.fromstring(signed_xml, parser=_secure_parser())
    return _sign_root(root, cert=cert, signer=signer, signing_time=now)


def test_each_root_level_signature_gets_its_own_result_and_signer():
    # verify_xml returns one result per <ds:Signature>, like verify_pdf, each with its own signer:
    # the leaf certificate is read per signature, not once from the whole document.
    once = _sign_with_cn(b"<?xml version='1.0'?><r><d>x</d></r>", "SIGNER ONE")
    twice = _countersign_with_cn(once, "SIGNER TWO")

    results = verify_xml(twice, trust_roots=None)
    assert [r.signer["common_name"] for r in results] == ["SIGNER ONE", "SIGNER TWO"]


def test_a_second_enveloped_signature_covers_the_first_and_says_so():
    """XMLDSig 6.6.4: the enveloped transform removes the Signature that contains the reference
    and nothing else. The second signature's digest is therefore over the document with the first
    one still in it, and matches. The first one's digest was computed before the second existed,
    and no longer matches. That is the verdict every validator following the specification gives,
    and the reason sign_xml refuses to produce this file. Every digest used to be computed with
    all signatures removed, which made this document verify here and nowhere else."""
    once = _sign_with_cn(b"<?xml version='1.0'?><r><d>x</d></r>", "SIGNER ONE")
    twice = _countersign_with_cn(once, "SIGNER TWO")

    first, second = verify_xml(twice, trust_roots=None)

    assert second.indication == "INDETERMINATE"      # intact, trust not checked
    assert all(c.ok for c in second.checks), [(c.name, c.detail) for c in second.checks if not c.ok]

    assert first.indication == "INVALID"
    failed = [c.name for c in first.checks if not c.ok]
    assert failed == ["document digest (reference)"]   # a good signature over a document that changed


def test_a_broken_second_signature_is_reported_with_its_own_reason():
    # Both signatures surface, each with the checks that failed on it: the CLI's worst-indication
    # aggregation can only flag what the verifier reports.
    from lxml import etree

    from firmauy.xml_sign import _ds

    once = _sign_with_cn(b"<?xml version='1.0'?><r><d>x</d></r>", "SIGNER ONE")
    twice = _countersign_with_cn(once, "SIGNER TWO")

    root = etree.fromstring(twice)
    second_sv = root.findall(_ds("Signature"))[1].find(_ds("SignatureValue"))
    t = (second_sv.text or "").strip()
    second_sv.text = ("B" if t[0] != "B" else "A") + t[1:]   # flip one b64 char -> bad signature

    first, second = verify_xml(etree.tostring(root), trust_roots=None)
    assert [c.name for c in first.checks if not c.ok] == ["document digest (reference)"]
    assert [c.name for c in second.checks if not c.ok] == ["SignedInfo signature (RSA-SHA256)"]


def test_the_enveloped_transform_keeps_the_text_after_the_signature():
    """A pretty-printed document has a newline between </ds:Signature> and the closing root tag.
    That newline is a text node of the root, not of the signature, and a validator following the
    specification digests it. lxml's remove() takes an element's tail along with it, which
    computed a digest no other validator would."""
    from lxml import etree

    from firmauy.xml_sign import _c14n, _compute_enveloped_digest, _ds, _sha256_b64

    root = etree.fromstring(
        b"<r><d>x</d><ds:Signature xmlns:ds='http://www.w3.org/2000/09/xmldsig#'/>\n</r>")
    sig = root.find(_ds("Signature"))

    expected = _sha256_b64(_c14n(etree.fromstring(b"<r><d>x</d>\n</r>")))
    assert _compute_enveloped_digest(root, sig) == expected
