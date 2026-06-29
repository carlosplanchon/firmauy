"""XAdES-T (signature timestamp) unit tests.

Sign with a software key + a pyHanko DummyTimeStamper (no real TSA, no smart card), then verify
that the SignatureTimeStamp is present and binds to the SignatureValue. Tampering the timestamp
must fail the dedicated check (and only that check, since it lives in UnsignedProperties)."""

import datetime

from asn1crypto import keys as a_keys
from asn1crypto import x509 as a_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pyhanko.sign.timestamps import DummyTimeStamper
from pyhanko_certvalidator.registry import SimpleCertificateStore

from cedula_uy_pdf_sign.xml_sign import sign_xml
from cedula_uy_pdf_sign.xml_verify import verify_xml

XML = b"<?xml version='1.0'?><root><data>hola</data></root>"
TS_CHECK = "signature timestamp (XAdES-T)"


def _self_signed(cn, *, timestamping=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
    )
    if timestamping:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=False)
    return key, builder.sign(key, hashes.SHA256())


def _dummy_timestamper():
    key, cert = _self_signed("Test TSA", timestamping=True)
    a_cert = a_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))
    a_key = a_keys.PrivateKeyInfo.load(key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return DummyTimeStamper(a_cert, a_key, certs_to_embed=SimpleCertificateStore())


def _sign(timestamper=None):
    key, cert = _self_signed("PEREZ JUAN")
    raw_signer = lambda data: key.sign(data, padding.PKCS1v15(), hashes.SHA256())  # noqa: E731
    now = datetime.datetime.now(datetime.timezone.utc)
    return sign_xml(XML, cert=cert, signer=raw_signer, signing_time=now, timestamper=timestamper)


def _check(result, name):
    return next((c for c in result.checks if c.name == name), None)


def test_xades_t_timestamp_present_and_verifies():
    signed = _sign(timestamper=_dummy_timestamper())
    assert b"SignatureTimeStamp" in signed

    result = verify_xml(signed, trust_roots=None)
    ts = _check(result, TS_CHECK)
    assert ts is not None and ts.ok
    assert "genTime" in ts.detail
    # integrity (incl. the timestamp binding) holds; no trust roots -> INDETERMINATE
    assert result.indication == "INDETERMINATE"


def test_xades_bes_has_no_timestamp_check():
    signed = _sign(timestamper=None)  # plain XAdES-BES
    assert b"SignatureTimeStamp" not in signed

    result = verify_xml(signed, trust_roots=None)
    assert _check(result, TS_CHECK) is None
    assert result.indication == "INDETERMINATE"


def test_tampered_timestamp_fails_only_the_timestamp_check():
    signed = _sign(timestamper=_dummy_timestamper())

    # Flip one base64 char inside the EncapsulatedTimeStamp (not covered by the main signature).
    pos = signed.index(b"EncapsulatedTimeStamp>") + len(b"EncapsulatedTimeStamp>") + 6
    data = bytearray(signed)
    data[pos] = ord("B") if data[pos] != ord("B") else ord("A")
    tampered = bytes(data)

    result = verify_xml(tampered, trust_roots=None)
    ts = _check(result, TS_CHECK)
    assert ts is not None and not ts.ok
    assert result.indication == "INVALID"
    # The main signature checks are untouched (timestamp is in UnsignedProperties).
    assert _check(result, "SignedInfo signature (RSA-SHA256)").ok
