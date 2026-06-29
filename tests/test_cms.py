"""Unit tests for detached CAdES/.p7s signing & verification (cms_sign / cms_verify).

These run without a token: they sign with an in-memory RSA key via pyHanko's
SimpleSigner and verify through the same code path the CLI uses.
"""

import datetime

import pytest
from asn1crypto import cms as asn1cms
from asn1crypto import keys as asn1keys
from asn1crypto import x509 as asn1x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pyhanko.sign.signers import SimpleSigner
from pyhanko_certvalidator.registry import SimpleCertificateStore

from cedula_uy_pdf_sign.cms_sign import sign_cms_detached
from cedula_uy_pdf_sign.cms_verify import verify_cms


def _key_and_cert() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "PEREZ PEREZ JUAN"),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, "DNI00000000"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)  # self-signed: usable as its own trust root
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=True, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _simple_signer(key, cert) -> SimpleSigner:
    der = cert.public_bytes(serialization.Encoding.DER)
    return SimpleSigner(
        signing_cert=asn1x509.Certificate.load(der),
        signing_key=asn1keys.PrivateKeyInfo.load(key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())),
        cert_registry=SimpleCertificateStore(),
    )


def test_sign_cms_produces_detached_cades_bes():
    key, cert = _key_and_cert()
    data = b"any custom binary file\x00\x01\x02"

    p7s = sign_cms_detached(data, signer=_simple_signer(key, cert))

    ci = asn1cms.ContentInfo.load(p7s)
    assert ci["content_type"].native == "signed_data"
    sd = ci["content"]

    # Detached: the content is not encapsulated in the signature.
    assert sd["encap_content_info"]["content"].native is None

    # CAdES-BES marker: signing-certificate-v2 signed attribute, plus messageDigest.
    signer_info = sd["signer_infos"][0]
    attr_types = {a["type"].native for a in signer_info["signed_attrs"]}
    assert "signing_certificate_v2" in attr_types
    assert "message_digest" in attr_types


def test_verify_cms_integrity_trust_and_tamper():
    key, cert = _key_and_cert()
    data = b"firma este archivo\n"
    p7s = sign_cms_detached(data, signer=_simple_signer(key, cert))

    # Integrity holds; without trust anchors the chain is not evaluated -> INDETERMINATE.
    res = verify_cms(data, p7s, trust_roots=None)
    assert res.indication == "INDETERMINATE"
    assert all(c.ok for c in res.checks), [(c.name, c.detail) for c in res.checks if not c.ok]

    # With the (self-signed) cert as trust root -> VALID.
    res_t = verify_cms(data, p7s, trust_roots=[cert])
    assert res_t.indication == "VALID"
    assert res_t.trusted

    # Tampering the signed bytes breaks integrity -> INVALID.
    res_bad = verify_cms(data + b"X", p7s, trust_roots=None)
    assert res_bad.indication == "INVALID"


def test_verify_cms_rejects_non_cms_input():
    with pytest.raises(ValueError):
        verify_cms(b"data", b"this is not a CMS structure at all")
