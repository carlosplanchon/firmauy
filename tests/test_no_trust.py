# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Verifying without trust anchors judges nothing against the operating system's trust store.

pyhanko-certvalidator reads a missing ``trust_roots`` as the operating system's trust store, a
fallback it deprecated in 0.32 and will stop honouring. The PDF and CMS verifiers left it missing
where no trust is evaluated (--no-trust, and the check after signing), so a signer whose chain
reached a root the system trusts came back ``trusted``. Here the signer's own self-signed
certificate stands in for such a root, and the store records whether it was asked at all.
"""

import datetime
import io

import pytest
from asn1crypto import keys as asn1keys
from asn1crypto import x509 as asn1x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.writer import PageObject, PdfFileWriter
from pyhanko.sign.signers import PdfSignatureMetadata, SimpleSigner, sign_pdf
from pyhanko_certvalidator import registry
from pyhanko_certvalidator.registry import SimpleCertificateStore

from firmauy.cms_sign import sign_cms_detached
from firmauy.cms_verify import verify_cms
from firmauy.pdf_verify import verify_pdf

DATA = b"contenido a firmar"


def _self_signed():
    """A signing certificate that is its own root, with the key usage pyHanko asks of a signer."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PEREZ JUAN")])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=True, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, asn1x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))


def _signer(key, cert) -> SimpleSigner:
    return SimpleSigner(
        signing_cert=cert,
        signing_key=asn1keys.PrivateKeyInfo.load(key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())),
        cert_registry=SimpleCertificateStore(),
    )


def _blank_pdf() -> io.BytesIO:
    writer = PdfFileWriter()
    box = generic.ArrayObject([generic.NumberObject(n) for n in (0, 0, 200, 200)])
    contents = writer.add_object(generic.StreamObject(stream_data=b""))
    writer.insert_page(PageObject(contents=contents, media_box=box))
    base = io.BytesIO()
    writer.write(base)
    base.seek(0)
    return base


def _verify_without_anchors(kind, key, cert, tmp_path):
    if kind == "cms":
        p7s = sign_cms_detached(io.BytesIO(DATA), signer=_signer(key, cert))
        return verify_cms(io.BytesIO(DATA), p7s)
    out = io.BytesIO()
    sign_pdf(IncrementalPdfFileWriter(_blank_pdf()), PdfSignatureMetadata(field_name="Sig1"),
             signer=_signer(key, cert), output=out)
    path = tmp_path / "firmado.pdf"
    path.write_bytes(out.getvalue())
    return verify_pdf(path)[0]


@pytest.fixture
def system_store(monkeypatch):
    """Stands in for the operating system's trust store. It answers with the certificates a test
    puts in it, and records every time it is asked."""
    roots, asked = [], []

    def trust_roots():
        asked.append(True)
        return list(roots)

    monkeypatch.setattr(registry, "_system_trust_roots", trust_roots)
    return roots, asked


@pytest.mark.parametrize("kind", ["pdf", "cms"])
def test_without_anchors_a_signer_the_system_trusts_is_not_reported_as_trusted(
        system_store, tmp_path, kind):
    roots, asked = system_store
    key, cert = _self_signed()
    roots.append(cert)

    result = _verify_without_anchors(kind, key, cert, tmp_path)

    assert result.indication == "INDETERMINATE"
    assert result.trusted is False
    assert asked == [], "the operating system's trust store was consulted"
