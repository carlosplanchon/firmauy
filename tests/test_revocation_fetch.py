# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""--check-revocation fetches through the proxy the environment names, and nothing fetches without it.

pyhanko-certvalidator 0.32 moved its default fetcher from requests to an aiohttp session that
ignores HTTP_PROXY, so a network whose only way out is a proxy lost revocation checking on an
upgrade. Each test stands up a stand-in proxy on localhost, points HTTP_PROXY at it and verifies a
signature whose certificate keeps its CRL on a host that cannot resolve: the proxy is the only
place the CRL request can be seen at all.
"""

import datetime
import http.server
import io
import threading

import pytest
from asn1crypto import keys as asn1keys
from asn1crypto import x509 as asn1x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from pyhanko.sign.signers import SimpleSigner
from pyhanko_certvalidator.registry import SimpleCertificateStore

CRL_URL = "http://crl.firmauy.invalid/test.crl"
DATA = b"contenido a firmar"


def _ca_and_leaf():
    """A CA, a leaf under it whose only revocation source is CRL_URL, and the leaf's key."""
    now = datetime.datetime.now(datetime.timezone.utc)

    def _cert(builder, key, issuer_key):
        return (builder.public_key(key.public_key())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=365))
                .sign(issuer_key, hashes.SHA256()))

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TEST REVOCATION CA")])
    ca = _cert(
        x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).serial_number(1)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True),
        ca_key, ca_key)

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TEST REVOCATION SIGNER")])
    leaf = _cert(
        x509.CertificateBuilder().subject_name(leaf_name).issuer_name(ca_name).serial_number(2)
        .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
            full_name=[x509.UniformResourceIdentifier(CRL_URL)],
            relative_name=None, reasons=None, crl_issuer=None)]), critical=False),
        leaf_key, ca_key)
    return ca, leaf, leaf_key


def _simple_signer(key, cert, ca) -> SimpleSigner:
    registry = SimpleCertificateStore()
    registry.register(asn1x509.Certificate.load(ca.public_bytes(serialization.Encoding.DER)))
    return SimpleSigner(
        signing_cert=asn1x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER)),
        signing_key=asn1keys.PrivateKeyInfo.load(key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())),
        cert_registry=registry,
    )


def _blank_pdf() -> io.BytesIO:
    from pyhanko.pdf_utils import generic
    from pyhanko.pdf_utils.writer import PageObject, PdfFileWriter

    writer = PdfFileWriter()
    box = generic.ArrayObject([generic.NumberObject(n) for n in (0, 0, 200, 200)])
    contents = writer.add_object(generic.StreamObject(stream_data=b""))
    writer.insert_page(PageObject(contents=contents, media_box=box))
    base = io.BytesIO()
    writer.write(base)
    base.seek(0)
    return base


@pytest.fixture
def proxy(monkeypatch):
    """A stand-in HTTP proxy on localhost. Records the target of every request and answers 404,
    which a hard-fail revocation check treats as revocation information it could not get."""
    seen = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)      # absolute-form, since the client is talking to a proxy
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    for var in ("NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    for var in ("HTTP_PROXY", "http_proxy"):
        monkeypatch.setenv(var, f"http://127.0.0.1:{srv.server_port}")
    try:
        yield seen
    finally:
        srv.shutdown()


def test_cms_revocation_goes_through_the_proxy(proxy):
    from firmauy.cms_sign import sign_cms_detached
    from firmauy.cms_verify import verify_cms

    ca, leaf, key = _ca_and_leaf()
    p7s = sign_cms_detached(io.BytesIO(DATA), signer=_simple_signer(key, leaf, ca))

    verify_cms(io.BytesIO(DATA), p7s, trust_roots=[ca], check_revocation=True)

    assert CRL_URL in proxy, "the CRL request did not go through HTTP_PROXY"


def test_pdf_revocation_goes_through_the_proxy(proxy, tmp_path):
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign.signers import PdfSignatureMetadata, sign_pdf

    from firmauy.pdf_verify import verify_pdf

    ca, leaf, key = _ca_and_leaf()
    out = io.BytesIO()
    sign_pdf(IncrementalPdfFileWriter(_blank_pdf()), PdfSignatureMetadata(field_name="Sig1"),
             signer=_simple_signer(key, leaf, ca), output=out)
    path = tmp_path / "firmado.pdf"
    path.write_bytes(out.getvalue())

    verify_pdf(path, trust_roots=[ca], check_revocation=True)

    assert CRL_URL in proxy, "the CRL request did not go through HTTP_PROXY"


def test_xml_revocation_goes_through_the_proxy(proxy):
    from firmauy.xml_sign import sign_xml
    from firmauy.xml_verify import verify_xml

    ca, leaf, key = _ca_and_leaf()
    signed = sign_xml(b"<root><data>x</data></root>", cert=leaf,
                      signer=lambda d: key.sign(d, padding.PKCS1v15(), hashes.SHA256()),
                      signing_time=datetime.datetime.now(datetime.timezone.utc))

    verify_xml(signed, trust_roots=[ca], check_revocation=True)

    assert CRL_URL in proxy, "the CRL request did not go through HTTP_PROXY"


def test_without_check_revocation_nothing_is_fetched(proxy):
    """The offline default stays offline, with the chain still validated against the anchors."""
    from firmauy.cms_sign import sign_cms_detached
    from firmauy.cms_verify import verify_cms

    ca, leaf, key = _ca_and_leaf()
    p7s = sign_cms_detached(io.BytesIO(DATA), signer=_simple_signer(key, leaf, ca))

    verify_cms(io.BytesIO(DATA), p7s, trust_roots=[ca])

    assert proxy == []
