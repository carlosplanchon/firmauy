# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""--check-revocation fetches through the proxy the environment names, under the outbound policy,
and nothing fetches without it.

pyhanko-certvalidator 0.32 moved its default fetcher from requests to an aiohttp session that
ignores HTTP_PROXY, so a network whose only way out is a proxy lost revocation checking on an
upgrade. The proxy tests stand up a stand-in proxy on localhost, point HTTP_PROXY at it and verify
a signature whose certificate keeps its CRL on a host that cannot resolve: the proxy is the only
place the CRL request can be seen at all. The policy tests serve certificates and CRLs from
127.0.0.1, which the policy refuses unless allow_private_network is set.
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
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID
from pyhanko.sign.signers import SimpleSigner
from pyhanko_certvalidator.registry import SimpleCertificateStore

CRL_URL = "http://crl.firmauy.invalid/test.crl"
DATA = b"contenido a firmar"


def _ca_and_leaf(crl_url=CRL_URL):
    """A CA, a leaf under it whose only revocation source is ``crl_url``, and the leaf's key."""
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
            full_name=[x509.UniformResourceIdentifier(crl_url)],
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
    _no_dns_for_invalid_names(monkeypatch)
    try:
        yield seen
    finally:
        srv.shutdown()


def _no_dns_for_invalid_names(monkeypatch):
    """The outbound policy resolves a proxied target locally before handing it to the proxy.
    A ``.invalid`` name never resolves (RFC 6761), so answer that here instead of asking the
    system resolver, which keeps these tests off the network and fast where DNS is slow."""
    import socket

    real = socket.getaddrinfo

    def getaddrinfo(host, *args, **kwargs):
        if isinstance(host, str) and host.endswith(".invalid"):
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)


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


# --- the outbound policy ------------------------------------------------------------------------

@pytest.fixture
def local_server(monkeypatch):
    """A server on 127.0.0.1, with no proxy in the way. It records the path of every GET, serves
    what a test puts in ``files`` (path to content type and body) and answers 404 to the rest."""
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy",
                "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    files, seen = {}, []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            content_type, body = files.get(self.path, (None, b""))
            self.send_response(200 if content_type else 404)
            if content_type:
                self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}", files, seen
    finally:
        srv.shutdown()


def _verify_with(kind, ca, leaf, key, tmp_path, **kwargs):
    """Sign with the leaf in the format ``kind`` and verify with revocation, returning the chain
    row of the (first) result."""
    from firmauy.verify_common import CHAIN_CHECK

    if kind == "cms":
        from firmauy.cms_sign import sign_cms_detached
        from firmauy.cms_verify import verify_cms

        p7s = sign_cms_detached(io.BytesIO(DATA), signer=_simple_signer(key, leaf, ca))
        result = verify_cms(io.BytesIO(DATA), p7s, trust_roots=[ca], check_revocation=True, **kwargs)
    elif kind == "pdf":
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
        from pyhanko.sign.signers import PdfSignatureMetadata, sign_pdf

        from firmauy.pdf_verify import verify_pdf

        out = io.BytesIO()
        sign_pdf(IncrementalPdfFileWriter(_blank_pdf()), PdfSignatureMetadata(field_name="Sig1"),
                 signer=_simple_signer(key, leaf, ca), output=out)
        path = tmp_path / "firmado.pdf"
        path.write_bytes(out.getvalue())
        result = verify_pdf(path, trust_roots=[ca], check_revocation=True, **kwargs)[0]
    else:
        from firmauy.xml_sign import sign_xml
        from firmauy.xml_verify import verify_xml

        signed = sign_xml(b"<root><data>x</data></root>", cert=leaf,
                          signer=lambda d: key.sign(d, padding.PKCS1v15(), hashes.SHA256()),
                          signing_time=datetime.datetime.now(datetime.timezone.utc))
        result = verify_xml(signed, trust_roots=[ca], check_revocation=True, **kwargs)[0]
    return next(c for c in result.checks if c.name == CHAIN_CHECK)


@pytest.mark.parametrize("kind", ["cms", "pdf", "xml"])
def test_a_crl_on_a_private_address_is_not_fetched_and_the_chain_row_says_why(
        local_server, tmp_path, kind):
    """The CRL URL comes from the certificate, which is the document's to choose. An internal
    address is refused before anything is sent, and the chain row says so and names the flag,
    where certvalidator alone would only say the CRL could not be fetched."""
    base, _, seen = local_server
    ca, leaf, key = _ca_and_leaf(f"{base}/test.crl")

    chain = _verify_with(kind, ca, leaf, key, tmp_path)

    assert seen == [], "the private address was contacted"
    assert not chain.ok
    assert "outbound policy" in chain.detail and "--allow-private-network" in chain.detail


def test_allow_private_network_lets_an_internal_crl_mirror_be_fetched(local_server, tmp_path):
    base, _, seen = local_server
    ca, leaf, key = _ca_and_leaf(f"{base}/test.crl")

    _verify_with("cms", ca, leaf, key, tmp_path, allow_private_network=True)

    assert seen == ["/test.crl"]


def _published_pki(base, *, revoked=False):
    """A root, an intermediate under it and a signer under that, published under ``base`` the way
    a CA publishes them: the signer names its issuer's certificate (AIA) and its CRL, and the
    intermediate names its own CRL. Returns the root, the signer, the signer's key and the files
    to serve. With ``revoked`` the signer's CRL lists the signer."""
    now = datetime.datetime.now(datetime.timezone.utc)

    def _name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    def _key_usage(*, ca):
        return x509.KeyUsage(digital_signature=not ca, content_commitment=not ca,
                             key_encipherment=False, data_encipherment=False,
                             key_agreement=False, key_cert_sign=ca, crl_sign=ca,
                             encipher_only=False, decipher_only=False)

    def _cert(subject, key, issuer, issuer_key, serial, extensions):
        builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                   .serial_number(serial).public_key(key.public_key())
                   .not_valid_before(now - datetime.timedelta(days=1))
                   .not_valid_after(now + datetime.timedelta(days=365))
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                                  critical=False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                       issuer_key.public_key()), critical=False))
        for extension, critical in extensions:
            builder = builder.add_extension(extension, critical=critical)
        return builder.sign(issuer_key, hashes.SHA256())

    def _crl_dp(url):
        return x509.CRLDistributionPoints([x509.DistributionPoint(
            full_name=[x509.UniformResourceIdentifier(url)],
            relative_name=None, reasons=None, crl_issuer=None)])

    def _crl(issuer, issuer_key, revoked_serials=()):
        builder = (x509.CertificateRevocationListBuilder().issuer_name(issuer)
                   .last_update(now - datetime.timedelta(hours=1))
                   .next_update(now + datetime.timedelta(days=1))
                   .add_extension(x509.CRLNumber(1), critical=False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                       issuer_key.public_key()), critical=False))
        for serial in revoked_serials:
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder().serial_number(serial)
                .revocation_date(now - datetime.timedelta(hours=1)).build())
        return builder.sign(issuer_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    root_key, int_key, leaf_key = (rsa.generate_private_key(public_exponent=65537, key_size=2048)
                                   for _ in range(3))
    root_name, int_name = _name("TEST POLICY ROOT"), _name("TEST POLICY INTERMEDIATE")
    root = _cert(root_name, root_key, root_name, root_key, 1, [
        (x509.BasicConstraints(ca=True, path_length=None), True),
        (_key_usage(ca=True), True)])
    intermediate = _cert(int_name, int_key, root_name, root_key, 2, [
        (x509.BasicConstraints(ca=True, path_length=0), True),
        (_key_usage(ca=True), True),
        (_crl_dp(f"{base}/int.crl"), False)])
    leaf = _cert(_name("TEST POLICY SIGNER"), leaf_key, int_name, int_key, 3, [
        (_key_usage(ca=False), True),
        (_crl_dp(f"{base}/leaf.crl"), False),
        (x509.AuthorityInformationAccess([x509.AccessDescription(
            AuthorityInformationAccessOID.CA_ISSUERS,
            x509.UniformResourceIdentifier(f"{base}/int.cer"))]), False)])
    files = {
        "/int.cer": ("application/pkix-cert",
                     intermediate.public_bytes(serialization.Encoding.DER)),
        "/int.crl": ("application/pkix-crl", _crl(root_name, root_key)),
        "/leaf.crl": ("application/pkix-crl",
                      _crl(int_name, int_key, [leaf.serial_number] if revoked else [])),
    }
    return root, leaf, leaf_key, files


def _p7s_without_the_chain(key, cert) -> bytes:
    """A detached signature carrying the signer's certificate alone, so the intermediate can only
    come from the AIA URL."""
    from firmauy.cms_sign import sign_cms_detached

    signer = SimpleSigner(
        signing_cert=asn1x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER)),
        signing_key=asn1keys.PrivateKeyInfo.load(key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())),
        cert_registry=SimpleCertificateStore(),
    )
    return sign_cms_detached(io.BytesIO(DATA), signer=signer)


@pytest.mark.parametrize("revoked", [False, True], ids=["good", "revoked"])
def test_what_the_policy_fetches_is_what_the_chain_is_judged_on(local_server, revoked):
    """The issuer from the AIA URL and both CRLs come through the policy's fetchers and decide
    the verdict: the chain validates on them, and a CRL that lists the signer fails it. The
    refusal tests only show a request being stopped, and would still pass if what the fetchers
    handed certvalidator could not be used."""
    from firmauy.cms_verify import verify_cms
    from firmauy.verify_common import CHAIN_CHECK

    base, files, seen = local_server
    root, leaf, key, published = _published_pki(base, revoked=revoked)
    files.update(published)

    result = verify_cms(io.BytesIO(DATA), _p7s_without_the_chain(key, leaf), trust_roots=[root],
                        check_revocation=True, allow_private_network=True)

    chain = next(c for c in result.checks if c.name == CHAIN_CHECK)
    assert set(seen) == {"/int.cer", "/int.crl", "/leaf.crl"}
    assert chain.ok is not revoked
    assert result.indication == ("INDETERMINATE" if revoked else "VALID")


def test_an_untrusted_certificate_cannot_send_the_issuer_fetch_to_a_private_address(local_server):
    """The case the policy exists for. certvalidator fetches an issuer from the AIA URL of a
    certificate it does not trust yet, so the document decides where that request goes. Without
    the flag nothing reaches the address, and the chain row says why."""
    from firmauy.cms_verify import verify_cms
    from firmauy.verify_common import CHAIN_CHECK

    base, files, seen = local_server
    root, leaf, key, published = _published_pki(base)
    files.update(published)

    result = verify_cms(io.BytesIO(DATA), _p7s_without_the_chain(key, leaf), trust_roots=[root],
                        check_revocation=True)

    chain = next(c for c in result.checks if c.name == CHAIN_CHECK)
    assert seen == []
    assert not chain.ok
    assert "outbound policy" in chain.detail and "--allow-private-network" in chain.detail
