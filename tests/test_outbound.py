# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""The outbound policy: which destinations firmauy connects to on its own, and within what limits.

Nothing here touches the real network. Servers run on 127.0.0.1, names are answered by a stand-in
resolver, and where a test needs a destination that counts as public, the classifier is told that
the local server's address is public for the duration.
"""

import dataclasses
import datetime
import http.server
import ipaddress
import socket
import threading
import time

import pytest
import requests

from firmauy import outbound


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch, tmp_path):
    """No proxy, CA bundle or netrc from the developer's environment leaks into a test."""
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy",
                "all_proxy", "no_proxy", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NETRC", str(tmp_path / "no-such-netrc"))


def _serve(handler_cls, *, tls_context=None):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    server.daemon_threads = True
    if tls_context is not None:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class _Recorder(http.server.BaseHTTPRequestHandler):
    """Answers 200 "ok" and records each request line, headers and body."""

    seen: list = []

    def _record(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        type(self).seen.append((self.command, self.path, dict(self.headers.items()), body))

    def do_GET(self):
        self._record()
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_POST = do_GET

    def log_message(self, *args):
        pass


def _recorder():
    return type("Recorder", (_Recorder,), {"seen": []})


def _policy(allow_private=True, **changes):
    return dataclasses.replace(outbound.cert_policy(allow_private), **changes)


def _resolver(monkeypatch, names):
    """Answer the names in ``names`` (an address, None for "does not resolve", or a callable
    taking the call count), and anything else as the real resolver would. Returns the list of
    names looked up through it."""
    real = socket.getaddrinfo
    calls = []

    def fake(host, port, family=0, type=0, proto=0, flags=0):
        key = host.decode() if isinstance(host, bytes) else host
        if key in names:
            calls.append(key)
            answer = names[key]
            address = answer(calls.count(key)) if callable(answer) else answer
            if address is None:
                raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
            if ":" in address:
                return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (address, port, 0, 0))]
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]
        return real(host, port, family, type, proto, flags)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return calls


def _treat_as_public(monkeypatch, *addresses):
    real = outbound.is_public_address
    monkeypatch.setattr(outbound, "is_public_address",
                        lambda value: str(value) in addresses or real(value))


# --- which destinations --------------------------------------------------------------------------

@pytest.mark.parametrize("address, public", [
    ("8.8.8.8", True), ("2001:4860:4860::8888", True), ("::ffff:8.8.8.8", True),
    ("127.0.0.1", False), ("10.0.0.1", False), ("192.168.1.1", False), ("100.64.0.1", False),
    ("0.0.0.0", False), ("169.254.169.254", False), ("224.0.0.1", False),
    ("255.255.255.255", False), ("::1", False), ("::", False), ("fe80::1", False),
    ("fc00::1", False), ("fec0::1", False), ("::7f00:1", False), ("::ffff:127.0.0.1", False),
    ("64:ff9b::7f00:1", False), ("2002:7f00:1::", False), ("ff02::1", False),
])
def test_the_address_table_matches_the_rule(address, public):
    """is_global alone passes multicast, NAT64's image of loopback, IPv4-compatible loopback and
    site-local IPv6: each of those rows would say True."""
    assert outbound.is_public_address(address) is public


def test_link_local_is_recognised_however_it_is_written():
    for address in ("169.254.169.254", "::ffff:169.254.169.254", "fe80::1", "fe80::1%eth0"):
        assert outbound._is_link_local(address), address
    assert not outbound._is_link_local("10.0.0.1")


def test_a_loopback_server_is_refused_before_any_request_reaches_it():
    handler = _recorder()
    server = _serve(handler)
    try:
        with pytest.raises(outbound.DestinationRefused, match="--allow-private-network"):
            outbound.fetch("GET", f"http://127.0.0.1:{server.server_port}/",
                           policy=_policy(allow_private=False))
    finally:
        server.shutdown()
    assert handler.seen == []


def test_a_loopback_server_is_served_when_private_destinations_are_allowed():
    handler = _recorder()
    server = _serve(handler)
    try:
        result = outbound.fetch("GET", f"http://127.0.0.1:{server.server_port}/x",
                                policy=_policy(allow_private=True))
    finally:
        server.shutdown()
    assert (result.status_code, result.content) == (200, b"ok")
    assert handler.seen[0][:2] == ("GET", "/x")


def test_link_local_is_refused_even_when_private_destinations_are_allowed(monkeypatch):
    """That range is where cloud metadata answers. The refusal comes before any connection, so
    nothing here reaches the network."""
    _resolver(monkeypatch, {"metadata.test": "169.254.169.254"})
    for url in ("http://169.254.169.254/latest/meta-data/", "http://metadata.test/"):
        with pytest.raises(outbound.DestinationRefused, match="link-local"):
            outbound.fetch("GET", url, policy=_policy(allow_private=True))


def test_a_name_is_resolved_once_and_the_socket_goes_to_the_vetted_address(monkeypatch):
    """DNS rebinding: a name that answers a harmless address to the check and an internal one to
    the connect. Resolved once, the second answer is never asked for."""
    handler = _recorder()
    server = _serve(handler)
    calls = _resolver(monkeypatch, {"rebind.test": lambda n: "127.0.0.1" if n == 1 else "10.0.0.1"})
    _treat_as_public(monkeypatch, "127.0.0.1")
    try:
        result = outbound.fetch("GET", f"http://rebind.test:{server.server_port}/",
                                policy=_policy(allow_private=False))
    finally:
        server.shutdown()
    assert result.content == b"ok"
    assert calls == ["rebind.test"]
    assert handler.seen[0][2]["Host"] == f"rebind.test:{server.server_port}"


def _tls_files(tmp_path, name):
    """A CA and a certificate for ``name`` signed by it, written as PEM."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.timezone.utc)

    def build(subject, issuer, key, issuer_key, *, ca, san=None):
        # Key identifiers and key usage, because Python 3.13+ verifies in X.509 strict mode and
        # refuses a chain without them.
        builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - datetime.timedelta(days=1))
                   .not_valid_after(now + datetime.timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                                  critical=False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                       issuer_key.public_key()), critical=False)
                   .add_extension(x509.KeyUsage(
                       digital_signature=not ca, content_commitment=False,
                       key_encipherment=False, data_encipherment=False, key_agreement=False,
                       key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False),
                       critical=True))
        if san:
            builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
        return builder.sign(issuer_key, hashes.SHA256())

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "outbound test CA")])
    ca = build(ca_name, ca_name, ca_key, ca_key, ca=True)
    key = ec.generate_private_key(ec.SECP256R1())
    cert = build(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]), ca_name, key, ca_key,
                 ca=False, san=[x509.DNSName(name)])
    pem = serialization.Encoding.PEM
    (tmp_path / "ca.pem").write_bytes(ca.public_bytes(pem))
    (tmp_path / "server.pem").write_bytes(cert.public_bytes(pem) + key.private_bytes(
        pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return tmp_path / "ca.pem", tmp_path / "server.pem"


@pytest.mark.parametrize("certificate_name, trusted", [("rebind.test", True), ("other.test", False)])
def test_tls_is_checked_against_the_name_while_the_socket_goes_to_the_address(
        monkeypatch, tmp_path, certificate_name, trusted):
    """Pinning the address must not pin the certificate check to it: the name the URL gave is
    what the certificate is matched against, and a certificate for another name fails."""
    import ssl

    ca_file, server_file = _tls_files(tmp_path, certificate_name)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(server_file)
    server = _serve(_recorder(), tls_context=context)
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(ca_file))
    _resolver(monkeypatch, {"rebind.test": "127.0.0.1"})
    try:
        if trusted:
            result = outbound.fetch("GET", f"https://rebind.test:{server.server_port}/",
                                    policy=_policy(allow_private=True))
            assert result.content == b"ok"
        else:
            with pytest.raises(requests.exceptions.SSLError):
                outbound.fetch("GET", f"https://rebind.test:{server.server_port}/",
                               policy=_policy(allow_private=True))
    finally:
        server.shutdown()


# --- redirects -----------------------------------------------------------------------------------

class _Redirector(http.server.BaseHTTPRequestHandler):
    """/r/N redirects to /r/N-1 until /r/0, which answers ok. /to?u=URL redirects to URL with the
    status in /to/STATUS. Records method, path and body of every request."""

    seen: list = []

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        type(self).seen.append((self.command, self.path, body))
        if self.path.startswith("/r/") and self.path != "/r/0":
            self.send_response(302)
            self.send_header("Location", f"/r/{int(self.path[3:]) - 1}")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.startswith("/to/"):
            status, _, target = self.path[4:].partition("?u=")
            self.send_response(int(status))
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = do_POST = _handle

    def log_message(self, *args):
        pass


def _redirector():
    return type("Redirector", (_Redirector,), {"seen": []})


def test_redirects_are_followed_up_to_the_limit_and_refused_past_it():
    handler = _redirector()
    server = _serve(handler)
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        assert outbound.fetch("GET", base + "/r/3", policy=_policy(max_redirects=3)).content == b"ok"
        with pytest.raises(outbound.RedirectRefused) as refused:
            outbound.fetch("GET", base + "/r/4", policy=_policy(max_redirects=3))
    finally:
        server.shutdown()
    assert refused.value.status_code == 302


def test_a_policy_without_redirects_refuses_the_first_and_never_asks_the_target():
    handler = _redirector()
    server = _serve(handler)
    try:
        with pytest.raises(outbound.RedirectRefused, match="not followed"):
            outbound.fetch("GET", f"http://127.0.0.1:{server.server_port}/r/1",
                           policy=_policy(max_redirects=0))
    finally:
        server.shutdown()
    assert [path for _, path, _ in handler.seen] == ["/r/1"]


def test_a_redirect_to_an_internal_name_is_refused_after_a_public_first_hop(monkeypatch):
    """Each hop is vetted like the first request: a public server cannot hand firmauy an
    internal address by redirecting to it."""
    handler = _redirector()
    server = _serve(handler)
    _resolver(monkeypatch, {"internal.test": "10.0.0.1"})
    _treat_as_public(monkeypatch, "127.0.0.1")
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        for target, why in (("http://internal.test/", "not a public address"),
                            ("http://169.254.169.254/", "link-local")):
            with pytest.raises(outbound.DestinationRefused, match=why):
                outbound.fetch("GET", f"{base}/to/302?u={target}", policy=_policy(allow_private=False))
    finally:
        server.shutdown()


def test_a_redirect_to_another_scheme_is_refused():
    server = _serve(_redirector())
    try:
        with pytest.raises(outbound.RedirectRefused, match="only http and https"):
            outbound.fetch("GET", f"http://127.0.0.1:{server.server_port}/to/302?u=ftp://x.test/",
                           policy=_policy())
    finally:
        server.shutdown()


def test_the_body_of_a_redirect_is_never_read():
    """requests' own redirect handling reads a 3xx body whole before moving on. This one
    declares a gigabyte and sends a trickle: read, it would take the whole deadline."""

    class HugeRedirect(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/ok":
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")
                return
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.send_header("Content-Length", str(1024 ** 3))
            self.end_headers()
            for _ in range(100):
                try:
                    self.wfile.write(b"x" * 1024)
                    self.wfile.flush()
                    time.sleep(0.05)
                except OSError:
                    return

        def log_message(self, *args):
            pass

    server = _serve(HugeRedirect)
    started = time.monotonic()
    try:
        result = outbound.fetch("GET", f"http://127.0.0.1:{server.server_port}/",
                                policy=_policy(total_timeout=10.0))
    finally:
        server.shutdown()
    assert result.content == b"ok"
    assert time.monotonic() - started < 3


def test_303_turns_a_post_into_a_get_and_307_keeps_it():
    handler = _redirector()
    server = _serve(handler)
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        for status in (303, 307):
            outbound.fetch("POST", f"{base}/to/{status}?u=/final{status}", policy=_policy(),
                           data=b"payload", headers={"Content-Type": "application/x-test"})
    finally:
        server.shutdown()
    final = {path: (method, body) for method, path, body in handler.seen if path.startswith("/final")}
    assert final == {"/final303": ("GET", b""), "/final307": ("POST", b"payload")}


def test_credentials_are_refused_together_with_redirects():
    with pytest.raises(ValueError, match="redirect"):
        outbound.fetch("GET", "http://127.0.0.1:9/", policy=_policy(max_redirects=3),
                       auth=("user", "secret"))


# --- size, time and budget -------------------------------------------------------------------------

class _Sized(http.server.BaseHTTPRequestHandler):
    """/declared answers with a Content-Length past the limit and no body. /undeclared sends
    chunks without a length until the connection closes."""

    protocol_version = "HTTP/1.0"

    def do_GET(self):
        self.send_response(200)
        if self.path == "/declared":
            self.send_header("Content-Length", str(10 * 1024 * 1024))
            self.end_headers()
            return
        self.end_headers()
        try:
            for _ in range(64):
                self.wfile.write(b"x" * 1024)
        except OSError:
            pass

    def log_message(self, *args):
        pass


@pytest.mark.parametrize("path", ["/declared", "/undeclared"])
def test_a_body_past_the_limit_is_refused(path):
    server = _serve(_Sized)
    try:
        with pytest.raises(outbound.ResponseTooLarge) as too_large:
            outbound.fetch("GET", f"http://127.0.0.1:{server.server_port}{path}",
                           policy=_policy(max_bytes=4096))
    finally:
        server.shutdown()
    assert too_large.value.limit == 4096


class _Trickle(http.server.BaseHTTPRequestHandler):
    """/body sends its headers, then a byte every 0.2 s. /status sends the status line and then a
    header every 0.2 s. Neither ever pauses long enough to trip a read timeout."""

    def do_GET(self):
        try:
            if self.path == "/body":
                self.send_response(200)
                self.send_header("Content-Length", "1000")
                self.end_headers()
                for _ in range(1000):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.2)
            else:
                self.wfile.write(b"HTTP/1.1 200 OK\r\n")
                self.wfile.flush()
                for i in range(100):
                    self.wfile.write(f"X-Slow-{i}: y\r\n".encode())
                    self.wfile.flush()
                    time.sleep(0.2)
        except OSError:
            return

    def log_message(self, *args):
        pass


@pytest.mark.parametrize("path", ["/body", "/status"])
def test_a_server_that_trickles_is_cut_off_at_the_total_deadline(path):
    """Per-read timeouts alone never fire here: something arrives every 0.2 s. The watchdog is
    what ends it, in the body and while the headers are still coming."""
    server = _serve(_Trickle)
    started = time.monotonic()
    try:
        with pytest.raises(outbound.DeadlineExceeded):
            outbound.fetch("GET", f"http://127.0.0.1:{server.server_port}{path}",
                           policy=_policy(total_timeout=1.0, read_timeout=5.0))
    finally:
        server.shutdown()
    assert time.monotonic() - started < 2.5


def test_the_budget_stops_the_fetch_past_its_count_and_the_byte_past_its_total():
    assert (outbound.FetchBudget().max_fetches, outbound.FetchBudget().max_bytes) == (32, 128 * outbound.MiB)
    server = _serve(_recorder())
    url = f"http://127.0.0.1:{server.server_port}/"
    try:
        budget = outbound.FetchBudget(max_fetches=2)
        for _ in range(2):
            outbound.fetch("GET", url, policy=_policy(), budget=budget)
        with pytest.raises(outbound.BudgetExceeded, match="2 requests"):
            outbound.fetch("GET", url, policy=_policy(), budget=budget)

        small = outbound.FetchBudget(max_bytes=3)
        outbound.fetch("GET", url, policy=_policy(), budget=small)       # 2 bytes
        with pytest.raises(outbound.BudgetExceeded, match="more than 3 bytes"):
            outbound.fetch("GET", url, policy=_policy(), budget=small)
    finally:
        server.shutdown()


# --- credentials ---------------------------------------------------------------------------------

def test_a_netrc_default_entry_is_never_sent(monkeypatch, tmp_path):
    """requests would send a netrc ``default`` entry to any host, so to whatever URL a document
    names. An explicit auth is still sent."""
    netrc = tmp_path / "netrc"
    netrc.write_text("default login someone password s3cret\n")
    netrc.chmod(0o600)
    monkeypatch.setenv("NETRC", str(netrc))
    handler = _recorder()
    server = _serve(handler)
    url = f"http://127.0.0.1:{server.server_port}/"
    try:
        outbound.fetch("GET", url, policy=_policy())
        outbound.fetch("GET", url, policy=_policy(max_redirects=0), auth=("alice", "pw"))
    finally:
        server.shutdown()
    assert "Authorization" not in handler.seen[0][2]
    assert handler.seen[1][2]["Authorization"].startswith("Basic ")


# --- proxies -------------------------------------------------------------------------------------

class _Proxy(http.server.BaseHTTPRequestHandler):
    """A stand-in proxy: records the request line of every request and CONNECT, answers 200."""

    seen: list = []

    def do_GET(self):
        type(self).seen.append(f"{self.command} {self.path}")
        self.send_response(200)
        self.send_header("Content-Length", "7")
        self.end_headers()
        self.wfile.write(b"proxied")

    def do_CONNECT(self):
        type(self).seen.append(f"{self.command} {self.path}")
        self.send_response(502)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def proxy(monkeypatch):
    handler = type("Proxy", (_Proxy,), {"seen": []})
    server = _serve(handler)
    address = f"http://127.0.0.1:{server.server_port}"
    for var in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
        monkeypatch.setenv(var, address)
    yield handler.seen
    server.shutdown()


def test_a_proxy_on_loopback_is_used_for_a_public_target(monkeypatch, proxy):
    """The proxy is the operator's choice: its address is not vetted, the target's is."""
    _resolver(monkeypatch, {"public.test": "93.184.216.34"})
    result = outbound.fetch("GET", "http://public.test/x", policy=_policy(allow_private=False))
    assert result.content == b"proxied"
    assert proxy == ["GET http://public.test/x"]


def test_a_proxied_target_that_resolves_internally_is_refused_before_the_proxy_sees_it(
        monkeypatch, proxy):
    _resolver(monkeypatch, {"internal.test": "10.0.0.1"})
    for url in ("http://internal.test/", "http://169.254.169.254/", "https://internal.test/"):
        with pytest.raises(outbound.DestinationRefused):
            outbound.fetch("GET", url, policy=_policy(allow_private=False))
    assert proxy == [], "the proxy was asked anyway"


def test_a_target_that_does_not_resolve_locally_goes_on_through_the_proxy(monkeypatch, proxy):
    """In a network that only reaches out through a proxy, the proxy is often the only thing
    that can resolve a name."""
    _resolver(monkeypatch, {"only-the-proxy-knows.test": None})
    result = outbound.fetch("GET", "http://only-the-proxy-knows.test/crl",
                            policy=_policy(allow_private=False))
    assert result.content == b"proxied"


def test_nothing_connects_outside_a_fetch():
    """The connection classes refuse to connect unless a fetch set their policy, so they cannot
    be picked up by some other code path and connect unvetted."""
    connection = outbound._PolicyHTTPConnection("127.0.0.1", 9)
    with pytest.raises(outbound._Refused):
        connection.connect()


def test_ipaddress_accepts_what_the_resolver_returns():
    """getaddrinfo can return a scoped IPv6 address. The classifier takes it as is."""
    assert outbound._address("fe80::1%lo") == ipaddress.ip_address("fe80::1")
