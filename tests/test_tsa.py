"""Unit tests for TSA timestamper construction with auth (signing._build_timestamper).

The builder is presentation-free: inconsistent options raise ValueError, and the
argv-visibility warning for sensitive literal headers goes to the optional ``notify``
callback (which the CLI wires to stderr)."""

import pytest
from pyhanko.sign.timestamps import TimeStamper

from firmauy.signing import _build_timestamper


def _b(**kw):
    kw.setdefault("tsa_url", None)
    kw.setdefault("tsa_user", None)
    kw.setdefault("tsa_pass_env", None)
    kw.setdefault("tsa_header", None)
    kw.setdefault("tsa_header_env", None)
    return _build_timestamper(**kw)


def test_none_without_url():
    assert _b() is None


def test_auth_options_require_url():
    with pytest.raises(ValueError, match="require --tsa-url"):
        _b(tsa_user="u")
    with pytest.raises(ValueError, match="require --tsa-url"):
        _b(tsa_header=["X: y"])


def test_url_only_no_auth():
    ts = _b(tsa_url="https://tsa.example/tsr")
    assert isinstance(ts, TimeStamper)
    assert ts.auth is None and ts.headers is None


def test_basic_auth(monkeypatch):
    monkeypatch.setenv("MY_TSA_PW", "s3cret")
    ts = _b(tsa_url="https://t", tsa_user="alice", tsa_pass_env="MY_TSA_PW")
    assert ts.auth == ("alice", "s3cret")


def test_user_without_passenv_raises():
    with pytest.raises(ValueError, match="both --tsa-user and --tsa-pass-env"):
        _b(tsa_url="https://t", tsa_user="alice")


def test_passenv_unset_raises(monkeypatch):
    monkeypatch.delenv("ABSENT_TSA_PW", raising=False)
    with pytest.raises(ValueError, match="is not set"):
        _b(tsa_url="https://t", tsa_user="alice", tsa_pass_env="ABSENT_TSA_PW")


def test_headers_parsed():
    ts = _b(tsa_url="https://t", tsa_header=["Authorization: Bearer abc", "X-Api-Key:k"])
    assert ts.headers == {"Authorization": "Bearer abc", "X-Api-Key": "k"}


def test_bad_header_raises():
    with pytest.raises(ValueError, match="Name: Value"):
        _b(tsa_url="https://t", tsa_header=["no-colon"])


# --- --tsa-header-env (keeps secrets off argv) ------------------------------

def test_header_env_reads_value_from_environment(monkeypatch):
    monkeypatch.setenv("TSA_AUTH", "Bearer s3cret")
    ts = _b(tsa_url="https://t", tsa_header_env=["Authorization: TSA_AUTH"])
    assert ts.headers == {"Authorization": "Bearer s3cret"}   # value came from env, not argv


def test_header_env_requires_url():
    with pytest.raises(ValueError, match="require --tsa-url"):
        _b(tsa_header_env=["Authorization: TSA_AUTH"])


def test_header_env_bad_format_raises():
    with pytest.raises(ValueError, match="Name: ENV_VAR"):
        _b(tsa_url="https://t", tsa_header_env=["no-colon"])


def test_header_env_missing_var_raises(monkeypatch):
    monkeypatch.delenv("ABSENT_HDR", raising=False)
    with pytest.raises(ValueError, match="is not set"):
        _b(tsa_url="https://t", tsa_header_env=["Authorization: ABSENT_HDR"])


def test_literal_and_env_headers_merge(monkeypatch):
    monkeypatch.setenv("TSA_AUTH", "Bearer s3cret")
    ts = _b(tsa_url="https://t", tsa_header=["X-Trace-Id: t1"],
            tsa_header_env=["Authorization: TSA_AUTH"])
    assert ts.headers == {"X-Trace-Id": "t1", "Authorization": "Bearer s3cret"}


def test_sensitive_literal_header_warns():
    # A credential passed literally is visible in argv: warn (via notify) and point at
    # --tsa-header-env.
    notes = []
    _b(tsa_url="https://t", tsa_header=["Authorization: Bearer abc"], notify=notes.append)
    assert any("visible in the process list" in n for n in notes)


def test_nonsensitive_literal_header_is_silent():
    notes = []
    _b(tsa_url="https://t", tsa_header=["X-Trace-Id: abc"], notify=notes.append)
    assert notes == []


def test_warning_dropped_without_notify():
    # The public API passes no notify: a sensitive literal header still builds, silently.
    ts = _b(tsa_url="https://t", tsa_header=["Authorization: Bearer abc"])
    assert ts.headers == {"Authorization": "Bearer abc"}


# --- credentials require TLS --------------------------------------------------

def test_basic_auth_over_http_is_refused(monkeypatch):
    """An anonymous timestamp over http is a defensible choice: the token is signed, so a passive
    observer learns a hash and can change nothing. A subscriber password over http is not, because
    it travels in the clear and is reusable once taken."""
    monkeypatch.setenv("TSA_PW", "s3cret")

    with pytest.raises(ValueError, match="unencrypted"):
        _b(tsa_url="http://tsa.example/tsr", tsa_user="ana", tsa_pass_env="TSA_PW")


def test_a_secret_header_over_http_is_refused(monkeypatch):
    monkeypatch.setenv("TSA_KEY", "abc123")

    with pytest.raises(ValueError, match="unencrypted"):
        _b(tsa_url="http://tsa.example/tsr", tsa_header_env=["Authorization: TSA_KEY"])


def test_a_literal_header_over_http_is_refused():
    with pytest.raises(ValueError, match="unencrypted"):
        _b(tsa_url="http://tsa.example/tsr", tsa_header=["X-Api-Key: abc123"])


def test_an_anonymous_timestamp_over_http_is_still_allowed():
    """Deliberately not blocked. Uruguay has no free public TSA and the ones people reach for are
    bring-your-own, so refusing plain http entirely would break the ordinary case to protect a
    credential that is not being sent."""
    assert isinstance(_b(tsa_url="http://tsa.example/tsr"), TimeStamper)


def test_credentials_over_https_are_fine(monkeypatch):
    monkeypatch.setenv("TSA_PW", "s3cret")

    built = _b(tsa_url="https://tsa.example/tsr", tsa_user="ana", tsa_pass_env="TSA_PW")

    assert isinstance(built, TimeStamper)


def test_the_scheme_check_is_not_fooled_by_case():
    with pytest.raises(ValueError, match="unencrypted"):
        _b(tsa_url="HTTP://tsa.example/tsr", tsa_header=["X-Api-Key: abc123"])
    assert isinstance(_b(tsa_url="HTTPS://tsa.example/tsr",
                         tsa_header=["X-Api-Key: abc123"]), TimeStamper)


def test_credentials_hidden_in_the_url_do_not_slip_past():
    """They never touch --tsa-user or --tsa-header, so a guard that only looked at those waved
    them through while requests sent them exactly the same way."""
    with pytest.raises(ValueError, match="credentials in it"):
        _b(tsa_url="http://ana:secreta@tsa.example/tsr")


def test_a_username_alone_in_the_url_counts_too():
    with pytest.raises(ValueError, match="credentials in it"):
        _b(tsa_url="http://ana@tsa.example/tsr")


def test_credentials_in_the_url_are_refused_even_over_https():
    """TLS protects them in transit and nothing protects them at rest. A URL on the command line
    is in argv, in /proc, in the shell history and in whatever CI logs, which is the exposure
    --tsa-pass-env exists to avoid. This module promises that passwords are never taken on the
    command line, and half-keeping that promise is worse than not making it."""
    with pytest.raises(ValueError, match="argv"):
        _b(tsa_url="https://ana:secreta@tsa.example/tsr")


# --- redirects ----------------------------------------------------------------

def _tsa_server(handler_cls):
    """A throwaway HTTP server on localhost, returned with its port."""
    import http.server
    import threading

    srv = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_a_redirect_is_refused_and_the_headers_never_arrive():
    """requests follows redirects by default and carries request headers along. It drops
    Authorization when a redirect downgrades https to http, and keeps everything else, so a TSA
    answering 302 could walk an --tsa-header-env secret into plaintext. Checking the scheme of
    the URL the user typed does not help: by the time the final URL is known, the secret is
    already at it.
    """
    import asyncio
    import http.server

    from asn1crypto import tsp

    seen_at_destination = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path == "/secure":
                self.send_response(302)
                self.send_header("Location", "/plain")
                self.end_headers()
                return
            seen_at_destination.update({k.lower(): v for k, v in self.headers.items()})
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    from firmauy.signing import _NoRedirectTimeStamper

    srv = _tsa_server(Handler)
    try:
        # The subclass directly, not through _build_timestamper, which would refuse a header over
        # http before this layer is reached. Two independent defences deserve separate tests: the
        # scheme guard covers the URL the user typed, and this one covers where it sends them.
        stamper = _NoRedirectTimeStamper(f"http://127.0.0.1:{srv.server_port}/secure",
                                         headers={"X-Api-Key": "s3cret-key"},
                                         allow_private_network=True)
        req = tsp.TimeStampReq({
            "version": 1,
            "message_imprint": tsp.MessageImprint({
                "hash_algorithm": {"algorithm": "sha256"},
                "hashed_message": b"\x00" * 32,
            }),
        })
        with pytest.raises(Exception, match="redirect"):
            asyncio.run(stamper.async_request_tsa_response(req))
    finally:
        srv.shutdown()

    assert "x-api-key" not in seen_at_destination, "the secret reached the redirect target"


def test_basic_auth_and_the_rfc3161_media_types_reach_the_tsa():
    """Checked where they land: at the server.

    pyHanko 0.37 moved ``HTTPTimeStamper`` to aiohttp and turned ``auth`` into an
    ``aiohttp.BasicAuth``, which requests refuses with a TypeError before sending anything. While
    this class inherited that constructor, every credentialed timestamp broke on a pyHanko upgrade,
    with no change on this side.
    """
    import asyncio
    import base64
    import http.server

    from asn1crypto import tsp

    seen = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            seen.update({k.lower(): v for k, v in self.headers.items()})
            self.rfile.read(int(self.headers["Content-Length"]))
            # An empty 200, which the client rejects as malformed. What is under test is the
            # request, and a well-formed reply would need a signed token to parse at all.
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    from firmauy.signing import _NoRedirectTimeStamper

    srv = _tsa_server(Handler)
    try:
        # The subclass directly: the builder refuses credentials over http, and this test is about
        # what the request carries, not about that guard.
        stamper = _NoRedirectTimeStamper(f"http://127.0.0.1:{srv.server_port}/tsr",
                                         auth=("alice", "s3cret"), allow_private_network=True)
        req = tsp.TimeStampReq({
            "version": 1,
            "message_imprint": tsp.MessageImprint({
                "hash_algorithm": {"algorithm": "sha256"},
                "hashed_message": b"\x00" * 32,
            }),
        })
        with pytest.raises(Exception, match="malformed"):
            asyncio.run(stamper.async_request_tsa_response(req))
    finally:
        srv.shutdown()

    assert seen["authorization"] == "Basic " + base64.b64encode(b"alice:s3cret").decode()
    assert seen["content-type"] == "application/timestamp-query"
    assert seen["accept"] == "application/timestamp-reply"


def test_the_builder_returns_a_timestamper_that_refuses_redirects():
    """A guard that lives in a subclass is only worth what the factory returns."""
    from firmauy.signing import _NoRedirectTimeStamper

    assert isinstance(_b(tsa_url="https://tsa.example/tsr"), _NoRedirectTimeStamper)


def test_empty_userinfo_is_still_userinfo():
    """`https://:@host/` parses to empty strings rather than None, so a truth test waves it
    through while requests still reads it as credentials."""
    with pytest.raises(ValueError, match="credentials in it"):
        _b(tsa_url="https://:@tsa.example/tsr")


def test_a_url_that_is_not_http_is_refused_here(monkeypatch):
    """Rejected at the option rather than several layers down inside requests, where the same
    mistake comes back as a connection error that names neither the option nor the fix."""
    for url in ("ftp://tsa.example/t", "file:///etc/passwd", "not-a-url"):
        with pytest.raises(ValueError, match="http:// or https://"):
            _b(tsa_url=url)


def test_a_url_without_a_host_is_refused():
    with pytest.raises(ValueError, match="no host"):
        _b(tsa_url="https:///sinhost")


def test_oversized_tsa_response_is_rejected_before_asn1_parsing():
    import asyncio
    import http.server

    from asn1crypto import tsp
    from firmauy.signing import _NoRedirectTimeStamper

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/timestamp-reply")
            self.send_header(
                "Content-Length", str(_NoRedirectTimeStamper._MAX_RESPONSE_BYTES + 1)
            )
            self.end_headers()

        def log_message(self, *args):
            pass

    srv = _tsa_server(Handler)
    try:
        stamper = _NoRedirectTimeStamper(f"http://127.0.0.1:{srv.server_port}/tsr",
                                         allow_private_network=True)
        req = tsp.TimeStampReq({
            "version": 1,
            "message_imprint": tsp.MessageImprint({
                "hash_algorithm": {"algorithm": "sha256"},
                "hashed_message": b"\x00" * 32,
            }),
        })
        with pytest.raises(Exception, match="exceeds the .* byte limit"):
            asyncio.run(stamper.async_request_tsa_response(req))
    finally:
        srv.shutdown()


def test_the_tsa_response_is_closed_when_it_is_refused(monkeypatch):
    """Streamed, so a response refused before its body is read holds its connection until
    something closes it. From #19."""
    import asyncio
    from unittest.mock import Mock

    from asn1crypto import tsp
    from firmauy.signing import _NoRedirectTimeStamper

    response = Mock(
        status_code=200,
        is_redirect=False,
        is_permanent_redirect=False,
        headers={"Content-Type": "application/timestamp-reply"},
        iter_content=lambda chunk_size: [b"12345"],
    )
    monkeypatch.setattr(_NoRedirectTimeStamper, "_MAX_RESPONSE_BYTES", 4)
    # Where the request leaves firmauy.outbound for requests: the adapter, one hop at a time.
    monkeypatch.setattr("requests.adapters.HTTPAdapter.send", Mock(return_value=response))
    req = tsp.TimeStampReq({
        "version": 1,
        "message_imprint": tsp.MessageImprint({
            "hash_algorithm": {"algorithm": "sha256"},
            "hashed_message": b"\x00" * 32,
        }),
    })

    with pytest.raises(Exception, match="exceeds the 4 byte limit"):
        asyncio.run(_NoRedirectTimeStamper("http://tsa.example/tsr").async_request_tsa_response(req))
    response.close.assert_called_once_with()


def test_a_tsa_on_a_private_address_is_refused_and_names_the_flag():
    """The TSA is under the same outbound policy as the revocation fetches: a --tsa-url can come
    from whoever configured the caller, so an internal address takes --allow-private-network."""
    import asyncio
    import http.server

    from asn1crypto import tsp

    hits = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            hits.append(self.path)
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    srv = _tsa_server(Handler)
    try:
        req = tsp.TimeStampReq({
            "version": 1,
            "message_imprint": tsp.MessageImprint({
                "hash_algorithm": {"algorithm": "sha256"},
                "hashed_message": b"\x00" * 32,
            }),
        })
        stamper = _b(tsa_url=f"http://127.0.0.1:{srv.server_port}/tsr")
        with pytest.raises(Exception, match="--allow-private-network"):
            asyncio.run(stamper.async_request_tsa_response(req))
    finally:
        srv.shutdown()
    assert hits == [], "the request reached the private address"


def test_the_builder_passes_the_opt_in_on_and_notes_it_when_there_is_no_tsa():
    notes = []
    assert _b(tsa_url="https://tsa.example/tsr", allow_private_network=True).allow_private_network
    assert not _b(tsa_url="https://tsa.example/tsr").allow_private_network
    assert _b(allow_private_network=True, notify=notes.append) is None
    assert any("--allow-private-network only applies" in n for n in notes)


# --- what a timestamp that did not come back raises -------------------------

def _request():
    from asn1crypto import tsp

    return tsp.TimeStampReq({
        "version": 1,
        "message_imprint": tsp.MessageImprint({
            "hash_algorithm": {"algorithm": "sha256"},
            "hashed_message": b"\x00" * 32,
        }),
    })


def _answering(body: bytes, content_type: str = "application/timestamp-reply"):
    """A TSA that answers every request with ``body``."""
    import http.server

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    return _tsa_server(Handler)


def _a_domain_condition(exc):
    """What 1.19.0 changed: a FirmaUYError, and not an OSError, so ``except OSError`` written for
    environment failures does not swallow a TSA that said no."""
    from firmauy.api import FirmaUYError, TimestampError

    assert isinstance(exc, TimestampError) and isinstance(exc, FirmaUYError)
    assert not isinstance(exc, OSError)


def test_a_private_tsa_raises_its_own_class_with_what_it_resolved_to():
    """A caller has to tell this one apart from the rest: the answer is a setting, not a retry."""
    import asyncio

    from firmauy.api import TimestampDestinationRefusedError

    stamper = _b(tsa_url="http://127.0.0.1:9/tsr")
    with pytest.raises(TimestampDestinationRefusedError, match="--allow-private-network") as got:
        asyncio.run(stamper.async_request_tsa_response(_request()))

    _a_domain_condition(got.value)
    assert got.value.host == "127.0.0.1"
    assert "127.0.0.1" in {str(address) for address in got.value.addresses}
    assert got.value.link_local is False, "the opt-in would reach this one"


def test_a_link_local_tsa_is_refused_even_with_the_opt_in_and_says_so():
    """The range cloud metadata services answer on. A caller offering allow_private_network as the
    way out of this one would be offering a switch that changes nothing."""
    import asyncio

    from firmauy.api import TimestampDestinationRefusedError

    stamper = _b(tsa_url="http://169.254.169.254/tsr", allow_private_network=True)
    with pytest.raises(TimestampDestinationRefusedError) as got:
        asyncio.run(stamper.async_request_tsa_response(_request()))

    assert got.value.link_local is True


def test_a_tsa_that_refuses_the_request_raises_a_timestamp_error():
    """pyHanko judges the response and raises its own TimestampRequestError, an OSError, when the
    TSA says no. Translated at async_timestamp, which every signing path calls."""
    import asyncio

    from asn1crypto import tsp

    from firmauy.signing import _NoRedirectTimeStamper

    # RFC 3161 leaves timeStampToken out of a refusal, and asn1crypto will not dump a
    # TimeStampResp without one, so the SEQUENCE around the status is written by hand.
    status = tsp.PKIStatusInfo({"status": "rejection", "status_string": ["no, gracias"]}).dump()
    refusal = b"\x30" + bytes([len(status)]) + status
    srv = _answering(refusal)
    try:
        stamper = _NoRedirectTimeStamper(f"http://127.0.0.1:{srv.server_port}/tsr",
                                         allow_private_network=True)
        with pytest.raises(Exception, match="refused our request") as got:
            asyncio.run(stamper.async_timestamp(b"\x00" * 32, "sha256"))
    finally:
        srv.shutdown()

    _a_domain_condition(got.value)
    assert type(got.value.__cause__).__name__ == "TimestampRequestError"


def test_bytes_that_are_not_a_timestamp_reply_raise_a_timestamp_error():
    """The right media type around something that is not DER. It came out of asn1crypto as a bare
    ValueError, which reads as a bug in the caller rather than as a TSA answering nonsense."""
    import asyncio

    from firmauy.signing import _NoRedirectTimeStamper

    srv = _answering(b"esto no es un sello de tiempo")
    try:
        stamper = _NoRedirectTimeStamper(f"http://127.0.0.1:{srv.server_port}/tsr",
                                         allow_private_network=True)
        with pytest.raises(Exception, match="malformed") as got:
            asyncio.run(stamper.async_request_tsa_response(_request()))
    finally:
        srv.shutdown()

    _a_domain_condition(got.value)


def test_a_tsa_nobody_is_listening_on_raises_a_timestamp_error():
    import asyncio
    import socket

    from firmauy.signing import _NoRedirectTimeStamper

    with socket.socket() as probe:              # a port that was free a moment ago
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    stamper = _NoRedirectTimeStamper(f"http://127.0.0.1:{port}/tsr", allow_private_network=True)
    with pytest.raises(Exception, match="communication with timestamp server") as got:
        asyncio.run(stamper.async_request_tsa_response(_request()))

    _a_domain_condition(got.value)
