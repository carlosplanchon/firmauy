# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Every connection firmauy opens on its own: the TSA request and the revocation fetches.

Both reach URLs that somebody other than the person running firmauy can choose. A --tsa-url can
come from whoever configured the caller, and the CRL, OCSP and AIA URLs come from certificates,
including certificates that are not trusted yet: certvalidator fetches an issuer from the AIA URL
of a certificate while it is still building the chain. Left to requests' defaults, a crafted
document could make firmauy fetch http://169.254.169.254/ (cloud metadata), follow thirty
redirects and read whatever came back, whole.

So these requests go through one policy:

- Destinations. A name is resolved once, and every address it resolves to must be public, or the
  request is refused before a byte is sent. The connection then goes to that vetted address and
  the name is not resolved again, so DNS rebinding cannot swap in an internal address between the
  check and the connect. TLS still verifies the certificate against the original name.
  ``allow_private`` (--allow-private-network) admits loopback and private networks, for an
  internal TSA or CRL mirror. Link-local addresses stay refused either way: that range is where
  cloud metadata services answer, and no TSA or mirror lives there.
- Proxies. A proxy the environment names (HTTP_PROXY, HTTPS_PROXY) is the operator's choice, so
  the connection to it is not vetted. The target is vetted by a local resolution, which the proxy
  may answer differently: through a proxy, rebinding protection is the proxy's job.
- Limits. Bytes read, redirects followed and total time, per request. The total is enforced by a
  watchdog that shuts the connection down when the time is up, because per-read timeouts alone
  let a server that trickles one byte at a time hold a request open for as long as it likes,
  during the TLS handshake and the headers as much as the body. Name resolution is the one step
  no limit reaches.
- Credentials. ``~/.netrc`` is never read. requests would otherwise send its entries, and a
  ``default`` entry to every host, to whatever URL a document names, over plain http as well.
"""

from __future__ import annotations

import ipaddress
import socket
import sys
import threading
from dataclasses import dataclass
from socket import timeout as SocketTimeout
from typing import Optional
from urllib.parse import urljoin, urlsplit

import requests
from requests.adapters import HTTPAdapter
from requests.auth import AuthBase
from requests.structures import CaseInsensitiveDict
from requests.utils import select_proxy
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NameResolutionError, NewConnectionError
from urllib3.util.connection import allowed_gai_family, create_connection

MiB = 1024 * 1024


# ---------------------------------------------------------------------------
# Which destinations are allowed
# ---------------------------------------------------------------------------

_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_GLOBAL_UNICAST = ipaddress.ip_network("2000::/3")
_SIX_TO_FOUR = ipaddress.ip_network("2002::/16")


def _address(value):
    """An ip_address from a string or an address, with a zone index (``fe80::1%eth0``) dropped
    and an IPv4 address carried inside an IPv6 one (mapped, or under NAT64's well-known prefix)
    unwrapped, so that it is judged as the address it stands for."""
    ip = ipaddress.ip_address(str(value).split("%", 1)[0])
    if ip.version == 6:
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip in _NAT64:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return ip


def is_public_address(value) -> bool:
    """Whether an address is on the public internet.

    ``is_global`` alone is not enough, in any Python this supports: it passes multicast, NAT64's
    image of loopback (``64:ff9b::7f00:1``), IPv4-compatible loopback (``::7f00:1``) and the
    deprecated site-local range (``fec0::/10``). So an IPv4 address carried in an IPv6 one is
    judged as itself, IPv6 has to be global unicast (``2000::/3``) and not 6to4 (``2002::/16``,
    which wraps an IPv4 address of any kind), and multicast is refused on its own.
    """
    ip = _address(value)
    if ip.version == 6 and (ip not in _GLOBAL_UNICAST or ip in _SIX_TO_FOUR):
        return False
    return ip.is_global and not ip.is_multicast


def _is_link_local(value) -> bool:
    return _address(value).is_link_local


def _allowed(value, allow_private: bool) -> bool:
    """The destination rule: link-local never, anything else when private destinations are
    allowed, and otherwise public addresses only. ``is_public_address`` is looked up here on every
    call, so a test can stand in for it."""
    if _is_link_local(value):
        return False
    return allow_private or is_public_address(value)


# ---------------------------------------------------------------------------
# Policies and the per-verification budget
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class OutboundPolicy:
    """What one request may do. Built by the functions below, one per kind of request."""

    allow_private: bool
    max_bytes: int
    total_timeout: float
    max_redirects: int
    connect_timeout: float = 5.0
    read_timeout: float = 10.0


def tsa_policy(allow_private: bool, *, max_bytes: int) -> OutboundPolicy:
    """A timestamp request. No redirect is followed: the request can carry the TSA credentials,
    and a redirect would carry them wherever it pointed."""
    return OutboundPolicy(allow_private, max_bytes=max_bytes, total_timeout=30.0, max_redirects=0)


def crl_policy(allow_private: bool) -> OutboundPolicy:
    """A CRL. The cédula CRL (https://ca.minterior.gub.uy/crls/crl.crl) measured 13,208,654 bytes
    on 2026-09-26 and is reissued daily: 64 MiB leaves it room to grow about five times, and
    300 s is what 12.6 MiB takes on a slow link. Its http:// URL answers 302 to https, which is
    why revocation fetches follow a few redirects, each one vetted like the first request."""
    return OutboundPolicy(allow_private, max_bytes=64 * MiB, total_timeout=300.0,
                          max_redirects=3)


def ocsp_policy(allow_private: bool) -> OutboundPolicy:
    """An OCSP response, a few kilobytes at most."""
    return OutboundPolicy(allow_private, max_bytes=1 * MiB, total_timeout=30.0, max_redirects=3)


def cert_policy(allow_private: bool) -> OutboundPolicy:
    """An issuer certificate fetched from an AIA URL, a few kilobytes at most."""
    return OutboundPolicy(allow_private, max_bytes=1 * MiB, total_timeout=30.0, max_redirects=3)


class FetchBudget:
    """What one verification may fetch in all, shared by its concurrent requests.

    The per-request limits do not bound the whole. certvalidator fetches an issuer's certificate
    from the AIA URL of each certificate it meets, recursively, so a server can hand out a chain
    that never ends, and one certificate may list many CRL URLs, fetched all at once. A cédula
    verification fetches two or three CRLs, the largest 12.6 MiB, well inside the defaults.
    """

    def __init__(self, max_fetches: int = 32, max_bytes: int = 128 * MiB):
        self.max_fetches = max_fetches
        self.max_bytes = max_bytes
        self.fetches = 0
        self.bytes = 0
        self._lock = threading.Lock()

    def charge_fetch(self, url: str) -> None:
        with self._lock:
            if self.fetches >= self.max_fetches:
                raise BudgetExceeded(
                    f"not fetching {url}: this verification already made {self.max_fetches} "
                    "requests, its limit.")
            self.fetches += 1

    def charge_bytes(self, count: int) -> None:
        with self._lock:
            self.bytes += count
            if self.bytes > self.max_bytes:
                raise BudgetExceeded(
                    f"this verification read more than {self.max_bytes} bytes in all, its limit.")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class OutboundError(requests.RequestException):
    """A request refused or cut short by the outbound policy.

    A ``requests.RequestException``, so certvalidator reports it as a failed fetch like any other,
    and hard-fail revocation fails the chain with this message instead of crashing. Being an
    ``OSError`` as well, it takes one message argument only: a second one would turn ``str()``
    into ``[Errno ...]``. Everything else it carries is an attribute.
    """


class DestinationRefused(OutboundError):
    def __init__(self, message: str, *, host: Optional[str], addresses=()):
        super().__init__(message)
        self.host = host
        self.addresses = tuple(addresses)


class RedirectRefused(OutboundError):
    def __init__(self, message: str, *, status_code: Optional[int]):
        super().__init__(message)
        self.status_code = status_code


class ResponseTooLarge(OutboundError):
    def __init__(self, message: str, *, limit: int):
        super().__init__(message)
        self.limit = limit


class DeadlineExceeded(OutboundError):
    pass


class UnexpectedContentType(OutboundError):
    def __init__(self, message: str, *, content_type: Optional[str]):
        super().__init__(message)
        self.content_type = content_type


class BudgetExceeded(OutboundError):
    pass


class _Refused(Exception):
    """Raised while urllib3 is connecting, carrying the refusal out.

    Deliberately not an ``OSError``: urllib3 and requests wrap those into ``ConnectionError`` and
    retry some of them, which would lose the reason, while any other exception comes out of
    ``HTTPAdapter.send`` as it went in. ``fetch`` turns it back into the ``DestinationRefused`` it
    carries.
    """

    def __init__(self, refusal: DestinationRefused):
        super().__init__(str(refusal))
        self.refusal = refusal


def _refusal(host: Optional[str], refused: list) -> DestinationRefused:
    address = refused[0]
    where = f"{host}, which resolves to {address}" if host and host != address else f"{address}"
    if _is_link_local(address):
        why = ("a link-local address, refused even with --allow-private-network: that range is "
               "where cloud metadata services answer, and no TSA or CRL mirror lives there")
    else:
        why = ("not a public address. Pass --allow-private-network (allow_private_network=True "
               "in the API) to reach an internal TSA or CRL/OCSP mirror on purpose")
    return DestinationRefused(f"Refusing to connect to {where}: {why}.", host=host,
                              addresses=refused)


def _host(url: str) -> str:
    return urlsplit(url).hostname or url


# ---------------------------------------------------------------------------
# One fetch in progress: its policy and its watchdog
# ---------------------------------------------------------------------------

_active = threading.local()


def _current() -> Optional["_Fetch"]:
    return getattr(_active, "fetch", None)


def _shutdown(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


class _Fetch:
    """The request being made on this thread.

    urllib3 opens connections on the calling thread, so the connection classes below find the
    policy here. It is the only way to reach them: keyword arguments for the pools cannot carry
    it, because urllib3 builds its pool keys from a fixed list of fields.
    """

    def __init__(self, policy: OutboundPolicy):
        self.policy = policy
        self.expired = threading.Event()
        self._lock = threading.Lock()
        self._sockets: list = []
        self._timer = threading.Timer(policy.total_timeout, self._expire)
        self._timer.daemon = True

    def start(self) -> None:
        self._timer.start()

    def watch(self, sock: socket.socket) -> None:
        """Keep a duplicate of ``sock`` to shut down when time is up, until the fetch ends.

        A duplicate, because TLS wrapping detaches the original socket object, and shutting down
        either descriptor ends the connection both refer to, which unblocks a read in progress
        wherever it is waiting. Kept until the end of the fetch rather than released when the
        connection closes: http.client closes the connection as soon as a response says it will
        close (HTTP/1.0, ``Connection: close``) while the response goes on reading the body from
        the same socket, and releasing the duplicate there left exactly that read unwatched.
        """
        dup = sock.dup()
        with self._lock:
            self._sockets.append(dup)
            late = self.expired.is_set()
        if late:
            _shutdown(dup)

    def _expire(self) -> None:
        self.expired.set()
        with self._lock:
            sockets = list(self._sockets)
        for sock in sockets:
            _shutdown(sock)

    def finish(self) -> None:
        self._timer.cancel()
        with self._lock:
            sockets, self._sockets = self._sockets, []
        for sock in sockets:
            sock.close()


# ---------------------------------------------------------------------------
# Connections that vet and pin their destination
# ---------------------------------------------------------------------------

class _PolicyConnectionMixin:
    """Overrides one method of urllib3's connection: the one that makes the socket.

    Everything after it (TLS, SNI, certificate matching, the Host header) reads ``self.host``,
    which is never touched, so it all stays on the original name while the socket goes to the
    vetted address.
    """

    def _new_conn(self):
        fetch = _current()
        if fetch is None:
            raise _Refused(DestinationRefused(
                "Refusing to connect: no outbound fetch is in progress on this thread.",
                host=self.host))
        if self.proxy is not None:
            # A connection to the proxy itself. The operator named it, so it is not vetted, only
            # timed. The target was vetted in _PolicyAdapter.send.
            sock = super()._new_conn()
        else:
            sock = self._connect_vetted(fetch.policy)
        fetch.watch(sock)
        return sock

    def _connect_vetted(self, policy: OutboundPolicy):
        # The base method resolves inside create_connection, and would resolve again on every
        # retry. Here the name is resolved once, judged, and the socket goes to what was judged.
        try:
            infos = socket.getaddrinfo(self._dns_host, self.port, allowed_gai_family(),
                                       socket.SOCK_STREAM)
        except socket.gaierror as e:
            raise NameResolutionError(self.host, self, e) from e
        addresses = list(dict.fromkeys(info[4][0] for info in infos))
        refused = [a for a in addresses if not _allowed(a, policy.allow_private)]
        if refused:
            raise _Refused(_refusal(self.host, refused))

        failure: Optional[Exception] = None
        for address in addresses:
            try:
                sock = create_connection((address, self.port), self.timeout,
                                         source_address=self.source_address,
                                         socket_options=self.socket_options)
            except SocketTimeout as e:
                failure = ConnectTimeoutError(
                    self, f"Connection to {self.host} timed out. (connect timeout={self.timeout})")
                failure.__cause__ = e
            except OSError as e:
                failure = NewConnectionError(self, f"Failed to establish a new connection: {e}")
                failure.__cause__ = e
            else:
                sys.audit("http.client.connect", self, self.host, self.port)
                return sock
        if failure is None:
            raise NewConnectionError(self, f"No address to connect to for {self.host}.")
        raise failure


class _PolicyHTTPConnection(_PolicyConnectionMixin, HTTPConnection):
    pass


class _PolicyHTTPSConnection(_PolicyConnectionMixin, HTTPSConnection):
    pass


class _PolicyHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = _PolicyHTTPConnection


class _PolicyHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _PolicyHTTPSConnection


_POOL_CLASSES = {"http": _PolicyHTTPConnectionPool, "https": _PolicyHTTPSConnectionPool}


def _vet_proxied_target(url: str) -> None:
    """Through a proxy the connection never sees the target, so it is vetted here, by a local
    resolution. A name that does not resolve locally goes on, since in a network that only
    reaches out through a proxy the proxy is often the only thing that can resolve it. A name
    that resolves to a refused address does not."""
    fetch = _current()
    parts = urlsplit(url)
    host = parts.hostname
    if fetch is None or not host:
        raise _Refused(DestinationRefused(f"Refusing to connect to {url}.", host=host))
    port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        return
    addresses = list(dict.fromkeys(info[4][0] for info in infos))
    refused = [a for a in addresses if not _allowed(a, fetch.policy.allow_private)]
    if refused:
        raise _Refused(_refusal(host, refused))


class _PolicyAdapter(HTTPAdapter):
    """requests' adapter with the connection classes above, for direct and proxied traffic.

    The pool classes are replaced on each manager instance, never in urllib3's module-level
    dictionary, which every other PoolManager in the process shares.
    """

    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = dict(_POOL_CLASSES)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        manager = super().proxy_manager_for(proxy, **proxy_kwargs)
        if not proxy.lower().startswith("socks"):
            manager.pool_classes_by_scheme = dict(_POOL_CLASSES)
        return manager

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        if select_proxy(request.url, proxies or {}):
            _vet_proxied_target(request.url)
        return super().send(request, stream=stream, timeout=timeout, verify=verify, cert=cert,
                            proxies=proxies)


class _NoNetrc(AuthBase):
    """Session auth that changes nothing, and matters only by being there.

    requests reads ``~/.netrc`` when neither the request nor the session carries auth, and would
    then send its credentials, a ``default`` entry to any host, to whatever URL a document names.
    With this on the session it never looks, while an explicit ``auth=`` on a request still wins.
    """

    def __call__(self, request):
        return request


# ---------------------------------------------------------------------------
# The request
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FetchResult:
    status_code: int
    headers: CaseInsensitiveDict
    content: bytes
    url: str


# requests' own reading of these: a POST redirected by 301, 302 or 303 is retried as a GET without
# its body, and 307 or 308 keep both.
_TURN_POST_INTO_GET = (301, 302, 303)
_CHUNK = 64 * 1024


def _check_deadline(fetch: _Fetch, url: str) -> None:
    if fetch.expired.is_set():
        raise DeadlineExceeded(
            f"{_host(url)} did not finish within {fetch.policy.total_timeout:g} s, so the request "
            "was cut off.")


def _too_large(url: str, policy: OutboundPolicy) -> ResponseTooLarge:
    return ResponseTooLarge(
        f"The response from {_host(url)} exceeds the {policy.max_bytes} byte limit, so it is not "
        "read.", limit=policy.max_bytes)


def _read_body(response, fetch: _Fetch, budget: Optional[FetchBudget], url: str) -> bytes:
    policy = fetch.policy
    declared = response.headers.get("Content-Length")
    if declared is not None:
        try:
            size = int(declared)
        except ValueError:
            size = None       # http.client ignores a malformed length too, and the count caps
        if size is not None and size > policy.max_bytes:
            raise _too_large(url, policy)
    body = bytearray()
    for chunk in response.iter_content(_CHUNK):
        _check_deadline(fetch, url)
        body.extend(chunk)
        if len(body) > policy.max_bytes:
            raise _too_large(url, policy)
        if budget is not None:
            budget.charge_bytes(len(chunk))
    _check_deadline(fetch, url)
    return bytes(body)


def _send_one(session, method: str, url: str, *, headers: dict, data, auth,
              policy: OutboundPolicy):
    """One request, one response, no redirect handling of any kind.

    Straight to the adapter rather than through ``Session.request``: even with
    ``allow_redirects=False``, ``Session.send`` runs its redirect generator once to fill in
    ``Response.next``, and that generator reads a 3xx body whole, into memory, to release the
    connection. Measured: a 302 declaring a gigabyte held the request until the server stopped
    sending. The session still prepares the request (its headers, and its auth, which is what
    keeps ~/.netrc out), and the environment still decides proxies, NO_PROXY and the CA bundle,
    worked out again for each URL.
    """
    prepared = session.prepare_request(
        requests.Request(method, url, headers=headers, data=data, auth=auth))
    settings = session.merge_environment_settings(prepared.url, {}, True, None, None)
    return session.get_adapter(prepared.url).send(
        prepared, stream=True, timeout=(policy.connect_timeout, policy.read_timeout),
        verify=settings["verify"], cert=settings["cert"], proxies=settings["proxies"])


def _hops(session, fetch: _Fetch, method: str, url: str, *, headers: dict, data, auth,
          expect_content_type: Optional[str], budget: Optional[FetchBudget]) -> FetchResult:
    policy = fetch.policy
    if urlsplit(url).scheme.lower() not in ("http", "https"):
        raise OutboundError(f"Only http and https URLs are fetched, not {url}.")
    followed = 0
    while True:
        if budget is not None:
            budget.charge_fetch(url)
        response = _send_one(session, method, url, headers=headers, data=data, auth=auth,
                             policy=policy)
        try:
            _check_deadline(fetch, url)
            target = session.get_redirect_target(response)
            if target is not None:
                if followed >= policy.max_redirects:
                    raise RedirectRefused(
                        f"{_host(url)} answered {response.status_code}, a redirect to {target}, "
                        + ("which is not followed here." if not policy.max_redirects
                           else f"past the {policy.max_redirects} redirects followed here."),
                        status_code=response.status_code)
                next_url = urljoin(response.url or url, target)
                if urlsplit(next_url).scheme.lower() not in ("http", "https"):
                    raise RedirectRefused(
                        f"{_host(url)} redirected to {next_url}, and only http and https are "
                        "followed.", status_code=response.status_code)
                if (response.status_code in _TURN_POST_INTO_GET
                        and method.upper() not in ("GET", "HEAD")):
                    method, data = "GET", None
                    headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}
                # The redirect's own body is never read (see _send_one): closing it unread throws
                # the connection away instead of draining it.
                url = next_url
                followed += 1
                continue
            if expect_content_type is not None:
                got = response.headers.get("Content-Type")
                if got != expect_content_type:
                    raise UnexpectedContentType(
                        f"{_host(url)} answered with Content-Type {got!r}, not "
                        f"{expect_content_type!r}.", content_type=got)
            content = _read_body(response, fetch, budget, url)
            return FetchResult(response.status_code, response.headers, content,
                               response.url or url)
        finally:
            response.close()


def fetch(method: str, url: str, *, policy: OutboundPolicy, headers: Optional[dict] = None,
          data=None, auth=None, expect_content_type: Optional[str] = None,
          budget: Optional[FetchBudget] = None) -> FetchResult:
    """Make one request under ``policy`` and return its final response, read whole.

    A Session per call, closed at the end: certvalidator runs its fetches concurrently in worker
    threads, and a Session is not safe to share between them. Redirects are followed by hand,
    each hop a new request through the same vetted connections. ``auth`` is refused together with
    a policy that follows redirects, since credentials are never sent where a redirect points.
    ``expect_content_type`` is checked before the body is read. Anything the policy refuses, or a
    limit it enforces, is an ``OutboundError``, and anything else is what requests raised.
    """
    if auth is not None and policy.max_redirects:
        raise ValueError(
            "credentials are never sent where a redirect points: pass auth only with a policy "
            "that follows no redirects")
    current = _Fetch(policy)
    previous = _current()
    _active.fetch = current
    current.start()
    try:
        with requests.Session() as session:
            session.auth = _NoNetrc()
            adapter = _PolicyAdapter()
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            return _hops(session, current, method, url, headers=dict(headers or {}), data=data,
                         auth=auth, expect_content_type=expect_content_type, budget=budget)
    except _Refused as exc:
        raise exc.refusal from None
    except OutboundError:
        raise
    except (requests.RequestException, OSError) as exc:
        # What the watchdog's shutdown looks like from inside requests: a connection reset, a
        # truncated body, a handshake that failed. Named for what it was.
        if current.expired.is_set():
            raise DeadlineExceeded(
                f"{_host(url)} did not finish within {policy.total_timeout:g} s, so the request "
                "was cut off.") from exc
        raise
    finally:
        current.finish()
        _active.fetch = previous

