# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Uruguayan national PKI trust anchors for verification.

The package bundles the **public** national CA certificates (the AGESIC root + the Ministerio
del Interior intermediate) under ``data/``, so chain validation works offline out of the box;
see ``data/PROVENANCE.md``. Every certificate on the *national-CA path* (bundled, cached,
downloaded, or seeded via ``--from-file``) is matched against a pinned SHA-256 fingerprint (and
the intermediate is checked to be signed by the root), so the origin of those bytes never
matters: a wrong or tampered certificate is rejected. (``--ca-file`` is the separate case where
the user supplies their *own* trust anchors for verification; those are intentionally not
pinned, since the whole point is to trust a set the user chose.)

``fetch_cas()`` refreshes a per-user cache from public sources (with a Certificate Transparency
fallback, since the MI's own repository ``ca.minterior.gub.uy`` has been decommissioned and now
returns HTTP 501). The bundled copies are the built-in fallback used when there is no cache and
no ``--ca-file``.
"""

import hashlib
import importlib.resources
import os
import random
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding

# Called with a human-readable status line while fetching (retry / source fallback).
Progress = Callable[[str], None]

# Pinned SHA-256 of each certificate (DER) -- fingerprints, not the certificates.
ACRN_SHA256 = "5533a0401f612c688ebce5bf53f2ec14a734eb178bfae00e50e85dae6723078a"
MICA_SHA256 = "a29cad5c89aa49cff81f17f45c42fd44685510246d9ab5d031448e2fda2517be"

# AC Raíz Nacional (AGESIC).
ACRN_URL = "https://www.uce.gub.uy/acrn/acrn.cer"

# AC Ministerio del Interior (intermediate), tried in order. The official MI repository
# is decommissioned (HTTP 501), so the byte-identical CT-log copy on crt.sh is the
# working fallback; the pinned fingerprint above guards both.
MICA_URLS = (
    "https://ca.minterior.gub.uy/certificados/MICA.cer",  # official (currently HTTP 501)
    "https://crt.sh/?d=29172099",                          # Certificate Transparency mirror
)

# crt.sh sits behind Cloudflare, which drops a bare "firmauy" token but accepts a
# descriptive bot-style User-Agent with a contact URL (which the official server allows too).
_USER_AGENT = "firmauy (+https://pypi.org/project/cedula-uy-pdf-sign)"


def cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "firmauy" / "national-ca"


def _load_cert(data: bytes) -> x509.Certificate:
    try:
        return x509.load_der_x509_certificate(data)
    except ValueError:
        return x509.load_pem_x509_certificate(data)


def _fingerprint(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()


def _certs_from_files(paths: Optional[list]) -> dict:
    """Map sha256(DER) -> certificate for every cert found in the given PEM/DER files.

    Used to seed `fetch_cas` from local files: a supplied cert is only ever used if its
    fingerprint matches a pin, so a wrong file simply falls through to downloading.
    """
    found: dict = {}
    for p in paths or []:
        path = Path(p)
        data = path.read_bytes()
        certs: list = []
        try:
            certs = list(x509.load_pem_x509_certificates(data))
        except Exception:
            certs = []
        if not certs:
            try:
                certs = [x509.load_der_x509_certificate(data)]
            except Exception as exc:
                raise RuntimeError(f"--from-file '{path}' is not a PEM/DER certificate: {exc}")
        for c in certs:
            found[_fingerprint(c)] = c
    return found


# Transport-level retry. crt.sh sits behind Cloudflare and flakes with intermittent
# 5xx / connection resets / timeouts, so transient failures are retried with exponential
# backoff + jitter (honouring a Retry-After header when the server sends one). 501 (the
# decommissioned MI server) is a permanent "not served": it is not retried, so we fall
# through to the next source at once.
_RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})
_RETRIES = 4
_BACKOFF_BASE = 1.0       # seconds; doubles each attempt
_BACKOFF_CAP = 10.0       # seconds; max single wait from backoff
_MAX_RETRY_AFTER = 30.0   # cap an over-large Retry-After
_MAX_DOWNLOAD_BYTES = 1024 * 1024   # 1 MiB; a CA certificate is a few KB, so this is ample and
                                    # bounds memory if a (pinned) host misbehaves or is compromised.

# Called before each retry wait: (url, attempt, total_attempts, exception, wait_seconds).
RetryHook = Callable[[str, int, int, Exception, float], None]
# Called when a source is exhausted and the next is tried: (failed_url, next_url, exception).
SourceFailHook = Callable[[str, str, Exception], None]


def _retry_after_seconds(exc: urllib.error.HTTPError) -> Optional[float]:
    """Delta-seconds from a Retry-After header, if present and sane. The HTTP-date form is
    not honoured (returns None, falling back to backoff)."""
    try:
        raw = exc.headers.get("Retry-After") if exc.headers else None
    except Exception:
        return None
    if not raw:
        return None
    try:
        secs = float(str(raw).strip())
    except (TypeError, ValueError):
        return None
    return min(secs, _MAX_RETRY_AFTER) if secs >= 0 else None


def _backoff_delay(attempt: int) -> float:
    """Exponential backoff (~1, 2, 4, 8 … capped) plus up to 0.5s of jitter."""
    base = min(_BACKOFF_CAP, _BACKOFF_BASE * (2 ** attempt))
    return base + random.uniform(0.0, 0.5)


def _download(
    url: str,
    timeout: int = 30,
    retries: int = _RETRIES,
    on_retry: Optional[RetryHook] = None,
) -> bytes:
    """Download `url`, retrying transient failures with exponential backoff (and a server
    Retry-After when offered). Non-retryable HTTP errors (e.g. 404/501) raise immediately.
    `on_retry` is invoked just before each wait."""
    last_exc: Exception = RuntimeError("no attempt made")
    for attempt in range(retries):
        retry_after: Optional[float] = None
        try:
            req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (pinned by fingerprint)
                data = resp.read(_MAX_DOWNLOAD_BYTES + 1)
                if len(data) > _MAX_DOWNLOAD_BYTES:
                    raise RuntimeError(
                        f"{_host(url)} returned more than {_MAX_DOWNLOAD_BYTES} bytes for a "
                        "certificate; refusing (a CA certificate is only a few KB)."
                    )
                return data
        except urllib.error.HTTPError as exc:
            last_exc = exc
            if exc.code not in _RETRYABLE_STATUS:
                raise
            retry_after = _retry_after_seconds(exc)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_exc = exc
        if attempt < retries - 1:
            delay = retry_after if retry_after is not None else _backoff_delay(attempt)
            if on_retry is not None:
                on_retry(url, attempt + 1, retries, last_exc, delay)
            time.sleep(delay)
    raise last_exc


def _download_first(
    urls: tuple[str, ...],
    timeout: int = 30,
    on_retry: Optional[RetryHook] = None,
    on_source_fail: Optional[SourceFailHook] = None,
) -> bytes:
    """Download from the first URL that responds; raise if all of them fail.

    Safe to try multiple sources because the caller pins the certificate fingerprint:
    the bytes are accepted only if they hash to the expected value.
    """
    errors = []
    for i, url in enumerate(urls):
        try:
            return _download(url, timeout=timeout, on_retry=on_retry)
        except Exception as exc:  # noqa: BLE001 (collect and report all source failures)
            errors.append(f"  {url}: {type(exc).__name__}: {exc}")
            if on_source_fail is not None and i + 1 < len(urls):
                on_source_fail(url, urls[i + 1], exc)
    raise RuntimeError("Could not download the certificate from any source:\n" + "\n".join(errors))


def _host(url: str) -> str:
    return urlparse(url).hostname or url


def _short_error(exc: Exception) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code}"
    if isinstance(exc, TimeoutError):
        return "timed out"
    if isinstance(exc, urllib.error.URLError):
        return f"{type(exc).__name__}: {exc.reason}"
    return type(exc).__name__


def fetch_cas(
    progress: Optional[Progress] = None,
    source_files: Optional[list] = None,
) -> tuple[Path, Path]:
    """Obtain root + intermediate, verify each against its pinned fingerprint (and the
    intermediate against the root), and cache them. Returns (acrn_path, mica_path).
    Raises on fingerprint mismatch.

    Certificates whose fingerprint matches a pin are taken from ``source_files`` (PEM/DER)
    when supplied; whatever is not provided there is downloaded. This lets a user seed the
    cache offline when a source is unreachable (e.g. the decommissioned MI server). The
    fingerprint pin makes the origin irrelevant. ``progress``, if given, receives
    human-readable status lines as sources are used, retried or fall back."""
    local = _certs_from_files(source_files)

    def _note(msg: str) -> None:
        if progress:
            progress(msg)

    def on_retry(url: str, attempt: int, total: int, exc: Exception, delay: float) -> None:
        _note(f"{_host(url)}: attempt {attempt}/{total} failed "
              f"({_short_error(exc)}); retrying in {delay:.1f}s…")

    def on_source_fail(failed: str, nxt: str, exc: Exception) -> None:
        _note(f"{_host(failed)} unavailable ({_short_error(exc)}); "
              f"falling back to {_host(nxt)}…")

    if ACRN_SHA256 in local:
        acrn = local[ACRN_SHA256]
        _note("national root: using supplied file (fingerprint matches the pin)")
    else:
        acrn = _load_cert(_download(ACRN_URL, on_retry=on_retry))
    got = _fingerprint(acrn)
    if got != ACRN_SHA256:
        raise RuntimeError(
            "National root fingerprint mismatch; refusing to cache.\n"
            f"  expected {ACRN_SHA256}\n  got      {got}\n"
            "The pinned fingerprint may be outdated or the download was tampered."
        )

    if MICA_SHA256 in local:
        mica = local[MICA_SHA256]
        _note("Ministerio del Interior intermediate: using supplied file (fingerprint matches the pin)")
    else:
        if source_files:
            _note("supplied file(s) did not contain the pinned MI intermediate; downloading…")
        mica = _load_cert(_download_first(MICA_URLS, on_retry=on_retry, on_source_fail=on_source_fail))
    got_mica = _fingerprint(mica)
    if got_mica != MICA_SHA256:
        raise RuntimeError(
            "Intermediate (Ministerio del Interior) fingerprint mismatch; refusing to cache.\n"
            f"  expected {MICA_SHA256}\n  got      {got_mica}\n"
            "The pinned fingerprint may be outdated or the download was tampered."
        )
    try:
        acrn.public_key().verify(
            mica.signature, mica.tbs_certificate_bytes,
            padding.PKCS1v15(), mica.signature_hash_algorithm,
        )
    except Exception as exc:
        raise RuntimeError(f"Intermediate is not signed by the national root: {exc}")

    d = cache_dir()
    d.mkdir(parents=True, exist_ok=True)
    acrn_path = d / "acrn.pem"
    mica_path = d / "mica.pem"
    acrn_path.write_bytes(acrn.public_bytes(Encoding.PEM))
    mica_path.write_bytes(mica.public_bytes(Encoding.PEM))
    return acrn_path, mica_path


def _bundled_cert(filename: str, expected_fp: str) -> Optional[x509.Certificate]:
    """Load a certificate shipped under ``data/``, returning it only if it matches the pin."""
    try:
        data = (importlib.resources.files("cedula_uy_pdf_sign") / "data" / filename).read_bytes()
        cert = _load_cert(data)
    except Exception:
        return None
    return cert if _fingerprint(cert) == expected_fp else None


def load_bundled_trust_anchors() -> tuple[list, list]:
    """Return (roots, intermediates) bundled with the package: the public national CA certs,
    each re-checked against its pinned fingerprint. Returns ([], []) if the bundled root is
    missing or fails the pin. Used as the built-in fallback so verification works offline."""
    root = _bundled_cert("acrn.pem", ACRN_SHA256)
    if root is None:
        return [], []
    mica = _bundled_cert("mica.pem", MICA_SHA256)
    return [root], ([mica] if mica is not None else [])


def load_cached_trust_anchors() -> tuple[list, list]:
    """Return (roots, intermediates) from the local cache, re-checking **both** pinned
    fingerprints. Returns ([], []) if the cache is missing, incomplete, unreadable or fails a
    pin, so callers fall back to the bundled anchors instead of failing."""
    d = cache_dir()
    acrn_path = d / "acrn.pem"
    mica_path = d / "mica.pem"
    if not (acrn_path.exists() and mica_path.exists()):
        return [], []
    try:
        acrn = x509.load_pem_x509_certificate(acrn_path.read_bytes())
        mica = x509.load_pem_x509_certificate(mica_path.read_bytes())
    except Exception:
        return [], []  # corrupt cache -> treat as absent
    if _fingerprint(acrn) != ACRN_SHA256 or _fingerprint(mica) != MICA_SHA256:
        return [], []  # tampered/outdated -> treat as absent
    return [acrn], [mica]
