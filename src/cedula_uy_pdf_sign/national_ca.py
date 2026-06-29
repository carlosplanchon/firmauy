# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Uruguayan national PKI trust anchors for verification (fetch + pin, not bundled).

The state CA certificates are NOT redistributed with this package. Only the expected
SHA-256 fingerprints of the national root and the Ministerio del Interior intermediate
are pinned here (hashes, not the certificates). `fetch_cas()` downloads the certificates
from public sources, verifies each against its pinned fingerprint, and caches them per
user. Verification then uses the cached certificates, or a user-supplied bundle
(``--ca-file``).

Because every certificate is matched against a pinned fingerprint (and the intermediate
is additionally checked to be signed by the pinned root), the trustworthiness of the
download source does not matter — a wrong or tampered byte stream is rejected. This lets
the intermediate fall back to a Certificate Transparency mirror (crt.sh), since the MI's
own repository (``ca.minterior.gub.uy``) has been decommissioned and now returns HTTP 501.
"""

import hashlib
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding

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


# HTTP statuses worth retrying (transient). 501 (the decommissioned MI server) is NOT
# here: it is a permanent "not served", so we fail fast and move to the next source.
_RETRYABLE_STATUS = frozenset({408, 429, 500, 502, 503, 504})
_RETRIES = 3


def _download(url: str, timeout: int = 30, retries: int = _RETRIES) -> bytes:
    """Download `url`, retrying transient failures (crt.sh behind Cloudflare flakes with
    intermittent 5xx / timeouts). Non-retryable HTTP errors (e.g. 404/501) raise at once."""
    last_exc: Exception = RuntimeError("no attempt made")
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (pinned by fingerprint)
                return resp.read()
        except urllib.error.HTTPError as exc:
            last_exc = exc
            if exc.code not in _RETRYABLE_STATUS:
                raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_exc = exc
        if attempt < retries - 1:
            time.sleep(1.5 * (attempt + 1))
    raise last_exc


def _download_first(urls: tuple[str, ...], timeout: int = 30) -> bytes:
    """Download from the first URL that responds; raise if all of them fail.

    Safe to try multiple sources because the caller pins the certificate fingerprint:
    the bytes are accepted only if they hash to the expected value.
    """
    errors = []
    for url in urls:
        try:
            return _download(url, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 (collect and report all source failures)
            errors.append(f"  {url}: {type(exc).__name__}: {exc}")
    raise RuntimeError("Could not download the certificate from any source:\n" + "\n".join(errors))


def fetch_cas() -> tuple[Path, Path]:
    """Download root + intermediate, verify each against its pinned fingerprint (and the
    intermediate against the root), and cache them. Returns (acrn_path, mica_path).
    Raises on fingerprint mismatch."""
    acrn = _load_cert(_download(ACRN_URL))
    got = _fingerprint(acrn)
    if got != ACRN_SHA256:
        raise RuntimeError(
            "National root fingerprint mismatch; refusing to cache.\n"
            f"  expected {ACRN_SHA256}\n  got      {got}\n"
            "The pinned fingerprint may be outdated or the download was tampered."
        )

    mica = _load_cert(_download_first(MICA_URLS))
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


def load_cached_trust_anchors() -> tuple[list, list]:
    """Return (roots, intermediates) from the local cache, re-checking the pinned
    fingerprint of the root. Returns ([], []) if the cache is empty or fails the pin."""
    d = cache_dir()
    acrn_path = d / "acrn.pem"
    if not acrn_path.exists():
        return [], []
    acrn = x509.load_pem_x509_certificate(acrn_path.read_bytes())
    if _fingerprint(acrn) != ACRN_SHA256:
        return [], []  # cache tampered/outdated -> treat as absent
    intermediates = []
    mica_path = d / "mica.pem"
    if mica_path.exists():
        intermediates.append(x509.load_pem_x509_certificate(mica_path.read_bytes()))
    return [acrn], intermediates
