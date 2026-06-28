# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Uruguayan national PKI trust anchors for verification (fetch + pin, not bundled).

The state CA certificates are NOT redistributed with this package. Only the expected
SHA-256 fingerprint of the national root is pinned here (a hash, not the certificate).
`fetch_cas()` downloads the certificates from the official sources, verifies the root
against the pinned fingerprint, and caches them per user. Verification then uses the
cached certificates, or a user-supplied bundle (``--ca-file``).
"""

import hashlib
import os
import urllib.request
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding

# Pinned SHA-256 of the national root certificate (DER) -- a fingerprint, not the cert.
ACRN_SHA256 = "5533a0401f612c688ebce5bf53f2ec14a734eb178bfae00e50e85dae6723078a"

# Official sources.
ACRN_URL = "https://www.uce.gub.uy/acrn/acrn.cer"               # AC Raíz Nacional (AGESIC)
MICA_URL = "https://ca.minterior.gub.uy/certificados/MICA.cer"  # AC Ministerio del Interior


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


def _download(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "firmauy"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (official HTTPS source)
        return resp.read()


def fetch_cas() -> tuple[Path, Path]:
    """Download root + intermediate from official sources, verify the root against the
    pinned fingerprint and the intermediate against the root, and cache them.
    Returns (acrn_path, mica_path). Raises on fingerprint mismatch."""
    acrn = _load_cert(_download(ACRN_URL))
    got = _fingerprint(acrn)
    if got != ACRN_SHA256:
        raise RuntimeError(
            "National root fingerprint mismatch; refusing to cache.\n"
            f"  expected {ACRN_SHA256}\n  got      {got}\n"
            "The pinned fingerprint may be outdated or the download was tampered."
        )

    mica = _load_cert(_download(MICA_URL))
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
