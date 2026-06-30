"""Offline tests for the trust-anchor download logic (multi-source + retry + progress).

No network: `_download` / `urlopen` / `time.sleep` are monkeypatched. These cover the
resilience added because the official MI intermediate URL is decommissioned (HTTP 501) and
the crt.sh fallback flakes with transient 5xx / timeouts.
"""

import datetime
import email.message
import urllib.error

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from cedula_uy_pdf_sign import national_ca


class _FakeResp:
    def __init__(self, data):
        self._data = data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, amt=None):
        return self._data if amt is None else self._data[:amt]


def _httperror(code, retry_after=None):
    hdrs = email.message.Message()
    if retry_after is not None:
        hdrs["Retry-After"] = retry_after
    return urllib.error.HTTPError("https://example/x", code, "err", hdrs, None)


# --- _download_first: source fallback ---------------------------------------

def test_download_first_uses_first_working_source(monkeypatch):
    calls = []

    def fake_download(url, timeout=30, on_retry=None):
        calls.append(url)
        return b"ROOT-OK"

    monkeypatch.setattr(national_ca, "_download", fake_download)
    assert national_ca._download_first(("https://a", "https://b")) == b"ROOT-OK"
    assert calls == ["https://a"]  # second source never tried


def test_download_first_falls_back_on_failure(monkeypatch):
    calls = []

    def fake_download(url, timeout=30, on_retry=None):
        calls.append(url)
        if "minterior" in url:
            raise _httperror(501)
        return b"MICA-OK"

    monkeypatch.setattr(national_ca, "_download", fake_download)
    data = national_ca._download_first(national_ca.MICA_URLS)
    assert data == b"MICA-OK"
    assert calls == list(national_ca.MICA_URLS[:2])  # official tried, then crt.sh


def test_download_first_reports_source_fallback(monkeypatch):
    def fake_download(url, timeout=30, on_retry=None):
        if "minterior" in url:
            raise _httperror(501)
        return b"OK"

    monkeypatch.setattr(national_ca, "_download", fake_download)
    switches = []
    data = national_ca._download_first(
        national_ca.MICA_URLS, on_source_fail=lambda *a: switches.append(a)
    )
    assert data == b"OK"
    assert len(switches) == 1
    failed, nxt, exc = switches[0]
    assert "minterior" in failed and "crt.sh" in nxt


def test_download_first_raises_when_all_sources_fail(monkeypatch):
    def fake_download(url, timeout=30, on_retry=None):
        raise OSError("network down")

    monkeypatch.setattr(national_ca, "_download", fake_download)
    with pytest.raises(RuntimeError, match="any source"):
        national_ca._download_first(("https://a", "https://b"))


# --- _download: retry on transient failures ---------------------------------

def test_download_retries_transient_then_succeeds(monkeypatch):
    monkeypatch.setattr(national_ca.time, "sleep", lambda _s: None)  # no real delay
    attempts = {"n": 0}

    def fake_urlopen(req, timeout=30):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise _httperror(502)
        return _FakeResp(b"CERT")

    monkeypatch.setattr(national_ca.urllib.request, "urlopen", fake_urlopen)
    assert national_ca._download("https://crt.sh/?d=1") == b"CERT"
    assert attempts["n"] == 3


def test_download_does_not_retry_non_transient(monkeypatch):
    monkeypatch.setattr(national_ca.time, "sleep", lambda _s: None)
    attempts = {"n": 0}

    def fake_urlopen(req, timeout=30):
        attempts["n"] += 1
        raise _httperror(501)

    monkeypatch.setattr(national_ca.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(urllib.error.HTTPError):
        national_ca._download("https://ca.minterior.gub.uy/certificados/MICA.cer")
    assert attempts["n"] == 1  # 501 fails fast, no retry


def test_download_invokes_on_retry_and_honours_retry_after(monkeypatch):
    monkeypatch.setattr(national_ca.time, "sleep", lambda _s: None)
    seq = [502, 503, None]  # fail, fail, then succeed

    def fake_urlopen(req, timeout=30):
        code = seq.pop(0)
        if code is not None:
            raise _httperror(code, retry_after="2")
        return _FakeResp(b"CERT")

    monkeypatch.setattr(national_ca.urllib.request, "urlopen", fake_urlopen)
    notes = []
    data = national_ca._download("https://crt.sh/?d=1", on_retry=lambda *a: notes.append(a))
    assert data == b"CERT"
    assert len(notes) == 2  # one before each of the two waits
    url, attempt, total, exc, delay = notes[0]
    assert attempt == 1 and total == national_ca._RETRIES
    assert delay == 2.0  # Retry-After header honoured over backoff


def test_download_caps_oversized_response(monkeypatch):
    # A (pinned) host returning a huge body must be refused, not read into memory unbounded.
    monkeypatch.setattr(national_ca.time, "sleep", lambda _s: None)
    big = b"x" * (national_ca._MAX_DOWNLOAD_BYTES + 10)
    monkeypatch.setattr(national_ca.urllib.request, "urlopen",
                        lambda req, timeout=30: _FakeResp(big))
    with pytest.raises(RuntimeError, match="more than"):
        national_ca._download("https://crt.sh/?d=1")


def test_download_accepts_response_at_the_cap(monkeypatch):
    # A normal small certificate (well under the cap) is returned unchanged.
    monkeypatch.setattr(national_ca.urllib.request, "urlopen",
                        lambda req, timeout=30: _FakeResp(b"CERT-BYTES"))
    assert national_ca._download("https://crt.sh/?d=1") == b"CERT-BYTES"


# --- _retry_after_seconds parsing -------------------------------------------

@pytest.mark.parametrize("value,expected", [
    ("5", 5.0),
    ("0", 0.0),
    ("999", national_ca._MAX_RETRY_AFTER),          # capped
    ("-3", None),                                   # negative ignored
    ("Wed, 21 Oct 2015 07:28:00 GMT", None),        # HTTP-date form not honoured
    (None, None),                                   # header absent
])
def test_retry_after_seconds(value, expected):
    assert national_ca._retry_after_seconds(_httperror(503, retry_after=value)) == expected


def test_backoff_delay_is_bounded_and_grows():
    # Exponential with jitter, capped. Lower bounds grow; never exceeds cap + jitter.
    assert national_ca._backoff_delay(0) >= national_ca._BACKOFF_BASE
    assert national_ca._backoff_delay(1) >= national_ca._BACKOFF_BASE * 2
    assert national_ca._backoff_delay(20) <= national_ca._BACKOFF_CAP + 0.5  # capped


# --- --from-file: seeding the cache from local certs ------------------------

def _make_chain():
    """Return (root, intermediate) where the intermediate is signed by the root key."""
    now = datetime.datetime.now(datetime.timezone.utc)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TEST ROOT")])
    root = (
        x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
        .public_key(root_key.public_key()).serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    int_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    int_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TEST INTERMEDIATE")])
    intermediate = (
        x509.CertificateBuilder().subject_name(int_name).issuer_name(root_name)
        .public_key(int_key.public_key()).serial_number(2)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(root_key, hashes.SHA256())  # signed by the ROOT key
    )
    return root, intermediate


def test_certs_from_files_parses_bundle(tmp_path):
    root, intermediate = _make_chain()
    bundle = tmp_path / "cas.pem"
    bundle.write_bytes(root.public_bytes(Encoding.PEM) + intermediate.public_bytes(Encoding.PEM))
    found = national_ca._certs_from_files([bundle])
    assert national_ca._fingerprint(root) in found
    assert national_ca._fingerprint(intermediate) in found
    assert len(found) == 2


def test_certs_from_files_rejects_non_certificate(tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_bytes(b"this is not a certificate")
    with pytest.raises(RuntimeError, match="not a PEM/DER"):
        national_ca._certs_from_files([bad])


def test_fetch_cas_from_files_uses_supplied_certs_without_network(tmp_path, monkeypatch):
    root, intermediate = _make_chain()
    bundle = tmp_path / "cas.pem"
    bundle.write_bytes(root.public_bytes(Encoding.PEM) + intermediate.public_bytes(Encoding.PEM))

    # Pin to the generated certs so fetch_cas accepts them.
    monkeypatch.setattr(national_ca, "ACRN_SHA256", national_ca._fingerprint(root))
    monkeypatch.setattr(national_ca, "MICA_SHA256", national_ca._fingerprint(intermediate))
    # Any network access would be a bug when both certs are supplied.
    def _no_network(*a, **k):
        raise AssertionError("network used despite both certs supplied via --from-file")
    monkeypatch.setattr(national_ca, "_download", _no_network)
    monkeypatch.setattr(national_ca, "_download_first", _no_network)
    # Redirect the cache to a temp dir.
    monkeypatch.setattr(national_ca, "cache_dir", lambda: tmp_path / "cache")

    acrn_path, mica_path = national_ca.fetch_cas(source_files=[bundle])
    assert acrn_path.exists() and mica_path.exists()
    cached_mica = x509.load_pem_x509_certificate(mica_path.read_bytes())
    assert national_ca._fingerprint(cached_mica) == national_ca._fingerprint(intermediate)


# --- bundled trust anchors --------------------------------------------------

def test_bundled_trust_anchors_match_pins():
    roots, intermediates = national_ca.load_bundled_trust_anchors()
    assert len(roots) == 1 and len(intermediates) == 1
    assert national_ca._fingerprint(roots[0]) == national_ca.ACRN_SHA256
    assert national_ca._fingerprint(intermediates[0]) == national_ca.MICA_SHA256
    assert "Ministerio del Interior" in intermediates[0].subject.rfc4514_string()
    assert "Raíz Nacional" in roots[0].subject.rfc4514_string()


def test_bundled_cert_rejects_wrong_fingerprint_or_missing():
    # Real bundled file but the wrong expected fingerprint -> rejected.
    assert national_ca._bundled_cert("acrn.pem", "00" * 32) is None
    # Missing file -> None (not an error).
    assert national_ca._bundled_cert("does-not-exist.pem", national_ca.ACRN_SHA256) is None


# --- cached trust anchors: graceful degradation -----------------------------

def _seed_cache(monkeypatch, tmp_path, root, mica):
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "acrn.pem").write_bytes(root.public_bytes(Encoding.PEM))
    (cache / "mica.pem").write_bytes(mica.public_bytes(Encoding.PEM))
    monkeypatch.setattr(national_ca, "cache_dir", lambda: cache)
    monkeypatch.setattr(national_ca, "ACRN_SHA256", national_ca._fingerprint(root))
    monkeypatch.setattr(national_ca, "MICA_SHA256", national_ca._fingerprint(mica))
    return cache


def test_load_cached_trust_anchors_valid(tmp_path, monkeypatch):
    root, mica = _make_chain()
    _seed_cache(monkeypatch, tmp_path, root, mica)
    roots, inter = national_ca.load_cached_trust_anchors()
    assert national_ca._fingerprint(roots[0]) == national_ca.ACRN_SHA256
    assert national_ca._fingerprint(inter[0]) == national_ca.MICA_SHA256


def test_load_cached_trust_anchors_corrupt_returns_empty(tmp_path, monkeypatch):
    root, mica = _make_chain()
    cache = _seed_cache(monkeypatch, tmp_path, root, mica)
    (cache / "acrn.pem").write_bytes(b"not a certificate")  # corrupt PEM
    assert national_ca.load_cached_trust_anchors() == ([], [])  # graceful, no raise


def test_load_cached_trust_anchors_wrong_fingerprint_returns_empty(tmp_path, monkeypatch):
    root, mica = _make_chain()
    cache = _seed_cache(monkeypatch, tmp_path, root, mica)
    other_root, _ = _make_chain()
    (cache / "mica.pem").write_bytes(other_root.public_bytes(Encoding.PEM))  # pin no longer matches
    assert national_ca.load_cached_trust_anchors() == ([], [])


def test_load_cached_trust_anchors_missing_mica_returns_empty(tmp_path, monkeypatch):
    root, mica = _make_chain()
    cache = _seed_cache(monkeypatch, tmp_path, root, mica)
    (cache / "mica.pem").unlink()
    assert national_ca.load_cached_trust_anchors() == ([], [])
