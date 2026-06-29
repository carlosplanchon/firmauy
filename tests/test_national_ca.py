"""Offline tests for the trust-anchor download logic (multi-source + retry).

No network: `_download` / `urlopen` are monkeypatched. These cover the resilience added
because the official MI intermediate URL is decommissioned (HTTP 501) and the crt.sh
fallback flakes with transient 5xx / timeouts.
"""

import urllib.error

import pytest

from cedula_uy_pdf_sign import national_ca


# --- _download_first: source fallback ---------------------------------------

def test_download_first_uses_first_working_source(monkeypatch):
    calls = []

    def fake_download(url, timeout=30):
        calls.append(url)
        return b"ROOT-OK"

    monkeypatch.setattr(national_ca, "_download", fake_download)
    assert national_ca._download_first(("https://a", "https://b")) == b"ROOT-OK"
    assert calls == ["https://a"]  # second source never tried


def test_download_first_falls_back_on_failure(monkeypatch):
    calls = []

    def fake_download(url, timeout=30):
        calls.append(url)
        if "minterior" in url:
            raise urllib.error.HTTPError(url, 501, "Not Implemented", {}, None)
        return b"MICA-OK"

    monkeypatch.setattr(national_ca, "_download", fake_download)
    data = national_ca._download_first(national_ca.MICA_URLS)
    assert data == b"MICA-OK"
    assert calls == list(national_ca.MICA_URLS[:2])  # official tried, then crt.sh


def test_download_first_raises_when_all_sources_fail(monkeypatch):
    def fake_download(url, timeout=30):
        raise OSError("network down")

    monkeypatch.setattr(national_ca, "_download", fake_download)
    with pytest.raises(RuntimeError, match="any source"):
        national_ca._download_first(("https://a", "https://b"))


# --- _download: retry on transient failures ---------------------------------

class _FakeResp:
    def __init__(self, data):
        self._data = data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._data


def test_download_retries_transient_then_succeeds(monkeypatch):
    monkeypatch.setattr(national_ca.time, "sleep", lambda _s: None)  # no real delay
    attempts = {"n": 0}

    def fake_urlopen(req, timeout=30):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise urllib.error.HTTPError(req.full_url, 502, "Bad Gateway", {}, None)
        return _FakeResp(b"CERT")

    monkeypatch.setattr(national_ca.urllib.request, "urlopen", fake_urlopen)
    assert national_ca._download("https://crt.sh/?d=1") == b"CERT"
    assert attempts["n"] == 3


def test_download_does_not_retry_non_transient(monkeypatch):
    monkeypatch.setattr(national_ca.time, "sleep", lambda _s: None)
    attempts = {"n": 0}

    def fake_urlopen(req, timeout=30):
        attempts["n"] += 1
        raise urllib.error.HTTPError(req.full_url, 501, "Not Implemented", {}, None)

    monkeypatch.setattr(national_ca.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(urllib.error.HTTPError):
        national_ca._download("https://ca.minterior.gub.uy/certificados/MICA.cer")
    assert attempts["n"] == 1  # 501 fails fast, no retry
