"""Unit tests for TSA timestamper construction with auth (cli._build_timestamper)."""

import pytest
import typer
from pyhanko.sign.timestamps import HTTPTimeStamper

from cedula_uy_pdf_sign.cli import _build_timestamper


def _b(**kw):
    kw.setdefault("tsa_url", None)
    kw.setdefault("tsa_user", None)
    kw.setdefault("tsa_pass_env", None)
    kw.setdefault("tsa_header", None)
    return _build_timestamper(**kw)


def test_none_without_url():
    assert _b() is None


def test_auth_options_require_url():
    with pytest.raises(typer.BadParameter, match="require --tsa-url"):
        _b(tsa_user="u")
    with pytest.raises(typer.BadParameter, match="require --tsa-url"):
        _b(tsa_header=["X: y"])


def test_url_only_no_auth():
    ts = _b(tsa_url="https://tsa.example/tsr")
    assert isinstance(ts, HTTPTimeStamper)
    assert ts.auth is None and ts.headers is None


def test_basic_auth(monkeypatch):
    monkeypatch.setenv("MY_TSA_PW", "s3cret")
    ts = _b(tsa_url="https://t", tsa_user="alice", tsa_pass_env="MY_TSA_PW")
    assert ts.auth == ("alice", "s3cret")


def test_user_without_passenv_raises():
    with pytest.raises(typer.BadParameter, match="both --tsa-user and --tsa-pass-env"):
        _b(tsa_url="https://t", tsa_user="alice")


def test_passenv_unset_raises(monkeypatch):
    monkeypatch.delenv("ABSENT_TSA_PW", raising=False)
    with pytest.raises(typer.BadParameter, match="is not set"):
        _b(tsa_url="https://t", tsa_user="alice", tsa_pass_env="ABSENT_TSA_PW")


def test_headers_parsed():
    ts = _b(tsa_url="https://t", tsa_header=["Authorization: Bearer abc", "X-Api-Key:k"])
    assert ts.headers == {"Authorization": "Bearer abc", "X-Api-Key": "k"}


def test_bad_header_raises():
    with pytest.raises(typer.BadParameter, match="Name: Value"):
        _b(tsa_url="https://t", tsa_header=["no-colon"])
