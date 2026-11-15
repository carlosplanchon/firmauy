"""Reader integration tests against a simulated PC/SC stack.

These drive the real ``firmauy.cli`` commands and ``firmauy.card_reader`` APDU code through a
virtual reader, so the SELECT / READ BINARY exchange, the T=0 ``61 xx`` continuations, the output
sinks and the JSON error contract are exercised together. No reader, pcscd, card or PIN is used.
"""

import base64
import hashlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import firmauy.cli as cli
from firmauy.card_reader import read_file
from firmauy.cli import app

from simulated_reader import (
    SimulatedCard,
    SimulatedReader,
    card_files,
    install_readers,
    jpeg_with_dimensions,
)


runner = CliRunner()
JPEG = jpeg_with_dimensions(240, 320)


def _one_reader(monkeypatch, card=None, **card_kwargs):
    card = card if card is not None else SimulatedCard(card_files(**card_kwargs))
    reader = SimulatedReader("Virtual Cédula Reader 00 00", card)
    install_readers(monkeypatch, [reader])
    return reader, card


# --- reader discovery and connection ---------------------------------------


def test_list_readers_reports_the_simulated_reader(monkeypatch):
    reader, _ = _one_reader(monkeypatch)
    result = runner.invoke(app, ["list-readers", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["readers"] == [str(reader)]
    assert payload["schema_version"] == cli._JSON_SCHEMA_VERSION


def test_list_readers_reports_no_reader(monkeypatch):
    install_readers(monkeypatch, [])
    result = runner.invoke(app, ["list-readers", "--json"])
    assert result.exit_code == 1
    assert json.loads(result.stdout)["readers"] == []


def test_fetch_identity_uses_the_only_reader(monkeypatch):
    _one_reader(monkeypatch)
    result = runner.invoke(app, ["fetch-identity", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["lastnames"] == "PEREZ"
    assert payload["document_number"] == "00000TXXX"
    assert payload["id_number_check_digit_valid"] is True


def test_fetch_identity_human_output(monkeypatch):
    _one_reader(monkeypatch)
    result = runner.invoke(app, ["fetch-identity"])
    assert result.exit_code == 0, result.output
    assert "PEREZ" in result.stdout
    assert "CÉDULA DE IDENTIDAD" in result.stdout


def test_fetch_identity_accepts_a_named_reader(monkeypatch):
    card = SimulatedCard(card_files())
    first = SimulatedReader("Reader A", card)
    second = SimulatedReader("Reader B", card)
    install_readers(monkeypatch, [first, second])

    result = runner.invoke(app, ["fetch-identity", "--reader", "Reader B", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["given_names"] == "JUAN"


def test_multiple_readers_require_a_selection(monkeypatch):
    card = SimulatedCard(card_files())
    install_readers(monkeypatch, [SimulatedReader("Reader A", card),
                                  SimulatedReader("Reader B", card)])
    result = runner.invoke(app, ["fetch-identity", "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert "Reader A" in payload["error"] and "Reader B" in payload["error"]


def test_named_reader_must_exist(monkeypatch):
    _one_reader(monkeypatch)
    result = runner.invoke(app, ["fetch-identity", "--reader", "Not Connected"])
    assert result.exit_code == 1
    assert "Not Connected" in result.stderr
    assert "Virtual Cédula Reader" in result.stderr


def test_a_reader_without_a_card_is_reported_as_card_not_found(monkeypatch):
    reader = SimulatedReader("Empty Reader", None)
    install_readers(monkeypatch, [reader])
    result = runner.invoke(app, ["fetch-identity", "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["error_code"] == "card_not_found"
    assert "Insert the cédula" in payload["error"]


def test_no_readers_at_all_is_reported_as_reader_not_found(monkeypatch):
    install_readers(monkeypatch, [])
    result = runner.invoke(app, ["fetch-identity", "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["error_code"] == "reader_not_found"


# --- identity reading and redaction ---------------------------------------


def test_fetch_identity_redact_never_leaks_personal_data(monkeypatch):
    _one_reader(monkeypatch)
    result = runner.invoke(app, ["fetch-identity", "--json", "--redact"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["redacted"] is True
    assert payload["lastnames"] == "[REDACTED]"
    for needle in ("PEREZ", "GOMEZ", "JUAN", "MONTEVIDEO", "12345672", "00000TXXX"):
        assert needle not in result.stdout, needle


def test_optional_files_may_be_absent(monkeypatch):
    _one_reader(monkeypatch, include_optional=False)
    result = runner.invoke(app, ["fetch-identity", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["lastnames"] == "PEREZ"
    assert "document_number" not in payload
    assert "mrz" not in payload


def test_a_status_error_on_an_optional_file_is_not_treated_as_absence(monkeypatch):
    card = SimulatedCard(card_files(), status={0x7001: (0x69, 0x82)})
    _one_reader(monkeypatch, card=card)
    result = runner.invoke(app, ["fetch-identity", "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert "SELECT 7001" in payload["error"]


# --- the APDU read path, including T=0 continuations ----------------------


def test_read_file_collects_chained_read_binary_responses():
    card = SimulatedCard(card_files(), chunked=True, chunk_size=5)
    data = read_file(card, 0x7002)
    assert data == list(card.files[0x7002])


def test_read_card_works_over_a_chunked_reader(monkeypatch):
    card = SimulatedCard(card_files(), chunked=True, chunk_size=4)
    _one_reader(monkeypatch, card=card)
    result = runner.invoke(app, ["fetch-identity", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["lastnames"] == "PEREZ"
    assert payload["document_number"] == "00000TXXX"
    assert len(payload["mrz"]) == 3


# --- photo output sinks ---------------------------------------------------


def test_fetch_photo_writes_the_exact_jpeg(monkeypatch, tmp_path):
    _one_reader(monkeypatch)
    out = tmp_path / "foto.jpg"
    result = runner.invoke(app, ["fetch-photo", str(out)])
    assert result.exit_code == 0, result.output
    assert out.read_bytes() == JPEG
    assert "Photo saved" in result.stdout


def test_fetch_photo_json_round_trips_the_image(monkeypatch):
    _one_reader(monkeypatch)
    result = runner.invoke(app, ["fetch-photo", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["format"] == "jpeg"
    assert payload["mime"] == "image/jpeg"
    assert (payload["width"], payload["height"]) == (240, 320)
    assert payload["bytes"] == len(JPEG)
    assert payload["sha256"] == hashlib.sha256(JPEG).hexdigest()
    assert base64.b64decode(payload["base64"]) == JPEG


def test_fetch_photo_json_redact_drops_the_image_and_fingerprints(monkeypatch):
    _one_reader(monkeypatch)
    result = runner.invoke(app, ["fetch-photo", "--json", "--redact"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["redacted"] is True
    assert payload["width"] == 240 and payload["height"] == 320
    assert "base64" not in payload
    assert "sha256" not in payload
    assert "bytes" not in payload


def test_fetch_photo_dash_streams_bytes_through_the_reader(monkeypatch):
    _one_reader(monkeypatch)

    class _Stdout:
        def __init__(self):
            self.buffer = __import__("io").BytesIO()

        def isatty(self):
            return False

    fake = _Stdout()
    monkeypatch.setattr(cli.sys, "stdout", fake)
    cli.fetch_photo_cmd(output=Path("-"), reader_name=None, overwrite=False,
                        json_output=False, json_pretty=False, redact=False)
    assert fake.buffer.getvalue() == JPEG


def test_fetch_photo_over_a_chunked_reader_is_complete(monkeypatch, tmp_path):
    card = SimulatedCard(card_files(), chunked=True, chunk_size=7)
    _one_reader(monkeypatch, card=card)
    out = tmp_path / "foto.jpg"
    result = runner.invoke(app, ["fetch-photo", str(out)])
    assert result.exit_code == 0, result.output
    assert out.read_bytes() == JPEG


# --- JSON errors stay structured -----------------------------------------


@pytest.mark.parametrize("command", [
    ["fetch-identity", "--json"],
    ["fetch-photo", "--json"],
])
def test_reader_commands_emit_json_errors(monkeypatch, command):
    # A reader with no card fails after discovery; under --json the failure must still be the
    # documented object on stdout, not a coloured line on stderr that a script cannot read.
    install_readers(monkeypatch, [SimulatedReader("Empty Reader", None)])
    result = runner.invoke(app, command)
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["error_code"] == "card_not_found"
