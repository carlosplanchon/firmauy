"""CLI-level smoke tests (Typer app wiring, --version, --json verify contract)."""

import datetime
import json
import re
from importlib.metadata import version

from unittest import mock

import pkcs11
import pytest

from asn1crypto import keys as asn1keys
from asn1crypto import x509 as asn1x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pyhanko.sign.signers import SimpleSigner
from pyhanko_certvalidator.registry import SimpleCertificateStore
from typer.testing import CliRunner

from firmauy.cli import (
    _detached_original,
    _detect_signature_kind,
    _doctor_emit,
    _emit_verify,
    _emit_verify_error,
    _verify_after_cms,
    app,
)
from firmauy.signing import _check_post_sign
from firmauy.cms_sign import sign_cms_detached
from firmauy.verify_common import Check, VerifyResult

import firmauy.cli as cli
import firmauy.signing as signing
from firmauy.errors import PinLastTryError, PinLockedError

runner = CliRunner()


# --- --version --------------------------------------------------------------

def test_version_flag_reports_package_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert f"firmauy {version('firmauy')}" in result.output


def plain(output: str) -> str:
    """Help text with the colour taken out. **Every** assertion about help text goes through here.

    In CI, GITHUB_ACTIONS makes Rich force colour, and Rich styles an option name in pieces: it
    emits "--tsa-ca" as "-", "-tsa" and "-ca" with escape codes between them, so the literal
    string never appears. A raw substring check therefore passes on a developer's machine, where
    Rich sees no terminal and emits none of that, and fails only in CI. This has now cost two
    releases, so it lives in one place with its reason attached.
    """
    return re.sub(r"\x1b\[[0-9;]*m", "", output)


def test_help_still_shows_app_description():
    # The --version callback must not clobber the app's help text.
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    clean = plain(result.output)
    assert "Sign and verify PDF (PAdES)" in clean
    assert "--version" in clean


# --- --json verify contract (helpers) ---------------------------------------

def test_emit_verify_json_schema(capsys):
    r = VerifyResult(
        "VALID", [Check("intact", True), Check("chain", True, "ok")],
        signer={"common_name": "CARLOS", "serial_number": "DNI1", "certificate_serial": "AB", "country": "UY"},
        issuer={"common_name": "AC MI", "organization": "MI"}, trusted=True,
    )
    overall = _emit_verify([r], json_output=True)
    assert overall == "VALID"
    out = json.loads(capsys.readouterr().out)
    assert out["schema_version"] == 2 and out["indication"] == "VALID"
    assert out["redacted"] is False                    # top-level redaction flag (always present)
    assert len(out["signatures"]) == 1
    sig = out["signatures"][0]
    assert sig["signer"]["common_name"] == "CARLOS" and sig["signer"]["serial_number"] == "DNI1"
    assert sig["issuer"]["common_name"] == "AC MI" and sig["trusted"] is True
    assert sig["checks"][1] == {"name": "chain", "ok": True, "detail": "ok"}


def test_emit_verify_redact_hides_signer_keeps_issuer(capsys):
    r = VerifyResult(
        "VALID", [],
        signer={"common_name": "CARLOS", "serial_number": "DNI1", "certificate_serial": "AB", "country": "UY"},
        issuer={"common_name": "AC MI"}, trusted=True,
    )
    _emit_verify([r], json_output=True, redact=True)
    out = json.loads(capsys.readouterr().out)
    assert out["redacted"] is True                     # top-level redaction flag
    sig = out["signatures"][0]
    assert sig["signer"]["common_name"] == "[REDACTED]"
    assert sig["signer"]["serial_number"] == "[REDACTED]"
    assert sig["signer"]["certificate_serial"] == "[REDACTED]"
    assert sig["signer"]["country"] == "UY"            # not personal -> kept
    assert sig["issuer"]["common_name"] == "AC MI"     # issuer (public CA) never redacted


def test_emit_verify_redact_hides_pii_in_check_detail(capsys):
    # A chain-validation detail can embed the cert subject DN (holder name + document number).
    # --redact must scrub it from both JSON and human output, while keeping it without --redact.
    leaky = 'InvalidCertificateError: self-signed - "Common Name: PEREZ PEREZ JUAN, Serial Number: DNI12345678"'
    r = VerifyResult(
        "INDETERMINATE",
        [Check("coverage (whole file)", True, "ENTIRE_FILE"),
         Check("certificate chain to trusted root", False, leaky)],
        signer={"common_name": "PEREZ PEREZ JUAN", "serial_number": "DNI12345678"},
        issuer={"common_name": "AC MI"},
    )

    # JSON, redacted: no PII anywhere; non-empty details become [REDACTED].
    _emit_verify([r], json_output=True, redact=True)
    out = capsys.readouterr().out
    assert "PEREZ" not in out and "DNI12345678" not in out
    checks = json.loads(out)["signatures"][0]["checks"]
    assert all(c["detail"] == "[REDACTED]" for c in checks)

    # Human, redacted: no PII in the printed details either.
    _emit_verify([r], json_output=False, redact=True)
    assert "PEREZ" not in capsys.readouterr().out

    # Without --redact, the detail is preserved (diagnostic value when debugging locally).
    _emit_verify([r], json_output=True, redact=False)
    out = capsys.readouterr().out
    assert "PEREZ PEREZ JUAN" in out and "ENTIRE_FILE" in out


def test_emit_verify_redact_redacts_self_issued_issuer(capsys):
    # The issuer (a public CA) is normally kept, but a self-issued cert's issuer *is* the holder,
    # so keeping it would defeat --redact.
    holder = {"common_name": "PEREZ JUAN", "serial_number": "DNI9"}
    r = VerifyResult("INDETERMINATE", [], signer=dict(holder), issuer=dict(holder))
    _emit_verify([r], json_output=True, redact=True)
    out = capsys.readouterr().out
    assert "PEREZ" not in out and "DNI9" not in out
    assert json.loads(out)["signatures"][0]["issuer"]["common_name"] == "[REDACTED]"

    # A normal (different) public-CA issuer is still kept.
    r2 = VerifyResult("INDETERMINATE", [], signer=dict(holder), issuer={"common_name": "AC MI"})
    _emit_verify([r2], json_output=True, redact=True)
    assert json.loads(capsys.readouterr().out)["signatures"][0]["issuer"]["common_name"] == "AC MI"


def test_emit_verify_pretty_is_indented(capsys):
    r = VerifyResult("VALID", [], signer={"common_name": "X"}, issuer={}, trusted=True)
    _emit_verify([r], json_output=True, pretty=True)
    out = capsys.readouterr().out
    assert "\n  " in out
    assert json.loads(out)["schema_version"] == 2


def test_emit_verify_overall_is_worst_signature(capsys):
    rs = [VerifyResult("VALID", []), VerifyResult("INVALID", []), VerifyResult("INDETERMINATE", [])]
    assert _emit_verify(rs, json_output=True) == "INVALID"
    out = json.loads(capsys.readouterr().out)
    assert out["indication"] == "INVALID"
    assert len(out["signatures"]) == 3


def test_emit_verify_error_json(capsys):
    _emit_verify_error(ValueError("boom"), json_output=True)
    out = json.loads(capsys.readouterr().out)
    assert out["schema_version"] == 2
    assert out["error"] == "boom"


def test_list_readers_json(monkeypatch, capsys):
    monkeypatch.setattr(cli, "list_readers", lambda: ["Reader A", "Reader B"])

    cli.list_readers_cmd(json_output=True)

    assert json.loads(capsys.readouterr().out) == {
        "schema_version": 2,
        "readers": ["Reader A", "Reader B"],
    }


def test_list_tokens_json(monkeypatch, capsys):
    class Token:
        label = "token"
        manufacturer = "maker"
        model = "model"
        serial = "serial"

    class Library:
        def get_tokens(self):
            return [Token()]

    monkeypatch.setattr(cli, "load_pkcs11_lib", lambda _: Library())

    cli.list_tokens(json_output=True)

    assert json.loads(capsys.readouterr().out) == {
        "schema_version": 2,
        "tokens": [{
            "label": "token", "manufacturer": "maker", "model": "model", "serial": "serial",
        }],
    }


# --- --json verify, end-to-end through the CLI ------------------------------

def _software_p7s(data: bytes) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TEST SIGNER")])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    signer = SimpleSigner(
        signing_cert=asn1x509.Certificate.load(der),
        signing_key=asn1keys.PrivateKeyInfo.load(key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())),
        cert_registry=SimpleCertificateStore(),
    )
    return sign_cms_detached(data, signer=signer)


def test_verify_any_json_end_to_end(tmp_path):
    data = b"payload for json verify\n"
    doc = tmp_path / "doc.bin"
    doc.write_bytes(data)
    (tmp_path / "doc.bin.p7s").write_bytes(_software_p7s(data))

    result = runner.invoke(app, ["verify-any", str(doc), "--no-trust", "--json"])
    assert result.exit_code == 2  # integrity OK, no trust -> INDETERMINATE
    payload = json.loads(result.output)  # stdout is pure JSON
    assert payload["schema_version"] == 2
    assert payload["indication"] == "INDETERMINATE"
    assert payload["signatures"][0]["indication"] == "INDETERMINATE"
    assert payload["signatures"][0]["signer"]["common_name"] == "TEST SIGNER"
    assert all(c["ok"] for c in payload["signatures"][0]["checks"])


def test_verify_any_json_pretty_redact_end_to_end(tmp_path):
    data = b"secret payload\n"
    doc = tmp_path / "d.bin"
    doc.write_bytes(data)
    (tmp_path / "d.bin.p7s").write_bytes(_software_p7s(data))

    result = runner.invoke(app, ["verify-any", str(doc), "--no-trust", "--json-pretty", "--redact"])
    assert result.exit_code == 2
    assert "\n  " in result.output  # --json-pretty implies --json and indents
    payload = json.loads(result.output)
    assert payload["signatures"][0]["signer"]["common_name"] == "[REDACTED]"


# --- doctor -----------------------------------------------------------------

def test_doctor_emit_ok_when_no_fail(capsys):
    checks = [
        {"status": "PASS", "name": "a", "detail": "", "fix": None},
        {"status": "WARN", "name": "b", "detail": "x", "fix": "do y"},
    ]
    assert _doctor_emit(checks, json_output=True) is True
    out = json.loads(capsys.readouterr().out)
    assert out["schema_version"] == 2 and out["ok"] is True
    assert len(out["checks"]) == 2


def test_doctor_emit_not_ok_on_fail(capsys):
    checks = [{"status": "FAIL", "name": "a", "detail": "x", "fix": "fix it"}]
    assert _doctor_emit(checks, json_output=True) is False
    assert json.loads(capsys.readouterr().out)["ok"] is False


def test_doctor_command_json_contract():
    # Environment-independent: assert the contract shape and exit/ok consistency.
    result = runner.invoke(app, ["doctor", "--json"])
    payload = json.loads(result.output)
    assert payload["schema_version"] == 2
    assert isinstance(payload["ok"], bool)
    assert payload["checks"]
    for c in payload["checks"]:
        assert {"status", "name", "detail", "fix"} <= set(c)
        assert c["status"] in {"PASS", "WARN", "FAIL"}
    assert result.exit_code == (0 if payload["ok"] else 1)


# --- --verify (post-sign self-check) ----------------------------------------

def test_check_post_sign_passes_and_raises(tmp_path):
    out = tmp_path / "salida.xml"
    # All checks ok -> no raise (post-sign self-check passes).
    _check_post_sign(VerifyResult("INDETERMINATE", [Check("intact", True), Check("valid", True)]),
                     out)
    # Any failed check -> raise (the produced signature is not intact).
    from firmauy.errors import PostSignVerificationError
    with pytest.raises(PostSignVerificationError, match="post-sign verification failed") as caught:
        _check_post_sign(
            VerifyResult("INVALID", [Check("intact", False, "tampered"), Check("valid", True)]),
            out)
    # The file was written before this ran. Saying so is what lets somebody delete it instead of
    # finding it later and taking it for a signature.
    assert "salida.xml is on disk" in str(caught.value)
    assert "delete it and sign again" in str(caught.value)
    assert caught.value.outcome == "failed" and caught.value.path == out


def test_verify_after_cms_catches_a_broken_signature(tmp_path):
    data = b"the signed content\n"
    doc = tmp_path / "d.bin"
    doc.write_bytes(data)
    sig = tmp_path / "d.bin.p7s"
    sig.write_bytes(_software_p7s(data))

    _verify_after_cms(doc, sig)  # intact -> no raise

    doc.write_bytes(b"TAMPERED content!!\n")  # mutate the bytes the signature covers
    from firmauy.errors import PostSignVerificationError
    with pytest.raises(PostSignVerificationError, match="not intact") as caught:
        _verify_after_cms(doc, sig)
    # Detached: the pair does not match, and which of the two moved is not knowable here.
    assert caught.value.outcome == "detached-mismatch"
    assert caught.value.covers == doc
    assert caught.value.path == sig


# --- verify (auto-detect) ---------------------------------------------------

def test_detect_signature_kind_and_original(tmp_path):
    pdf = tmp_path / "a.pdf"
    pdf.write_bytes(b"%PDF-1.7\nx")
    assert _detect_signature_kind(pdf) == "pdf"

    xml = tmp_path / "a.xml"
    xml.write_bytes(b"\xef\xbb\xbf<?xml version='1.0'?><ds:Signature/>")  # BOM tolerated
    assert _detect_signature_kind(xml) == "xml"

    p7s = tmp_path / "doc.bin.p7s"
    p7s.write_bytes(_software_p7s(b"hi"))
    assert _detect_signature_kind(p7s) == "cms"

    junk = tmp_path / "j.bin"
    junk.write_bytes(b"not a signature")
    with pytest.raises(ValueError, match="could not detect"):
        _detect_signature_kind(junk)

    assert _detached_original(p7s) == tmp_path / "doc.bin"
    assert _detached_original(tmp_path / "x.txt") is None


def test_detect_kind_not_fooled_by_embedded_pdf_marker(tmp_path):
    # An XML/text that merely *contains* "%PDF-" must not be misdetected as a PDF (#6); the header
    # is only honoured at the logical start of the file.
    xml = tmp_path / "doc.xml"
    xml.write_bytes(b"<?xml version='1.0'?><root><note>see %PDF-1.7 spec</note></root>")
    assert _detect_signature_kind(xml) == "xml"

    # A real PDF (header at the start, optionally after a BOM / whitespace) is still detected.
    assert _detect_signature_kind_bytes(tmp_path, b"%PDF-1.7\n...") == "pdf"
    assert _detect_signature_kind_bytes(tmp_path, b"\xef\xbb\xbf%PDF-1.7\n") == "pdf"


def _detect_signature_kind_bytes(tmp_path, data: bytes) -> str:
    p = tmp_path / "probe.bin"
    p.write_bytes(data)
    return _detect_signature_kind(p)


def test_detect_signature_kind_bounds_the_cms_read(tmp_path, monkeypatch):
    # A file beyond the CMS-detection cap is not a detached .p7s and must not be read/parsed whole.
    # _detect_signature_kind and its cap live in firmauy._shared (the CLI re-exports the function).
    import firmauy._shared as shared

    p7s = tmp_path / "sig.p7s"
    p7s.write_bytes(_software_p7s(b"hi"))                 # a real, valid detached CMS
    assert shared._detect_signature_kind(p7s) == "cms"    # detected normally under the real cap

    monkeypatch.setattr(shared, "_CMS_DETECT_MAX_BYTES", 16)
    with pytest.raises(ValueError, match="could not detect"):
        shared._detect_signature_kind(p7s)                # same file now exceeds the (tiny) budget


def test_verify_autodetect_cms_locates_original(tmp_path):
    data = b"auto-detected content\n"
    (tmp_path / "doc.bin").write_bytes(data)
    p7s = tmp_path / "doc.bin.p7s"
    p7s.write_bytes(_software_p7s(data))

    result = runner.invoke(app, ["verify", str(p7s), "--no-trust", "--json"])
    assert result.exit_code == 2  # detected CMS, original located, integrity ok, no trust
    payload = json.loads(result.output)
    assert payload["indication"] == "INDETERMINATE"
    assert payload["signatures"][0]["signer"]["common_name"] == "TEST SIGNER"


def test_verify_autodetect_detached_without_original_errors(tmp_path):
    orphan = tmp_path / "orphan.p7s"
    orphan.write_bytes(_software_p7s(b"x"))  # original "orphan" does not exist
    result = runner.invoke(app, ["verify", str(orphan), "--no-trust"])
    assert result.exit_code == 1
    assert "needs its original file" in result.output


def _make_id_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "UY"),
        x509.NameAttribute(NameOID.COMMON_NAME, "PEREZ JUAN"),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, "DNI123"),
    ])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AC MI")])
    return (
        x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key()).serial_number(0x78191)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=True, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .sign(key, hashes.SHA256())
    )


def test_cert_record_structure_and_pem():
    from firmauy.cli import _cert_record

    rec = _cert_record("5c10d3", _make_id_cert(), include_pem=True)
    assert rec["id"] == "5c10d3"
    assert rec["subject"]["common_name"] == "PEREZ JUAN" and rec["subject"]["serial_number"] == "DNI123"
    assert rec["issuer"]["common_name"] == "AC MI"
    assert rec["certificate_serial"] == "78191"
    assert rec["digital_signature"] is True
    assert rec["pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert "pem" not in _cert_record("5c10d3", _make_id_cert(), include_pem=False)


def test_redact_cert_record_hides_holder_keeps_issuer():
    from firmauy.cli import _cert_record, _redact_cert_record

    red = _redact_cert_record(_cert_record("5c10d3", _make_id_cert(), include_pem=True))
    assert red["subject"]["common_name"] == "[REDACTED]"
    assert red["subject"]["serial_number"] == "[REDACTED]"
    assert red["subject"]["country"] == "UY"          # not personal -> kept
    assert red["certificate_serial"] == "[REDACTED]"
    assert red["pem"] == "[REDACTED]"
    assert red["issuer"]["common_name"] == "AC MI"    # issuer (public CA) kept


def test_list_certs_redact_with_raw_pem_errors_before_card():
    # The guard fires before any PKCS#11 access, so this is card-independent.
    result = runner.invoke(app, ["list-certs", "--pem", "--redact"])
    assert result.exit_code == 1
    assert "redact has no effect on raw --pem" in result.output


def test_validate_image_accepts_valid_rejects_invalid(tmp_path):
    from PIL import Image

    from firmauy.cli import _validate_image

    good = tmp_path / "ok.png"
    Image.new("RGB", (8, 8), (1, 2, 3)).save(good)
    _validate_image(str(good))   # valid -> no raise
    _validate_image(None)        # no image -> no raise

    bad = tmp_path / "bad.png"
    bad.write_bytes(b"not an image")
    with pytest.raises(RuntimeError, match="not a valid image"):
        _validate_image(str(bad))


def test_sign_pdf_invalid_image_fails_before_the_card(tmp_path):
    # The --image check runs in pre-flight, so a bad image fails without touching the card / PIN.
    pdf = tmp_path / "in.pdf"
    pdf.write_bytes(b"%PDF-1.7\n")
    bad = tmp_path / "bad.png"
    bad.write_bytes(b"not an image")
    result = runner.invoke(app, ["sign-pdf", str(pdf), "--image", str(bad)])
    assert result.exit_code == 1
    assert "not a valid image" in result.output


def test_sign_pdf_rejects_malformed_cert_id_before_the_pin(tmp_path):
    # A malformed --cert-id (odd-length hex) is validated up front in _signing_session, before the
    # PKCS#11 module is loaded or the PIN is prompted, so it fails fast with a clear message instead
    # of a cryptic bytes.fromhex ValueError after the PIN. No card / module needed for this to fire.
    pdf = tmp_path / "in.pdf"
    pdf.write_bytes(b"%PDF-1.7\n")
    result = runner.invoke(app, ["sign-pdf", str(pdf), "--cert-id", "ABC"])
    assert result.exit_code == 1
    assert "odd number of hex digits" in result.output


def test_batch_output_preserves_subdirs_and_avoids_collisions(tmp_path):
    from pathlib import Path

    from firmauy.cli import _batch_output

    out = tmp_path / "out"
    indir = tmp_path / "in"

    # Positional file (input_dir=None) -> flat by stem + suffix + ext.
    assert _batch_output(Path("/x/y/a.pdf"), None, out, ".pdf", "_firmado") == out / "a_firmado.pdf"
    # Top-level file inside --input-dir -> flat (no spurious '.' segment).
    assert _batch_output(indir / "a.pdf", indir, out, ".pdf", "_firmado") == out / "a_firmado.pdf"
    # A sub-folder file keeps its structure under output_dir.
    assert _batch_output(indir / "sub" / "a.pdf", indir, out, ".pdf", "_firmado") == out / "sub" / "a_firmado.pdf"
    # Equally-named files in different sub-folders do NOT collide (the bug this fixes).
    o1 = _batch_output(indir / "d1" / "a.pdf", indir, out, ".pdf", "_firmado")
    o2 = _batch_output(indir / "d2" / "a.pdf", indir, out, ".pdf", "_firmado")
    assert o1 != o2


def test_batch_input_rejects_symlinks_outside_input_dir(tmp_path):
    from firmauy.cli import _batch_input_allowed

    input_dir = tmp_path / "in"
    input_dir.mkdir()
    outside = tmp_path / "outside.pdf"
    outside.write_bytes(b"%PDF-1.7\n")
    link = input_dir / "linked.pdf"
    link.symlink_to(outside)

    assert not _batch_input_allowed(link, input_dir)

    regular = input_dir / "regular.pdf"
    regular.write_bytes(b"%PDF-1.7\n")
    assert _batch_input_allowed(regular, input_dir)


def test_raise_on_output_collisions():
    from pathlib import Path

    from firmauy.cli import _raise_on_output_collisions

    # Distinct outputs -> no raise.
    _raise_on_output_collisions([(Path("d1/x"), Path("out/x1")), (Path("d2/y"), Path("out/y1"))])
    # Two inputs mapping to the same output -> raise, naming both offenders.
    with pytest.raises(RuntimeError, match="Output path collision"):
        _raise_on_output_collisions([(Path("d1/x"), Path("out/x")), (Path("d2/x"), Path("out/x"))])


@pytest.mark.parametrize("cmd, fname", [
    ("sign-pdf-batch", "report.pdf"),
    ("sign-xml-batch", "report.xml"),
    ("sign-any-batch", "report.bin"),
])
def test_batch_rejects_output_collision_before_card(tmp_path, cmd, fname):
    # Two same-named inputs in different folders map to one output. Every per-type batch must refuse
    # this up front (even with --overwrite, which would otherwise silently drop one signed output),
    # before creating the output dir or touching the card -- like the unified sign-batch already did.
    d1 = tmp_path / "d1"
    d2 = tmp_path / "d2"
    d1.mkdir()
    d2.mkdir()
    (d1 / fname).write_bytes(b"%PDF-1.7\n")
    (d2 / fname).write_bytes(b"%PDF-1.7\n")
    out = tmp_path / "out"

    result = runner.invoke(app, [cmd, str(d1 / fname), str(d2 / fname),
                                 "--output-dir", str(out), "--overwrite"])
    assert result.exit_code == 1, result.output
    assert "Output path collision" in result.output
    assert not out.exists()   # refused before the output dir was created / the card was touched


def test_atomic_write_bytes_writes_and_cleans_up_temp(tmp_path):
    from firmauy.signing import _atomic_write_bytes

    out = tmp_path / "o.bin"
    _atomic_write_bytes(out, b"hello")
    assert out.read_bytes() == b"hello"
    assert list(tmp_path.iterdir()) == [out]        # the staging file is gone after os.replace


def test_atomic_write_bytes_replaces_symlink_without_writing_through(tmp_path):
    # The XML/CMS signed outputs go through _atomic_write_bytes, which must REPLACE a pre-existing
    # output symlink with the real file -- not follow it and clobber its target (what write_bytes did).
    from firmauy.signing import _atomic_write_bytes

    target = tmp_path / "target.txt"
    target.write_bytes(b"DO NOT TOUCH")
    link = tmp_path / "out.xml"
    link.symlink_to(target)

    _atomic_write_bytes(link, b"<signed/>")

    assert not link.is_symlink()                    # symlink replaced by a regular file
    assert link.read_bytes() == b"<signed/>"
    assert target.read_bytes() == b"DO NOT TOUCH"   # the symlink target was never written through
    assert sorted(p.name for p in tmp_path.iterdir()) == ["out.xml", "target.txt"]


class _RecordingConn:
    def __init__(self):
        self.disconnected = False

    def disconnect(self):
        self.disconnected = True


def test_fetch_identity_disconnects_the_reader(monkeypatch):

    conn = _RecordingConn()
    monkeypatch.setattr(signing, "open_reader", lambda reader_name=None: conn)
    monkeypatch.setattr(cli, "read_card", lambda c: {"bio": {}, "doc_num": None, "mrz": None})

    result = runner.invoke(app, ["fetch-identity", "--json"])
    assert result.exit_code == 0, result.output
    assert conn.disconnected is True   # the PC/SC connection is released, like fetch-photo


def test_fetch_identity_disconnects_even_when_read_fails(monkeypatch):
    # The disconnect lives in a finally, so a read error must still release the reader.

    conn = _RecordingConn()

    def boom(_c):
        raise RuntimeError("read failed")

    monkeypatch.setattr(signing, "open_reader", lambda reader_name=None: conn)
    monkeypatch.setattr(cli, "read_card", boom)

    result = runner.invoke(app, ["fetch-identity"])
    assert result.exit_code == 1
    assert conn.disconnected is True   # released despite the read error


def test_image_opacity_warning_only_outside_background(capsys):
    from firmauy.cli import _warn_image_opacity_unused
    from firmauy.constants import DEFAULT_IMAGE_OPACITY, ImageMode

    img = "sig.png"
    # Non-default opacity in a non-background mode -> warns.
    _warn_image_opacity_unused(img, ImageMode.only, 0.5)
    assert "only applies to --image-mode background" in capsys.readouterr().err
    # Background mode, default opacity, or no image -> silent.
    _warn_image_opacity_unused(img, ImageMode.background, 0.5)
    _warn_image_opacity_unused(img, ImageMode.side, DEFAULT_IMAGE_OPACITY)
    _warn_image_opacity_unused(None, ImageMode.only, 0.9)
    assert capsys.readouterr().err == ""


def test_verify_autodetect_xml_dispatch(tmp_path):
    # A valid XML without a <ds:Signature> proves the XML branch is wired (verify_xml -> INVALID).
    xml = tmp_path / "u.xml"
    xml.write_bytes(b"<?xml version='1.0'?><root/>")
    result = runner.invoke(app, ["verify", str(xml), "--no-trust", "--json"])
    assert result.exit_code == 1
    assert json.loads(result.output)["indication"] == "INVALID"


def test_verify_original_ignored_for_non_cms_warns(tmp_path):
    xml = tmp_path / "u.xml"
    xml.write_bytes(b"<?xml version='1.0'?><root/>")
    result = runner.invoke(app, ["verify", str(xml), "--original", "whatever.txt", "--no-trust"])
    assert "--original is ignored" in result.output   # warned, not silently dropped
    assert result.exit_code == 1                       # still verified the XML (no signature)


def test_verify_tsa_ca_is_no_longer_refused_for_a_pdf(tmp_path):
    """It used to print "--tsa-ca is ignored for a PDF file" and drop the option, along with the
    advice that "PDF/CMS timestamps use --ca-file". Both were wrong: the option now applies to
    every format, and --ca-file decides who may have *signed* the document, so pointing it at a
    timestamping authority to get a stamp validated widens that instead."""
    pdf = tmp_path / "a.pdf"
    pdf.write_bytes(b"%PDF-1.7\n")
    tsaca = tmp_path / "tsa.pem"
    tsaca.write_bytes(b"-----BEGIN CERTIFICATE-----\nnot real\n-----END CERTIFICATE-----\n")
    result = runner.invoke(app, ["verify", str(pdf), "--tsa-ca", str(tsaca), "--no-trust"])
    assert "--tsa-ca is ignored" not in result.output
    assert "--ca-file" not in result.output


def test_every_verify_command_accepts_tsa_ca():
    """1.12.0 wired --tsa-ca through the verifiers and the auto-detecting `verify`, but left the
    per-format commands without the option, so the documentation promised something two of the
    four commands could not do. A person who knows their file is a PDF reaches for verify-pdf.
    """
    for command in ("verify", "verify-xml", "verify-pdf", "verify-any"):
        assert "--tsa-ca" in plain(runner.invoke(app, [command, "--help"]).output), \
            f"{command} does not offer --tsa-ca"


def test_no_verify_command_rejects_tsa_ca_as_unknown(tmp_path):
    """Offered in the help and actually accepted are two different things, and only the second is
    what happens when somebody types it. Checked without going through the help renderer at all.
    """
    pem = tmp_path / "tsa.pem"
    pem.write_bytes(_ANCHOR_PEM)
    target = tmp_path / "archivo.pdf"
    target.write_bytes(b"%PDF-1.7\n")

    for command in ("verify", "verify-xml", "verify-pdf", "verify-any"):
        out = plain(runner.invoke(app, [command, str(target), "--tsa-ca", str(pem)]).output)
        # Whatever it says about the file is beside the point; what must not appear is Click
        # refusing the option itself.
        assert "No such option" not in out, f"{command} rejected --tsa-ca"


def test_verify_pdf_actually_uses_the_tsa_anchors(tmp_path, monkeypatch):
    """The option existing is not the option working: the wiring is the part that was missing
    everywhere else, and an accepted-and-ignored flag is worse than no flag."""
    import firmauy.cli as cli

    seen = {}

    def _spy(path, **kwargs):
        seen.update(kwargs)
        raise RuntimeError("stop here")

    monkeypatch.setattr(cli, "verify_pdf", _spy)
    pdf = tmp_path / "a.pdf"
    pdf.write_bytes(b"%PDF-1.7\n")
    tsaca = tmp_path / "tsa.pem"
    tsaca.write_bytes(_ANCHOR_PEM)

    runner.invoke(app, ["verify-pdf", str(pdf), "--tsa-ca", str(tsaca), "--no-trust"])

    assert seen.get("tsa_trust_roots"), "verify-pdf accepted --tsa-ca and dropped it"


def test_verify_any_actually_uses_the_tsa_anchors(tmp_path, monkeypatch):
    import firmauy.cli as cli

    seen = {}

    def _spy(data, p7s, **kwargs):
        seen.update(kwargs)
        raise RuntimeError("stop here")

    monkeypatch.setattr(cli, "verify_cms", _spy)
    original = tmp_path / "documento.bin"
    original.write_bytes(b"contenido")
    (tmp_path / "documento.bin.p7s").write_bytes(b"no importa")
    tsaca = tmp_path / "tsa.pem"
    tsaca.write_bytes(_ANCHOR_PEM)

    runner.invoke(app, ["verify-any", str(original), "--tsa-ca", str(tsaca), "--no-trust"])

    assert seen.get("tsa_trust_roots"), "verify-any accepted --tsa-ca and dropped it"


def _make_anchor_pem() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TSA CA")])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365)).sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


_ANCHOR_PEM = _make_anchor_pem()


def test_resolve_tsa_anchors(tmp_path):
    from firmauy.cli import _resolve_tsa_anchors

    assert _resolve_tsa_anchors(None) == (None, None)

    # A self-signed cert is treated as an anchor (root).
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TSA CA")])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365)).sign(key, hashes.SHA256())
    )
    pem = tmp_path / "tsa.pem"
    pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    roots, others = _resolve_tsa_anchors(pem)
    assert len(roots) == 1 and others == []


# --- --timezone pre-flight validation ---------------------------------------

def test_validate_timezone_accepts_valid_rejects_invalid():
    import typer

    from firmauy.cli import _validate_timezone

    _validate_timezone("America/Montevideo")   # valid -> no raise
    _validate_timezone("UTC")                   # valid -> no raise
    with pytest.raises(typer.BadParameter, match="not a valid IANA timezone"):
        _validate_timezone("Marte/Olympus_Mons")


def test_sign_pdf_invalid_timezone_fails_before_the_card(tmp_path):
    # A bad --timezone is caught in pre-flight, so it never reaches the PIN / card and never
    # wastes a card retry-limit attempt on a typo.
    pdf = tmp_path / "in.pdf"
    pdf.write_bytes(b"%PDF-1.7\n")
    result = runner.invoke(app, ["sign-pdf", str(pdf), "--timezone", "Marte/Olympus_Mons"])
    assert result.exit_code == 1
    assert "is not a valid IANA timezone" in result.output


# --- sign-pdf atomic output (no partial file on a mid-signing failure) -------

def _valid_pdf_bytes() -> bytes:
    import io

    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(300, 300))
    c.drawString(50, 150, "hi")
    c.showPage()
    c.save()
    return buf.getvalue()


def _software_signer() -> SimpleSigner:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TEST SIGNER")])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    return SimpleSigner(
        signing_cert=asn1x509.Certificate.load(der),
        signing_key=asn1keys.PrivateKeyInfo.load(key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())),
        cert_registry=SimpleCertificateStore(),
    )


def _run_failing_sign(tmp_path, monkeypatch, out, *, overwrite):
    from pyhanko.sign import signers


    inp = tmp_path / "in.pdf"
    inp.write_bytes(_valid_pdf_bytes())

    # Simulate a card failure mid-signing, *after* pyHanko began writing to the output stream.
    def boom(self, writer, output=None, **kw):
        if output is not None:
            output.write(b"%PDF-1.4 partial-incremental-update...")
        raise RuntimeError("card removed mid-signing (simulated)")

    monkeypatch.setattr(signers.PdfSigner, "sign_pdf", boom)
    meta = signers.PdfSignatureMetadata(field_name="Sig1", md_algorithm=None)
    with pytest.raises(RuntimeError, match="card removed"):
        cli._sign_one_pdf(
            input_pdf=inp, output_pdf=out, pkcs11_signer=_software_signer(),
            signer_name="X", issuer_name="Y", cert_serial="1", timestamper=None,
            meta=meta, page=-1, x1=20, y1=20, x2=225, y2=90,
            timezone="America/Montevideo", field_name="Sig1",
            force=False, overwrite=overwrite,
        )


def test_sign_pdf_failure_leaves_no_partial_output(tmp_path, monkeypatch):
    out = tmp_path / "out_firmado.pdf"
    _run_failing_sign(tmp_path, monkeypatch, out, overwrite=False)
    assert not out.exists()                        # no partial/corrupt file at the destination
    assert list(tmp_path.glob("*.part")) == []     # the temp file was cleaned up


def test_sign_pdf_overwrite_failure_keeps_previous_output(tmp_path, monkeypatch):
    # With --overwrite, a failed re-sign must not destroy the previously good output.
    out = tmp_path / "out_firmado.pdf"
    out.write_bytes(b"PREVIOUS GOOD OUTPUT")
    _run_failing_sign(tmp_path, monkeypatch, out, overwrite=True)
    assert out.read_bytes() == b"PREVIOUS GOOD OUTPUT"
    assert list(tmp_path.glob("*.part")) == []


def test_sign_pdf_output_symlink_is_replaced_not_followed(tmp_path):
    # The atomic os.replace replaces an output symlink with the signed file instead of writing
    # through it. Pin that (safer) behavior: the symlink's previous target is left untouched,
    # so an attacker pre-creating the output as a symlink cannot redirect the write.
    from pyhanko.sign import signers


    inp = tmp_path / "in.pdf"
    inp.write_bytes(_valid_pdf_bytes())
    target = tmp_path / "real.pdf"
    target.write_bytes(b"ORIGINAL TARGET CONTENT")
    out = tmp_path / "out.pdf"
    out.symlink_to(target)

    meta = signers.PdfSignatureMetadata(field_name="Sig1", md_algorithm=None)
    cli._sign_one_pdf(
        input_pdf=inp, output_pdf=out, pkcs11_signer=_software_signer(),
        signer_name="X", issuer_name="Y", cert_serial="1", timestamper=None,
        meta=meta, page=-1, x1=20, y1=20, x2=225, y2=90,
        timezone="America/Montevideo", field_name="Sig1", force=False, overwrite=True)

    assert not out.is_symlink()                                # symlink replaced by a regular file
    assert out.read_bytes().startswith(b"%PDF")                # which holds the signed PDF
    assert target.read_bytes() == b"ORIGINAL TARGET CONTENT"   # the old target is untouched


def test_sign_one_helpers_reject_input_equals_output(tmp_path):
    # The guard lives in the _sign_one_* helpers, so batch mode is covered too (the single
    # commands also guard before the PIN). It fires first, before any signing, so dummy args are
    # fine. This is the data-loss case of sign-*-batch --suffix "" with --output-dir == input dir.

    p = tmp_path / "a.bin"
    p.write_bytes(b"x")
    with pytest.raises(RuntimeError, match="same file"):
        cli._sign_one_pdf(
            input_pdf=p, output_pdf=p, pkcs11_signer=None, signer_name="", issuer_name="",
            cert_serial="", timestamper=None, meta=None, page=-1, x1=20, y1=20, x2=225, y2=90,
            timezone="UTC", field_name="Sig1", force=False, overwrite=True)
    with pytest.raises(RuntimeError, match="same file"):
        cli._sign_one_xml(
            input_xml=p, output_xml=p, cert=None, signer=None,
            signing_time=datetime.datetime.now(), overwrite=True, timestamper=None)
    with pytest.raises(RuntimeError, match="same file"):
        cli._sign_one_cms(
            input_file=p, output_p7s=p, pkcs11_signer=None, timestamper=None, overwrite=True)


# --- fetch-photo output sink: file, stdout stream ("-"), and the TTY guard ------------------------

_JPEG = b"\xff\xd8\xff" + b"\x00" * 50 + b"\xff\xd9"


class _FakeConn:
    """A card connection stub that records whether it was disconnected (finally-cleanup)."""
    def __init__(self):
        self.disconnected = False

    def disconnect(self):
        self.disconnected = True


def _patch_card(monkeypatch, conn):
    monkeypatch.setattr(signing, "open_reader", lambda name=None: conn)
    monkeypatch.setattr(cli, "read_photo", lambda c: _JPEG)


def test_fetch_photo_dash_streams_raw_jpeg_to_stdout(monkeypatch):
    # `fetch-photo -` writes the raw JPEG bytes to stdout (for pipes/redirects) and nothing else:
    # the status line must go to stderr so it never corrupts the stream.
    import io
    from pathlib import Path


    conn = _FakeConn()
    _patch_card(monkeypatch, conn)

    class _Stdout:
        def __init__(self):
            self.buffer = io.BytesIO()

        def isatty(self):
            return False                       # piped/redirected, not a terminal

    fake = _Stdout()
    monkeypatch.setattr(cli.sys, "stdout", fake)

    cli.fetch_photo_cmd(output=Path("-"), reader_name=None, overwrite=False,
                        json_output=False, json_pretty=False, redact=False)

    assert fake.buffer.getvalue() == _JPEG     # exactly the JPEG, no status text leaked to stdout
    assert conn.disconnected                   # the connection was closed in the finally block


def test_fetch_photo_dash_refuses_interactive_terminal(monkeypatch, capsys):
    # Streaming to a TTY would dump binary to the screen; refuse before even opening the card.
    from pathlib import Path

    import typer


    opened = {"n": 0}

    def _should_not_open(name=None):
        opened["n"] += 1
        return _FakeConn()

    monkeypatch.setattr(signing, "open_reader", _should_not_open)

    class _Tty:
        def isatty(self):
            return True                        # interactive terminal
        # deliberately no .buffer: the guard must fire before any write

    monkeypatch.setattr(cli.sys, "stdout", _Tty())

    with pytest.raises(typer.Exit):
        cli.fetch_photo_cmd(output=Path("-"), reader_name=None, overwrite=False,
                        json_output=False, json_pretty=False, redact=False)

    assert opened["n"] == 0                     # guarded before touching the reader
    assert "terminal" in capsys.readouterr().err.lower()


def test_fetch_photo_to_file_writes_bytes_and_reports_on_stdout(tmp_path, monkeypatch, capsys):
    # The default (a path) still writes the JPEG to disk and reports on stdout.

    conn = _FakeConn()
    _patch_card(monkeypatch, conn)

    out = tmp_path / "foto.jpg"
    cli.fetch_photo_cmd(output=out, reader_name=None, overwrite=False,
                        json_output=False, json_pretty=False, redact=False)

    assert out.read_bytes() == _JPEG
    assert conn.disconnected
    assert "Photo saved" in capsys.readouterr().out


def test_fetch_photo_default_output_when_omitted(tmp_path, monkeypatch, capsys):
    # Omitting the output argument (None from typer) still writes the effective default,
    # cedula_foto.jpg in the current directory.

    conn = _FakeConn()
    _patch_card(monkeypatch, conn)
    monkeypatch.chdir(tmp_path)

    cli.fetch_photo_cmd(output=None, reader_name=None, overwrite=False,
                        json_output=False, json_pretty=False, redact=False)

    assert (tmp_path / "cedula_foto.jpg").read_bytes() == _JPEG
    assert conn.disconnected
    assert "Photo saved" in capsys.readouterr().out


def test_fetch_photo_existing_output_requires_overwrite(tmp_path, monkeypatch, capsys):
    # An existing output file is refused without --overwrite, before the card is even opened,
    # and its bytes are left untouched.
    import typer


    opened = {"n": 0}
    monkeypatch.setattr(signing, "open_reader",
                        lambda name=None: opened.__setitem__("n", opened["n"] + 1))

    out = tmp_path / "foto.jpg"
    out.write_bytes(b"previous")

    with pytest.raises(typer.Exit):
        cli.fetch_photo_cmd(output=out, reader_name=None, overwrite=False,
                            json_output=False, json_pretty=False, redact=False)

    assert opened["n"] == 0
    assert out.read_bytes() == b"previous"
    assert "--overwrite" in capsys.readouterr().err


def test_fetch_photo_overwrite_replaces_existing_file(tmp_path, monkeypatch):

    conn = _FakeConn()
    _patch_card(monkeypatch, conn)

    out = tmp_path / "foto.jpg"
    out.write_bytes(b"previous")

    cli.fetch_photo_cmd(output=out, reader_name=None, overwrite=True,
                        json_output=False, json_pretty=False, redact=False)

    assert out.read_bytes() == _JPEG
    assert conn.disconnected


# --- fetch-photo --json record (stdout, redaction, conflict with a file/'-') ----------------------

def test_fetch_photo_json_emits_record_to_stdout(monkeypatch, capsys):
    import base64


    conn = _FakeConn()
    _patch_card(monkeypatch, conn)

    cli.fetch_photo_cmd(output=None, reader_name=None, overwrite=False,
                        json_output=True, json_pretty=False, redact=False)

    obj = json.loads(capsys.readouterr().out)
    assert obj["schema_version"] == 2
    assert obj["redacted"] is False                     # flag present (and false) on the full record
    assert obj["format"] == "jpeg" and obj["mime"] == "image/jpeg"
    assert obj["bytes"] == len(_JPEG)
    assert base64.b64decode(obj["base64"]) == _JPEG     # the record carries the exact image
    assert conn.disconnected


def test_fetch_photo_json_redact_drops_image_and_hash(monkeypatch, capsys):

    _patch_card(monkeypatch, _FakeConn())

    cli.fetch_photo_cmd(output=None, reader_name=None, overwrite=False,
                        json_output=True, json_pretty=False, redact=True)

    obj = json.loads(capsys.readouterr().out)
    assert obj["redacted"] is True                      # top-level flag signals the redaction
    assert "base64" not in obj and "sha256" not in obj and "bytes" not in obj   # dropped, not stringified
    assert obj["format"] == "jpeg"                      # non-identifying shape still present


def test_fetch_photo_json_rejects_file_path(monkeypatch, capsys):
    # --json writes to stdout; pairing it with a file path (or "-") is a conflict, caught before
    # the card is even opened.
    from pathlib import Path

    import typer


    opened = {"n": 0}
    monkeypatch.setattr(signing, "open_reader",
                        lambda name=None: opened.__setitem__("n", opened["n"] + 1))

    with pytest.raises(typer.Exit):
        cli.fetch_photo_cmd(output=Path("out.jpg"), reader_name=None, overwrite=False,
                            json_output=True, json_pretty=False, redact=False)

    assert opened["n"] == 0
    assert "cannot be combined" in capsys.readouterr().err.lower()


def test_fetch_photo_json_rejects_explicit_default_path(monkeypatch, capsys):
    # A path that happens to spell out the default (cedula_foto.jpg) is still an explicit path:
    # with --json it must be refused, not silently treated as "no path given".
    from pathlib import Path

    import typer


    opened = {"n": 0}
    monkeypatch.setattr(signing, "open_reader",
                        lambda name=None: opened.__setitem__("n", opened["n"] + 1))

    with pytest.raises(typer.Exit):
        cli.fetch_photo_cmd(output=Path("cedula_foto.jpg"), reader_name=None, overwrite=False,
                            json_output=True, json_pretty=False, redact=False)

    assert opened["n"] == 0
    assert "cannot be combined" in capsys.readouterr().err.lower()


def test_fetch_photo_redact_without_json_is_refused(monkeypatch, capsys):
    # --redact only shapes the --json record; on a file or stream it would either write nothing or
    # silently save the full photo despite the privacy flag, so it is refused before opening the
    # card.
    import typer


    opened = {"n": 0}
    monkeypatch.setattr(signing, "open_reader",
                        lambda name=None: opened.__setitem__("n", opened["n"] + 1))

    with pytest.raises(typer.Exit):
        cli.fetch_photo_cmd(output=None, reader_name=None, overwrite=False,
                            json_output=False, json_pretty=False, redact=True)

    assert opened["n"] == 0
    assert "--json" in capsys.readouterr().err


# --- fetch-identity carries the same top-level redacted flag -------------------------------------

def test_fetch_identity_json_carries_redacted_flag(monkeypatch, capsys):

    card = {"bio": {0x01: "PEREZ"}, "doc_num": None, "mrz": None}
    monkeypatch.setattr(signing, "open_reader", lambda name=None: _FakeConn())
    monkeypatch.setattr(cli, "read_card", lambda conn: card)

    cli.fetch_identity_cmd(reader_name=None, json_output=True, json_pretty=False, redact=False)
    full = json.loads(capsys.readouterr().out)
    assert full["redacted"] is False and full["lastnames"] == "PEREZ"

    cli.fetch_identity_cmd(reader_name=None, json_output=True, json_pretty=False, redact=True)
    red = json.loads(capsys.readouterr().out)
    assert red["redacted"] is True and red["lastnames"] == "[REDACTED]"


# --- validate-ci (card-free check-digit command) --------------------------------------------------

def test_validate_ci_valid_exit_zero():
    result = runner.invoke(app, ["validate-ci", "12345672"])
    assert result.exit_code == 0
    assert "VALID" in result.stdout


def test_validate_ci_invalid_exit_one():
    result = runner.invoke(app, ["validate-ci", "12345678"])   # check digit should be 2, not 8
    assert result.exit_code == 1
    assert "INVALID" in result.stdout and "expected 2" in result.stdout


def test_validate_ci_malformed_exit_two():
    assert runner.invoke(app, ["validate-ci", "abc"]).exit_code == 2


def test_validate_ci_other_digit_sets_are_malformed_not_invalid():
    """1234567-2 in Arabic-Indic digits is a correct number, and it exited 1, INVALID. A script
    reading the exit code was told a correct cédula was wrong."""
    assert runner.invoke(app, ["validate-ci", "١٢٣٤٥٦٧٢"]).exit_code == 2


def test_validate_ci_json_full_record():
    result = runner.invoke(app, ["validate-ci", "1.234.567-2", "--json"])
    assert result.exit_code == 0
    obj = json.loads(result.stdout)
    assert obj["redacted"] is False and obj["valid"] is True
    assert obj["normalized"] == "12345672" and obj["expected_check_digit"] == "2"


def test_validate_ci_json_redact_drops_number_keeps_validity():
    result = runner.invoke(app, ["validate-ci", "12345678", "--json", "--redact"])
    assert result.exit_code == 1                                   # exit code still reflects validity
    assert json.loads(result.stdout) == {"schema_version": 2, "redacted": True, "valid": False}


def test_validate_ci_complete_prints_completed_number():
    result = runner.invoke(app, ["validate-ci", "1234567", "--complete"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "12345672"


def test_validate_ci_complete_with_redact_conflicts():
    assert runner.invoke(app, ["validate-ci", "1234567", "--complete", "--redact"]).exit_code == 2


# --- sign / sign-batch: auto-detect + dispatch ----------------------------------------------------

def test_detect_input_kind(tmp_path):
    from firmauy.signing import _detect_input_kind
    (tmp_path / "a.pdf").write_bytes(b"%PDF-1.7\n%body")
    assert _detect_input_kind(tmp_path / "a.pdf") == "pdf"
    (tmp_path / "a.xml").write_bytes(b"\xef\xbb\xbf  \n<?xml version='1.0'?><r/>")   # BOM + ws + decl
    assert _detect_input_kind(tmp_path / "a.xml") == "xml"
    (tmp_path / "b.xml").write_bytes(b"<root/>")                                      # bare root
    assert _detect_input_kind(tmp_path / "b.xml") == "xml"
    (tmp_path / "c.zip").write_bytes(b"PK\x03\x04 binary")
    assert _detect_input_kind(tmp_path / "c.zip") == "any"
    (tmp_path / "e").write_bytes(b"")                                                 # empty -> any
    assert _detect_input_kind(tmp_path / "e") == "any"
    (tmp_path / "f.txt").write_bytes(b"hello %PDF- not at the start")                 # not misdetected
    assert _detect_input_kind(tmp_path / "f.txt") == "any"


def test_resolve_sign_kind(tmp_path):
    from firmauy.cli import _resolve_sign_kind
    from firmauy.constants import SignAs
    (tmp_path / "a.pdf").write_bytes(b"%PDF-1.7")
    assert _resolve_sign_kind(tmp_path / "a.pdf", SignAs.auto) == "pdf"
    assert _resolve_sign_kind(tmp_path / "a.pdf", SignAs.cades) == "any"     # force detached over a PDF
    (tmp_path / "a.xml").write_bytes(b"<r/>")
    assert _resolve_sign_kind(tmp_path / "a.xml", SignAs.cades) == "any"
    assert _resolve_sign_kind(tmp_path / "a.xml", SignAs.pdf) == "pdf"       # forced


class _FakeCert:
    subject = issuer = None
    serial_number = 0x1A


class _FakeSession:
    """A session showing the given ``(id, certificate)`` pairs as certificate objects. None by
    default, so the certificate check before login concludes nothing and a test reaches the
    (patched) select_certificate as before."""

    def __init__(self, certs=()):
        self.certs = certs

    def get_objects(self, attrs=None):
        return iter([{pkcs11.Attribute.ID: obj_id,
                      pkcs11.Attribute.VALUE: cert.public_bytes(serialization.Encoding.DER)}
                     for obj_id, cert in self.certs])


class _FakeToken:
    """A token that reports ``flags`` as its PIN state, shows ``certs`` in every session, fails a
    login with ``login_error`` when given, and records the PIN of each session it opens (None for
    a session without login)."""

    label = "tok"

    def __init__(self, *, certs=(), flags=pkcs11.TokenFlag(0), login_error=None):
        self.certs = certs
        self.flags = flags
        self.login_error = login_error
        self.logins = []

    def open(self, user_pin=None):
        self.logins.append(user_pin)
        token = self

        class _Ctx:
            def __enter__(self_):
                if user_pin is not None and token.login_error is not None:
                    raise token.login_error
                return _FakeSession(token.certs)

            def __exit__(self_, *a):
                return False
        return _Ctx()


def _patch_signing(monkeypatch):
    """Patch the PKCS#11/cert path so sign/sign-batch reach the dispatch without a card. Returns a
    list that records (kind, output_path) for each worker call."""
    calls = []
    monkeypatch.setattr(signing, "load_pkcs11_lib", lambda lib: object())
    monkeypatch.setattr(signing, "find_token", lambda lib, label: _FakeToken())
    monkeypatch.setattr(cli, "get_pin", lambda *a, **k: "1234")
    monkeypatch.setattr(signing, "select_certificate",
                        lambda session, cid, notify=None: (b"\x01", _FakeCert()))
    monkeypatch.setattr(signing, "get_common_name", lambda name: "SIGNER")
    monkeypatch.setattr(signing, "normalize_issuer_name", lambda s: "ISSUER")
    monkeypatch.setattr(signing, "PKCS11Signer", lambda **k: object())
    monkeypatch.setattr(signing, "_make_raw_signer", lambda session, key_id: (lambda data: b"sig"))
    monkeypatch.setattr(cli, "_sign_one_pdf", lambda **k: calls.append(("pdf", k["output_pdf"])))
    monkeypatch.setattr(cli, "_sign_one_xml", lambda **k: calls.append(("xml", k["output_xml"])))
    monkeypatch.setattr(cli, "_sign_one_cms", lambda **k: calls.append(("cms", k["output_p7s"])))
    return calls


def test_sign_dispatches_pdf_xml_any(monkeypatch, tmp_path):
    calls = _patch_signing(monkeypatch)
    (tmp_path / "doc.pdf").write_bytes(b"%PDF-1.7\n")
    assert runner.invoke(app, ["sign", str(tmp_path / "doc.pdf")]).exit_code == 0
    assert calls[-1] == ("pdf", tmp_path / "doc_firmado.pdf")

    (tmp_path / "f.xml").write_bytes(b"<r/>")
    assert runner.invoke(app, ["sign", str(tmp_path / "f.xml")]).exit_code == 0
    assert calls[-1] == ("xml", tmp_path / "f_firmado.xml")

    (tmp_path / "p.zip").write_bytes(b"PKbin")
    assert runner.invoke(app, ["sign", str(tmp_path / "p.zip")]).exit_code == 0
    assert calls[-1] == ("cms", tmp_path / "p.zip.p7s")


def test_sign_as_cades_forces_detached_over_pdf(monkeypatch, tmp_path):
    calls = _patch_signing(monkeypatch)
    (tmp_path / "doc.pdf").write_bytes(b"%PDF-1.7\n")
    r = runner.invoke(app, ["sign", str(tmp_path / "doc.pdf"), "--as", "cades"])
    assert r.exit_code == 0, r.output
    assert calls == [("cms", tmp_path / "doc.pdf.p7s")]      # detached .p7s, not _firmado.pdf


def test_sign_warns_pdf_only_option_on_non_pdf(monkeypatch, tmp_path):
    calls = _patch_signing(monkeypatch)
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    (tmp_path / "f.xml").write_bytes(b"<r/>")
    r = runner.invoke(app, ["sign", str(tmp_path / "f.xml"), "--image", str(tmp_path / "logo.png")])
    assert r.exit_code == 0, r.output
    assert "ignored for a XML signature" in r.output         # the Note (PDF-only option on a non-PDF)
    assert calls[-1][0] == "xml"                              # still routed to XML


def test_sign_batch_mixed_folder_one_session(monkeypatch, tmp_path):
    calls = _patch_signing(monkeypatch)
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.pdf").write_bytes(b"%PDF-1.7\n")
    (src / "b.xml").write_bytes(b"<r/>")
    (src / "c.zip").write_bytes(b"PKbin")
    out = tmp_path / "out"
    r = runner.invoke(app, ["sign-batch", "--input-dir", str(src), "--output-dir", str(out)])
    assert r.exit_code == 0, r.output
    assert sorted(k for k, _ in calls) == ["cms", "pdf", "xml"]     # one of each, one session
    assert "Signed: 3/3" in r.output
    by_kind = {k: o for k, o in calls}
    assert by_kind["pdf"].name == "a_firmado.pdf" and by_kind["pdf"].parent == out
    assert by_kind["xml"].name == "b_firmado.xml" and by_kind["xml"].parent == out
    assert by_kind["cms"].name == "c.zip.p7s" and by_kind["cms"].parent == out


def test_sign_batch_skips_a_planted_symlink_and_says_so(monkeypatch, tmp_path):
    """A link planted in the folder used to get its target signed, whatever file on the disk it
    pointed at. Skipped now, and named, because a batch that drops a file without a word looks
    like one that lost it. Passed as an argument, the same file is signed: that is the way to do
    it on purpose."""
    calls = _patch_signing(monkeypatch)
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.pdf").write_bytes(b"%PDF-1.7\n")
    private = tmp_path / "private.pdf"
    private.write_bytes(b"%PDF-1.7\n")
    (src / "b.pdf").symlink_to(private)
    out = tmp_path / "out"

    r = runner.invoke(app, ["sign-batch", "--input-dir", str(src), "--output-dir", str(out)])
    assert r.exit_code == 0, r.output
    assert [o.name for _, o in calls] == ["a_firmado.pdf"]
    assert "Skipping" in r.output and "b.pdf" in r.output

    calls.clear()
    r = runner.invoke(app, ["sign-batch", str(src / "b.pdf"), "--output-dir", str(out)])
    assert r.exit_code == 0, r.output
    assert [o.name for _, o in calls] == ["b_firmado.pdf"]


def test_sign_batch_detects_output_collision(monkeypatch, tmp_path):
    # Two same-stem files of different extensions both detected as PDF would map to the same output
    # (a_firmado.pdf). The batch must refuse up front, before signing anything (F1).
    calls = _patch_signing(monkeypatch)
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.pdf").write_bytes(b"%PDF-1.7\n")
    (src / "a.txt").write_bytes(b"%PDF-1.7\n")      # different ext, same stem, also detected pdf
    out = tmp_path / "out"
    r = runner.invoke(app, ["sign-batch", "--input-dir", str(src), "--output-dir", str(out)])
    assert r.exit_code == 1
    assert "collision" in r.output.lower()
    assert "a_firmado.pdf" in r.output
    assert calls == []                              # aborted before signing anything
    assert not out.exists()                         # and before even creating the output dir


def test_sign_batch_no_false_collision_for_distinct_outputs(monkeypatch, tmp_path):
    # Same stem but different kinds (pdf vs cades) produce distinct outputs and must NOT be flagged.
    calls = _patch_signing(monkeypatch)
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.pdf").write_bytes(b"%PDF-1.7\n")       # -> a_firmado.pdf
    (src / "a.bin").write_bytes(b"\x00\x01rawbytes") # -> a.bin.p7s
    out = tmp_path / "out"
    r = runner.invoke(app, ["sign-batch", "--input-dir", str(src), "--output-dir", str(out)])
    assert r.exit_code == 0, r.output
    assert sorted(k for k, _ in calls) == ["cms", "pdf"]
    assert "Signed: 2/2" in r.output


def test_signing_session_yields_context_and_stays_silent(monkeypatch, capsys):
    # The shared PKCS#11 bootstrap of every sign-* command: open the session, select the cert, and
    # yield a backend-agnostic context whose lazy factories build the pyHanko / raw signers the
    # command bodies consume. The session itself prints nothing: the display fields travel on the
    # context and the CLI prints the identity block via _print_signing_info.
    monkeypatch.setattr(signing, "load_pkcs11_lib", lambda lib: object())
    monkeypatch.setattr(signing, "find_token", lambda lib, label: _FakeToken())
    monkeypatch.setattr(signing, "select_certificate",
                        lambda session, cid, notify=None: (b"\x01", _FakeCert()))
    monkeypatch.setattr(signing, "get_common_name", lambda name: "SIGNER")
    monkeypatch.setattr(signing, "normalize_issuer_name", lambda s: "ISSUER")
    monkeypatch.setattr(signing, "PKCS11Signer", lambda **kw: ("pk-signer", kw))
    monkeypatch.setattr(signing, "_make_raw_signer", lambda session, key_id: ("raw-signer", key_id))

    common = dict(native=False, reader=None, pkcs11_lib="lib.so", token_label=None, cert_id=None)

    with cli._signing_session(**common, pin="1234") as ctx:
        assert ctx.cert is not None
        assert (ctx.signer_name, ctx.issuer_name) == ("SIGNER", "ISSUER")
        assert ctx.cert_serial == format(_FakeCert.serial_number, "X")     # "1A"
        # Display fields for the CLI's identity block (the session no longer prints it).
        assert (ctx.source_caption, ctx.source_display, ctx.key_id) == ("Token", "tok", b"\x01")
        # The PKCS#11 backend builds a PKCS11Signer bound to the selected key, and the XML raw signer
        # via _make_raw_signer; each factory is memoized (built at most once).
        pk = ctx.pyhanko_signer()
        assert pk[0] == "pk-signer" and pk[1]["cert_id"] == b"\x01"
        assert ctx.pyhanko_signer() is pk                                  # cached, not rebuilt
        assert ctx.raw_signer() == ("raw-signer", b"\x01")
        last_ctx = ctx
    assert capsys.readouterr().out == ""                    # presentation-free session

    # The CLI prints the identity block from the context; --quiet suppresses it entirely.
    cli._print_signing_info(last_ctx, tsa_url=None, quiet=False)
    out = capsys.readouterr().out
    assert "SIGNER" in out and "ISSUER" in out and "tok" in out
    cli._print_signing_info(last_ctx, tsa_url=None, quiet=True)
    assert capsys.readouterr().out == ""                                # silent under --quiet


def test_signing_session_notes_backend_mismatched_options(monkeypatch):
    # The backend-option pre-flight lives inside _signing_session (shared by all 8 sign commands),
    # so no command can forget it: --reader without --native is reported through notify, pre-PIN.
    monkeypatch.setattr(signing, "load_pkcs11_lib", lambda lib: object())
    monkeypatch.setattr(signing, "find_token", lambda lib, label: _FakeToken())
    monkeypatch.setattr(signing, "select_certificate",
                        lambda session, cid, notify=None: (b"\x01", _FakeCert()))
    monkeypatch.setattr(signing, "get_common_name", lambda name: "SIGNER")
    monkeypatch.setattr(signing, "normalize_issuer_name", lambda s: "ISSUER")

    notes = []
    with cli._signing_session(native=False, reader="ACS ACR39U 00 00", pkcs11_lib="lib.so",
                              token_label=None, cert_id=None, pin="1234", notify=notes.append):
        pass
    assert any("--reader only applies to --native" in n for n in notes)

    # Without a notify sink (the public API), the note is dropped and nothing is printed.
    with cli._signing_session(native=False, reader="ACS ACR39U 00 00", pkcs11_lib="lib.so",
                              token_label=None, cert_id=None, pin="1234"):
        pass


def _pkcs11_session(**kwargs):
    return signing._signing_session(native=False, reader=None, pkcs11_lib="lib.so",
                                    token_label=None, cert_id=None, **kwargs)


@pytest.mark.parametrize("flags, error", [
    (pkcs11.TokenFlag.USER_PIN_LOCKED, PinLockedError),
    (pkcs11.TokenFlag.USER_PIN_FINAL_TRY, PinLastTryError),
], ids=["locked", "final-try"])
def test_pkcs11_session_refuses_the_pin_state_the_token_reports_before_asking(
        monkeypatch, flags, error):
    # The PKCS#11 counterpart of native verify_pin's guard, and earlier than it: the PIN is not
    # even asked for, so a GUI never shows a dialog whose answer could only lock the card.
    token = _FakeToken(flags=flags)
    monkeypatch.setattr(signing, "load_pkcs11_lib", lambda lib: object())
    monkeypatch.setattr(signing, "find_token", lambda lib, label: token)
    asked = []

    with pytest.raises(error) as exc:
        with _pkcs11_session(pin_provider=lambda: asked.append(1) or "1234"):
            pass

    assert type(exc.value) is error
    assert asked == []
    assert token.logins == [None]         # the certificate check's session, never a login


def test_pkcs11_session_asks_once_when_the_count_is_only_low(monkeypatch):
    # USER_PIN_COUNT_LOW means a wrong PIN was entered since the last good one. That is no reason
    # to refuse, and SoftHSM sets it after any wrong PIN.
    token = _FakeToken(flags=pkcs11.TokenFlag.USER_PIN_COUNT_LOW)
    monkeypatch.setattr(signing, "load_pkcs11_lib", lambda lib: object())
    monkeypatch.setattr(signing, "find_token", lambda lib, label: token)
    monkeypatch.setattr(signing, "select_certificate",
                        lambda session, cid, notify=None: (b"\x01", _FakeCert()))
    monkeypatch.setattr(signing, "get_common_name", lambda name: "SIGNER")
    monkeypatch.setattr(signing, "normalize_issuer_name", lambda s: "ISSUER")
    asked = []

    with _pkcs11_session(pin_provider=lambda: asked.append(1) or "1234"):
        pass

    assert asked == [1]
    assert token.logins == [None, "1234"]


@pytest.mark.parametrize("cert_fixture, cert_id, code", [
    ("cert_expired", None, "certificate_not_valid"),
    ("cert_valid", "02", "certificate_not_found"),
], ids=["expired", "unknown-cert-id"])
def test_cli_pkcs11_rejects_a_certificate_problem_before_the_pin(
        monkeypatch, tmp_path, request, cert_fixture, cert_id, code):
    # The PKCS#11 counterpart of test_cli_native_rejects_expired_certificate. The token shows its
    # certificate without login, as the cédula does with both middlewares, so the problem is found
    # before the PIN is read, where a mistyped PIN would have spent a try and hidden it.
    token = _FakeToken(certs=[(b"\x01", request.getfixturevalue(cert_fixture))])
    monkeypatch.setattr(signing, "load_pkcs11_lib", lambda lib: object())
    monkeypatch.setattr(signing, "find_token", lambda lib, label: token)

    def _no_pin(*a, **k):
        raise AssertionError("the PIN must not be requested for a certificate problem")
    monkeypatch.setattr(cli, "get_pin", _no_pin)

    src = tmp_path / "data.bin"
    src.write_bytes(b"payload")
    args = ["sign-any", str(src), str(tmp_path / "data.bin.p7s"), "--json"]
    if cert_id:
        args += ["--cert-id", cert_id]
    r = runner.invoke(app, args)

    assert r.exit_code == 1
    assert json.loads(r.stdout)["error_code"] == code
    assert token.logins == [None]


def _list_certs_with(monkeypatch, token, *args):
    monkeypatch.setattr(cli, "load_pkcs11_lib", lambda lib: object())
    monkeypatch.setattr(cli, "find_token", lambda lib, label: token)
    return runner.invoke(app, ["list-certs", "--json", *args])


def test_list_certs_with_a_pin_refuses_the_final_try(monkeypatch):
    token = _FakeToken(flags=pkcs11.TokenFlag.USER_PIN_FINAL_TRY)

    def _no_pin(*a, **k):
        raise AssertionError("the PIN must not be read when the token is on its last try")
    monkeypatch.setattr(cli, "get_pin", _no_pin)

    r = _list_certs_with(monkeypatch, token, "--pin-source", "stdin")

    assert r.exit_code == 1
    assert json.loads(r.stdout)["error_code"] == "pin_error"
    assert token.logins == []


def test_list_certs_without_a_pin_ignores_the_pin_state(monkeypatch, cert_valid):
    # Without a PIN nothing logs in, so a locked PIN is no reason not to list public certificates.
    token = _FakeToken(certs=[(b"\x01", cert_valid)], flags=pkcs11.TokenFlag.USER_PIN_LOCKED)

    r = _list_certs_with(monkeypatch, token)

    assert r.exit_code == 0, r.output
    assert len(json.loads(r.stdout)["certificates"]) == 1
    assert token.logins == [None]


def test_list_certs_reports_a_wrong_pin_as_incorrect_pin(monkeypatch):
    # Before, the module's own PinIncorrect escaped untranslated, and --json said operation_failed.
    token = _FakeToken(login_error=pkcs11.exceptions.PinIncorrect())
    monkeypatch.setattr(cli, "get_pin", lambda *a, **k: "1234")

    r = _list_certs_with(monkeypatch, token, "--pin-source", "stdin")

    assert r.exit_code == 1
    assert json.loads(r.stdout)["error_code"] == "incorrect_pin"


class _FakeHybridWriter:
    """Stands in for IncrementalPdfFileWriter: reports a hybrid-xref PDF and records the strict
    flag it was opened with, so _sign_one_pdf's hybrid-xref branch can be tested without a
    hand-crafted hybrid PDF."""
    last_strict = None

    def __init__(self, stream, strict=True):
        type(self).last_strict = strict
        import types as _t
        self.prev = _t.SimpleNamespace(xrefs=_t.SimpleNamespace(hybrid_xrefs_present=True))


_SIGN_ONE_PDF_ARGS = dict(
    pkcs11_signer=object(), signer_name="S", issuer_name="I", cert_serial="1A",
    timestamper=None, meta=object(), page=-1, x1=0, y1=0, x2=1, y2=1, timezone="UTC",
    field_name="Sig1", force=False, overwrite=False,
)


def test_sign_one_pdf_rejects_hybrid_xref_by_default(monkeypatch, tmp_path):
    # A hybrid cross-reference PDF is refused before any signing work, with a message that names
    # both the qpdf workaround and the opt-in flag.
    monkeypatch.setattr(signing, "IncrementalPdfFileWriter", _FakeHybridWriter)
    src = tmp_path / "in.pdf"
    src.write_bytes(b"%PDF-1.7\n")

    with pytest.raises(RuntimeError) as ei:
        cli._sign_one_pdf(input_pdf=src, output_pdf=tmp_path / "out.pdf", **_SIGN_ONE_PDF_ARGS)
    msg = str(ei.value)
    assert "hybrid cross-reference" in msg
    assert "qpdf" in msg and "--allow-hybrid-xref" in msg
    assert _FakeHybridWriter.last_strict is True                 # default opens strict


def test_sign_one_pdf_allows_hybrid_xref_with_flag(monkeypatch, tmp_path):
    # --allow-hybrid-xref opens the PDF non-strict and warns (via notify) instead of refusing; we
    # stop right after the guard (before the real pyHanko machinery) via a sentinel from
    # enumerate_sig_fields.
    monkeypatch.setattr(signing, "IncrementalPdfFileWriter", _FakeHybridWriter)

    class _Sentinel(Exception):
        pass

    def _stop(_writer):
        raise _Sentinel
    monkeypatch.setattr(signing.fields, "enumerate_sig_fields", _stop)

    src = tmp_path / "in.pdf"
    src.write_bytes(b"%PDF-1.7\n")
    notes = []
    with pytest.raises(_Sentinel):                               # got past the guard, no RuntimeError
        cli._sign_one_pdf(input_pdf=src, output_pdf=tmp_path / "out.pdf",
                          allow_hybrid_xref=True, notify=notes.append, **_SIGN_ONE_PDF_ARGS)
    assert _FakeHybridWriter.last_strict is False                # opened non-strict to allow signing
    joined = " ".join(notes)
    assert "hybrid cross-reference sections" in joined and "--allow-hybrid-xref" in joined


def test_doctor_notes_options_that_do_not_apply(monkeypatch):
    """doctor gets the same pre-flight courtesy as the sign commands: an option that does not
    apply to the chosen mode is called out on stderr instead of silently ignored."""
    monkeypatch.setattr(
        cli, "_collect_doctor_checks",
        lambda native, reader, lib: [{"status": "PASS", "name": "stub", "detail": "", "fix": None}],
    )

    # --pkcs11-lib alongside --native: the native checks use no PKCS#11 module.
    r = runner.invoke(app, ["doctor", "--native", "--pkcs11-lib", "/custom/module.so"])
    assert r.exit_code == 0
    assert "--pkcs11-lib is ignored with --native" in r.output

    # --reader without --native: the PKCS#11 checks use no PC/SC reader.
    r = runner.invoke(app, ["doctor", "--reader", "ACS ACR 38U-CCID 00 00"])
    assert r.exit_code == 0
    assert "--reader only applies to --native" in r.output

    # Coherent invocations stay note-free.
    for args in (["doctor", "--native"], ["doctor", "--pkcs11-lib", "/custom/module.so"]):
        r = runner.invoke(app, args)
        assert r.exit_code == 0
        assert "Note:" not in r.output


def test_the_staging_file_is_not_a_predictable_name(tmp_path):
    """The old staging path was `<name>.part`, which anybody could predict and pre-create.

    os.replace protects the *destination* from a symlink, and the staging path had no guard at
    all, so on a shared or world-writable directory a symlink planted at the predictable name
    would have had the signed document written through it. mkstemp gives an unpredictable name
    and O_EXCL, which refuses to open anything that already exists.
    """
    from firmauy.signing import _staged_output

    out = tmp_path / "documento.pdf"
    with _staged_output(out) as handle:
        # What is actually on disk while the write is in flight, rather than what the helper
        # says it is doing.
        staged = [p.name for p in tmp_path.iterdir()]
        handle.write(b"%PDF-1.7\n")

    assert not any(n == "documento.pdf.part" for n in staged)
    assert len(staged) == 1 and staged[0].endswith(".part")
    # And it does not embed the output's name, which would spend the filesystem's name budget.
    assert "documento" not in staged[0]
    assert out.read_bytes() == b"%PDF-1.7\n"


def test_a_symlink_planted_at_the_staging_path_cannot_capture_the_output(tmp_path):
    """The attack the predictable name allowed, run against the current code.

    The staging name is unpredictable now, so this plants a symlink at every name the old scheme
    would have used and confirms none of them is followed and nothing lands on the target.
    """
    from firmauy.signing import _atomic_write_bytes

    victim = tmp_path / "victima.txt"
    victim.write_bytes(b"DO NOT TOUCH")
    out = tmp_path / "documento.xml"
    (tmp_path / "documento.xml.part").symlink_to(victim)

    _atomic_write_bytes(out, b"<signed/>")

    assert victim.read_bytes() == b"DO NOT TOUCH"
    assert out.read_bytes() == b"<signed/>"
    assert not out.is_symlink()


def test_a_failed_write_leaves_nothing_behind(tmp_path):
    """Including the staging file, whose name nobody outside the helper knows to clean up."""
    from firmauy.signing import _staged_output

    out = tmp_path / "documento.pdf"
    with pytest.raises(RuntimeError):
        with _staged_output(out) as _handle:
            raise RuntimeError("the card was pulled")

    assert list(tmp_path.iterdir()) == []


def test_the_staging_file_does_not_decide_the_output_permissions(tmp_path):
    """mkstemp creates at 0600 and os.replace keeps it, so without a deliberate chmod every
    signed document would silently come out private. Making the staging name unpredictable was
    about stopping a symlink from capturing the output; it has nothing to say about who may read
    the result, and quietly answering that question too is a change nobody asked for."""
    import os
    import stat

    from firmauy.signing import _atomic_write_bytes

    previous = os.umask(0o022)
    try:
        out = tmp_path / "nuevo.xml"
        _atomic_write_bytes(out, b"<signed/>")
        assert stat.S_IMODE(out.stat().st_mode) == 0o644
    finally:
        os.umask(previous)


def test_overwriting_keeps_the_mode_the_file_already_had(tmp_path):
    """Somebody who ran chmod 664 on their output meant it, and signing over it is not the moment
    to overrule them."""
    import os
    import stat

    from firmauy.signing import _atomic_write_bytes

    out = tmp_path / "compartido.xml"
    out.write_bytes(b"<old/>")
    os.chmod(out, 0o664)

    _atomic_write_bytes(out, b"<signed/>")

    assert stat.S_IMODE(out.stat().st_mode) == 0o664


def test_the_staged_handle_is_closed_even_when_the_caller_raises(tmp_path):
    """The context manager owns the file. Handing back a raw descriptor made every caller
    responsible for a close they could skip by raising first, leaking it onto a path that had
    already been unlinked."""
    from firmauy.signing import _staged_output

    handle = None
    with pytest.raises(RuntimeError):
        with _staged_output(tmp_path / "x.bin") as h:
            handle = h
            raise RuntimeError("the card was pulled")

    assert handle is not None and handle.closed


def test_a_symlinked_output_does_not_donate_its_targets_permissions(tmp_path):
    """os.replace keeps the bytes safe and preservation was reading the mode with stat(), which
    follows the link. A symlink planted at the output, pointed at anything world-writable, then
    handed its mode to the signed document: the right bytes with somebody else's permissions,
    which is half a defence."""
    import os
    import stat

    from firmauy.signing import _atomic_write_bytes

    previous = os.umask(0o022)
    try:
        victim = tmp_path / "victima.txt"
        victim.write_bytes(b"DO NOT TOUCH")
        os.chmod(victim, 0o777)
        out = tmp_path / "salida.xml"
        out.symlink_to(victim)

        _atomic_write_bytes(out, b"<signed/>")

        assert stat.S_IMODE(out.stat().st_mode) == 0o644     # the umask's answer, not the link's
        assert not out.is_symlink()
        assert victim.read_bytes() == b"DO NOT TOUCH"
    finally:
        os.umask(previous)


def test_setuid_is_not_inherited_by_a_freshly_signed_document(tmp_path):
    """Preserving the mode of the file being replaced is about honouring a chmod 664, not about
    carrying every bit across. A setuid bit on a signed document is not something anybody meant
    to ask for."""
    import os
    import stat

    from firmauy.signing import _atomic_write_bytes

    out = tmp_path / "raro.bin"
    out.write_bytes(b"old")
    os.chmod(out, 0o4755)

    _atomic_write_bytes(out, b"new")

    assert stat.S_IMODE(out.stat().st_mode) == 0o755


def test_a_long_output_name_is_still_signable(tmp_path):
    """The staging name used to embed the output's, adding 23 bytes to a basename that may
    already be near NAME_MAX. A 233-byte name the filesystem accepts happily then failed with
    ENAMETOOLONG on a path that can hold 255."""
    from firmauy.signing import _atomic_write_bytes

    out = tmp_path / ("a" * 250 + ".xml")
    _atomic_write_bytes(out, b"<signed/>")

    assert out.read_bytes() == b"<signed/>"


def test_the_staging_file_is_private_while_it_holds_the_document(tmp_path):
    """An unpredictable name stops somebody planting a file there and says nothing about somebody
    watching the directory and reading one. The staging file used to sit at 0644 for the whole
    signing operation while holding, for a PDF, essentially the entire document, even when the
    destination it was about to replace was 0600."""
    import os
    import stat

    from firmauy.signing import _staged_output

    previous = os.umask(0o022)
    try:
        out = tmp_path / "privado.pdf"
        out.write_bytes(b"old")
        os.chmod(out, 0o600)

        seen = []
        with _staged_output(out) as handle:
            handle.write(b"SECRET DOCUMENT")
            handle.flush()
            staging = [p for p in tmp_path.iterdir() if p.name.startswith(".firmauy-")]
            seen = [stat.S_IMODE(p.stat().st_mode) for p in staging]

        assert seen == [0o600], "the document was readable while it was being written"
        assert stat.S_IMODE(out.stat().st_mode) == 0o600
    finally:
        os.umask(previous)


def test_without_overwrite_a_file_that_appears_mid_signing_survives(tmp_path):
    """The callers check `path.exists()` before touching the card, and then a certificate read, a
    PIN and possibly a TSA round trip happen before the write. Anything appearing in that window
    used to be destroyed silently, with no --overwrite anywhere in sight."""
    from firmauy.errors import OutputExistsError
    from firmauy.signing import _staged_output

    out = tmp_path / "salida.xml"

    with pytest.raises(OutputExistsError):
        with _staged_output(out, overwrite=False) as handle:
            handle.write(b"<mine/>")
            out.write_bytes(b"<from another process/>")   # the race, made deterministic

    assert out.read_bytes() == b"<from another process/>"
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".firmauy-")]


def test_with_overwrite_replacing_still_works(tmp_path):
    from firmauy.signing import _atomic_write_bytes

    out = tmp_path / "salida.xml"
    out.write_bytes(b"<old/>")

    _atomic_write_bytes(out, b"<new/>", overwrite=True)

    assert out.read_bytes() == b"<new/>"


def test_a_dangling_symlink_counts_as_occupied(tmp_path):
    """`Path.exists()` reports a broken link as absent, so the early check waves it through.
    os.link does not, which is the second reason the guarantee belongs at the commit."""
    from firmauy.errors import OutputExistsError
    from firmauy.signing import _atomic_write_bytes

    out = tmp_path / "roto.xml"
    out.symlink_to(tmp_path / "no-existe")
    assert out.exists() is False

    with pytest.raises(OutputExistsError):
        _atomic_write_bytes(out, b"<signed/>", overwrite=False)


def _no_hard_links(src, dst, *args, **kwargs):
    """What link(2) answers on FAT32 and exFAT, which keep no link count at all."""
    import errno

    raise PermissionError(errno.EPERM, "Operation not permitted", str(src), None, str(dst))


def test_a_filesystem_without_hard_links_still_commits_without_clobbering(tmp_path, monkeypatch):
    """A pendrive is FAT32 or exFAT, neither has hard links, and os.link answers EPERM there. That
    used to come back as a bare OSError after the PIN was typed and the card had signed, and only
    --overwrite got past it. Made deterministic by refusing the link the way the kernel does."""
    import os

    from firmauy.signing import _atomic_write_bytes

    monkeypatch.setattr(os, "link", _no_hard_links)
    out = tmp_path / "salida.xml"

    _atomic_write_bytes(out, b"<signed/>", overwrite=False)

    assert out.read_bytes() == b"<signed/>"
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".firmauy-")]


def test_the_fallback_commit_still_refuses_to_clobber(tmp_path, monkeypatch):
    """Without a link, the reservation is what keeps the guarantee: an exclusive create fails on
    anything already at the name, so what appeared mid-signing survives, as it does with one."""
    import os

    from firmauy.errors import OutputExistsError
    from firmauy.signing import _staged_output

    monkeypatch.setattr(os, "link", _no_hard_links)
    out = tmp_path / "salida.xml"

    with pytest.raises(OutputExistsError):
        with _staged_output(out, overwrite=False) as handle:
            handle.write(b"<mine/>")
            out.write_bytes(b"<from another process/>")

    assert out.read_bytes() == b"<from another process/>"
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".firmauy-")]


def test_a_failed_rename_takes_its_empty_reservation_with_it(tmp_path, monkeypatch):
    """The reservation is an empty file under the output's name. Left behind, the next attempt
    would refuse to sign over it, and it could pass for the document."""
    import errno
    import os

    from firmauy.signing import _atomic_write_bytes

    def disk_says_no(src, dst):
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(os, "link", _no_hard_links)
    monkeypatch.setattr(os, "replace", disk_says_no)
    out = tmp_path / "salida.xml"

    with pytest.raises(OSError) as failure:
        _atomic_write_bytes(out, b"<signed/>", overwrite=False)

    assert failure.value.errno == errno.EIO
    assert not out.exists()
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".firmauy-")]


def test_any_other_link_failure_is_not_taken_for_a_missing_feature(tmp_path, monkeypatch):
    """EACCES is the directory refusing, not the filesystem lacking links. It propagates as it
    is, and nothing is created under the output's name on the way."""
    import errno
    import os

    from firmauy.signing import _atomic_write_bytes

    def directory_says_no(src, dst, *args, **kwargs):
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(os, "link", directory_says_no)
    out = tmp_path / "salida.xml"

    with pytest.raises(PermissionError) as failure:
        _atomic_write_bytes(out, b"<signed/>", overwrite=False)

    assert failure.value.errno == errno.EACCES
    assert not out.exists()
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".firmauy-")]


def test_the_file_is_still_private_at_the_moment_it_is_committed(tmp_path):
    """The narrowing used to be undone before the commit, so the staging file sat at its final,
    possibly world-readable mode for the instant between. Small window, real one, and "private
    while it holds data" was not literally true until the widening moved after the commit."""
    import os
    import stat

    from firmauy.signing import _atomic_write_bytes

    seen = {}
    real_replace, real_link = os.replace, os.link

    def spy_replace(src, dst):
        seen["replace"] = stat.S_IMODE(os.stat(src).st_mode)
        return real_replace(src, dst)

    def spy_link(src, dst):
        seen["link"] = stat.S_IMODE(os.stat(src).st_mode)
        return real_link(src, dst)

    previous = os.umask(0o022)
    os.replace, os.link = spy_replace, spy_link
    try:
        _atomic_write_bytes(tmp_path / "a.xml", b"x")
        _atomic_write_bytes(tmp_path / "b.xml", b"x", overwrite=False)
    finally:
        os.replace, os.link = real_replace, real_link
        os.umask(previous)

    assert seen == {"replace": 0o600, "link": 0o600}
    # And the finished files still end up with the ordinary mode.
    assert stat.S_IMODE((tmp_path / "a.xml").stat().st_mode) == 0o644


def test_the_group_of_the_replaced_file_survives(tmp_path):
    """An atomic replace swaps an inode, so the group goes with it unless it is put back. The mode
    then reads 0640 before and after while a different set of people can open the document."""
    import os
    import stat

    from firmauy.signing import _atomic_write_bytes

    others = [g for g in os.getgroups() if g != os.getgid()]
    if not others:
        pytest.skip("the test user belongs to no second group")

    out = tmp_path / "grupal.xml"
    out.write_bytes(b"old")
    os.chown(out, -1, others[0])
    os.chmod(out, 0o640)

    _atomic_write_bytes(out, b"<signed/>")

    assert out.stat().st_gid == others[0]
    assert stat.S_IMODE(out.stat().st_mode) == 0o640


def _acl_of(path) -> bytes | None:
    import os

    try:
        return os.getxattr(path, "system.posix_acl_access")
    except (OSError, AttributeError):
        return None


def _set_default_acl(directory, spec) -> bool:
    """Give `directory` a default ACL with setfacl. False when the platform cannot."""
    import shutil
    import subprocess

    if not shutil.which("setfacl"):
        return False
    return subprocess.run(["setfacl", "-d", "-m", spec, str(directory)],
                          capture_output=True).returncode == 0


def test_an_inherited_acl_does_not_widen_a_replaced_file(tmp_path):
    """The measured case. A directory with a default ACL hands it to every file created in it,
    the staging file included, so replacing a document that had no such grant published one that
    did: same mode digits, readable by somebody who could not read it before."""
    import subprocess

    if not _set_default_acl(tmp_path, "u:nobody:r"):
        pytest.skip("no ACL support here")

    from firmauy.signing import _atomic_write_bytes

    out = tmp_path / "doc.xml"
    out.write_bytes(b"old")
    subprocess.run(["setfacl", "-b", str(out)], capture_output=True)
    before = _acl_of(out)

    _atomic_write_bytes(out, b"<signed/>")

    assert _acl_of(out) == before, "the signed file allows somebody the original did not"


def test_an_explicit_acl_on_the_replaced_file_is_kept(tmp_path):
    """The other direction: preserving means matching what the replaced file allowed, which
    includes a grant somebody made on purpose."""
    import shutil
    import subprocess

    if not shutil.which("setfacl"):
        pytest.skip("no ACL support here")

    from firmauy.signing import _atomic_write_bytes

    out = tmp_path / "conacl.xml"
    out.write_bytes(b"old")
    if subprocess.run(["setfacl", "-m", "u:nobody:r", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("no ACL support here")
    before = _acl_of(out)
    assert before is not None

    _atomic_write_bytes(out, b"<signed/>")

    assert _acl_of(out) == before


# --- when the access control cannot be carried across, nothing is published ----
#
# These patch the syscall rather than arranging real privileges, because the failure is what is
# under test and it needs no root to be worth guarding. The previous version swallowed all three
# and published anyway: mode digits preserved, the people they applied to changed.

def _fails_to_preserve(monkeypatch, name, exc):
    import os

    monkeypatch.setattr(os, name, mock.Mock(side_effect=exc))


def test_a_group_that_cannot_be_restored_stops_the_write(tmp_path, monkeypatch):
    """A file whose group the process cannot set: without this, its 0640 was reapplied to the
    process's own group and a different set of people could read the signed document."""
    import os

    from firmauy.errors import OutputAccessControlError
    from firmauy.signing import _atomic_write_bytes

    out = tmp_path / "grupal.xml"
    out.write_bytes(b"ORIGINAL")
    os.chmod(out, 0o640)
    _fails_to_preserve(monkeypatch, "fchown", PermissionError(1, "Operation not permitted"))

    with pytest.raises(OutputAccessControlError):
        _atomic_write_bytes(out, b"<signed/>")

    assert out.read_bytes() == b"ORIGINAL"
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".firmauy-")]


def test_an_acl_that_cannot_be_restored_stops_the_write(tmp_path, monkeypatch):
    from firmauy.errors import OutputAccessControlError
    from firmauy.signing import _atomic_write_bytes

    out = tmp_path / "conacl.xml"
    out.write_bytes(b"ORIGINAL")
    _fails_to_preserve(monkeypatch, "removexattr", OSError(5, "Input/output error"))

    with pytest.raises(OutputAccessControlError):
        _atomic_write_bytes(out, b"<signed/>")

    assert out.read_bytes() == b"ORIGINAL"


def test_an_unreadable_acl_stops_the_write(tmp_path, monkeypatch):
    """Guessing "absent" would restore absence onto a file that may have had one, which is a
    decision about who may read a document, not a detail to paper over."""
    from firmauy.errors import OutputAccessControlError
    from firmauy.signing import _atomic_write_bytes

    out = tmp_path / "ilegible.xml"
    out.write_bytes(b"ORIGINAL")
    _fails_to_preserve(monkeypatch, "getxattr", OSError(5, "Input/output error"))

    with pytest.raises(OutputAccessControlError):
        _atomic_write_bytes(out, b"<signed/>")

    assert out.read_bytes() == b"ORIGINAL"


def test_a_filesystem_without_acls_is_not_an_error(tmp_path, monkeypatch):
    """ENOTSUP is the platform saying it has no ACLs, which means none could have been inherited
    either. That is nothing to restore, not a failure."""
    import errno
    import os

    from firmauy.signing import _atomic_write_bytes

    out = tmp_path / "sinacl.xml"
    out.write_bytes(b"old")
    os.chmod(out, 0o640)
    monkeypatch.setattr(os, "getxattr",
                        mock.Mock(side_effect=OSError(errno.ENOTSUP, "Not supported")))

    _atomic_write_bytes(out, b"<signed/>")

    assert out.read_bytes() == b"<signed/>"


def test_the_owner_is_carried_across_too(tmp_path):
    """uid was not even captured, so replacing a file belonging to somebody else reapplied their
    mode to a document owned by whoever ran the signature."""
    from firmauy.signing import _capture_replaced

    out = tmp_path / "doc.xml"
    out.write_bytes(b"x")

    assert _capture_replaced(out).uid == out.stat().st_uid


def test_the_permissions_come_from_the_file_actually_being_replaced(tmp_path):
    """Signing takes seconds: a card, a PIN, sometimes a TSA. A capture taken before all that
    describes a file that may since have been replaced by a more private one, and reapplying the
    old mode publishes the document wider than the thing it overwrote."""
    import os
    import stat

    from firmauy.signing import _staged_output

    previous = os.umask(0o022)
    try:
        out = tmp_path / "doc.xml"
        out.write_bytes(b"PUBLIC-OLD")
        os.chmod(out, 0o644)

        with _staged_output(out, overwrite=True) as handle:
            handle.write(b"SIGNED")
            out.write_bytes(b"PRIVATE-NEW")      # somebody else publishes, mid-signature
            os.chmod(out, 0o600)

        assert out.read_bytes() == b"SIGNED"
        assert stat.S_IMODE(out.stat().st_mode) == 0o600
    finally:
        os.umask(previous)


def test_a_file_that_appears_mid_signing_still_decides_the_permissions(tmp_path):
    """The same race from the other end: nothing to replace when the signature starts, so the
    umask would have decided, and something private to replace by the time it finishes."""
    import os
    import stat

    from firmauy.signing import _staged_output

    previous = os.umask(0o022)
    try:
        out = tmp_path / "nuevo.xml"

        with _staged_output(out, overwrite=True) as handle:
            handle.write(b"SIGNED")
            out.write_bytes(b"APPEARED")
            os.chmod(out, 0o600)

        assert stat.S_IMODE(out.stat().st_mode) == 0o600
    finally:
        os.umask(previous)


def test_the_capture_describes_one_file_and_not_two(tmp_path, monkeypatch):
    """Mode, owner and group come from one syscall and the ACL from another, both by pathname,
    and a pathname is not a handle. If the entry is replaced between the two, the answer mixes a
    public file's mode with a private file's ACL and publishes the document at the wider one."""
    import os
    import stat

    from firmauy.signing import _staged_output

    previous = os.umask(0o022)
    try:
        out = tmp_path / "doc.xml"
        out.write_bytes(b"PUBLIC-OLD")
        os.chmod(out, 0o644)

        real_getxattr = os.getxattr
        swapped = []

        def swap_then_read(target, attribute, **kwargs):
            # Exactly the window: the mode has been read, the ACL has not.
            if isinstance(target, int) and not swapped:
                swapped.append(True)
                other = tmp_path / "other"
                other.write_bytes(b"PRIVATE-NEW")
                os.chmod(other, 0o600)
                os.replace(other, out)
            return real_getxattr(target, attribute, **kwargs)

        monkeypatch.setattr(os, "getxattr", swap_then_read)

        with _staged_output(out, overwrite=True) as handle:
            handle.write(b"SIGNED")

        assert swapped, "the race never happened, the test proves nothing"
        assert stat.S_IMODE(out.stat().st_mode) == 0o600
    finally:
        os.umask(previous)


def test_the_same_file_made_private_mid_read_is_also_caught(tmp_path, monkeypatch):
    """Not every mid-read change swaps the inode. A plain chmod leaves device and inode alone and
    still makes the mode read a moment earlier wrong, which is why ctime is part of the check."""
    import os
    import stat

    from firmauy.signing import _staged_output

    previous = os.umask(0o022)
    try:
        out = tmp_path / "doc.xml"
        out.write_bytes(b"PUBLIC")
        os.chmod(out, 0o644)

        real_getxattr = os.getxattr
        narrowed = []

        def narrow_then_read(target, attribute, **kwargs):
            if isinstance(target, int) and not narrowed:
                narrowed.append(True)
                os.chmod(out, 0o600)
            return real_getxattr(target, attribute, **kwargs)

        monkeypatch.setattr(os, "getxattr", narrow_then_read)

        with _staged_output(out, overwrite=True) as handle:
            handle.write(b"SIGNED")

        assert narrowed, "the race never happened, the test proves nothing"
        assert stat.S_IMODE(out.stat().st_mode) == 0o600
    finally:
        os.umask(previous)


def test_a_path_that_never_holds_still_publishes_nothing(tmp_path, monkeypatch):
    """Starting over is bounded. Against something rewriting the path without pause the answer is
    to refuse, not to publish permissions belonging to a file that is no longer there."""
    import os

    import pytest

    from firmauy.errors import OutputAccessControlError
    from firmauy.signing import _staged_output

    out = tmp_path / "doc.xml"
    out.write_bytes(b"OLD")
    os.chmod(out, 0o644)

    real_getxattr = os.getxattr
    swaps = []

    def swap_then_read(target, attribute, **kwargs):
        if isinstance(target, int):
            swaps.append(True)
            other = tmp_path / f"other{len(swaps)}"
            other.write_bytes(b"CHURN")
            os.chmod(other, 0o600)
            os.replace(other, out)
        return real_getxattr(target, attribute, **kwargs)

    monkeypatch.setattr(os, "getxattr", swap_then_read)

    with pytest.raises(OutputAccessControlError) as caught:
        with _staged_output(out, overwrite=True) as handle:
            handle.write(b"SIGNED")

    assert caught.value.path == out
    assert len(swaps) > 1, "it gave up without starting over even once"
    assert out.read_bytes() != b"SIGNED"
    assert not list(tmp_path.glob(".firmauy-*.part")), "a staging file was left behind"


def test_a_discarded_attempt_leaves_nothing_on_the_staging_file(tmp_path):
    """Reading the access control can be thrown away and started over, and that is only safe if a
    thrown-away read never touched the file about to be published. Measured before the fix: the
    first read copied a grant to a third party, the file then vanished, the second read found
    nothing to preserve and so restored nothing, and the grant from the discarded read was
    published on a file that never had one."""
    import os
    import shutil
    import stat
    import subprocess

    from firmauy.signing import _staged_output

    if not shutil.which("setfacl"):
        pytest.skip("no ACL support here")

    out = tmp_path / "doc.xml"
    out.write_bytes(b"OLD")
    os.chmod(out, 0o644)
    if subprocess.run(["setfacl", "-m", "u:nobody:r", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("no ACL support here")

    others = [g for g in os.getgroups() if g != os.getgid()]
    if others:
        os.chown(out, -1, others[0])

    real_getxattr = os.getxattr
    vanished = []

    def read_then_vanish(target, attribute, **kwargs):
        value = real_getxattr(target, attribute, **kwargs)
        if isinstance(target, int) and not vanished:
            vanished.append(True)
            os.unlink(out)              # the read is now worthless, and gets discarded
        return value

    previous = os.umask(0o022)
    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(os, "getxattr", read_then_vanish)
            with _staged_output(out, overwrite=True) as handle:
                handle.write(b"SIGNED")
    finally:
        os.umask(previous)

    assert vanished, "the race never happened, the test proves nothing"
    assert out.read_bytes() == b"SIGNED"
    assert _acl_of(out) is None, "an ACL from a discarded read reached the published file"
    assert stat.S_IMODE(out.stat().st_mode) == 0o644
    assert out.stat().st_uid == os.getuid()
    if others:
        assert out.stat().st_gid == os.getgid(), "a group from a discarded read reached the file"




class _NoClock:
    """A stat result from a filesystem whose timestamps cannot tell two moments apart.

    HFS+ and FAT move in whole seconds, so anything happening inside one tick is invisible to
    them. POSIX also declines to require that `rename` touch the renamed file's status change
    time at all: "Some implementations mark for update the last file status change timestamp of
    renamed files and some do not." Tests that would otherwise pass because ext4 happens to be
    generous wear this, so what they prove holds where it is not.
    """

    def __init__(self, real):
        self._real = real

    def __getattr__(self, name):
        return getattr(self._real, name)

    @property
    def st_ctime_ns(self):
        return 0

    @property
    def st_ctime(self):
        return 0.0


def _stop_the_clock(patch):
    """Make every stat this code performs report the same status change time."""
    import os
    import pathlib

    real_lstat, real_fstat = pathlib.Path.lstat, os.fstat
    patch.setattr(pathlib.Path, "lstat", lambda self, *a, **kw: _NoClock(real_lstat(self, *a, **kw)))
    patch.setattr(os, "fstat", lambda fd, *a, **kw: _NoClock(real_fstat(fd, *a, **kw)))


def test_an_entry_that_leaves_and_returns_mid_read_cannot_mix_two_files(tmp_path):
    """The case no amount of comparing pathname lookups can catch. The file is moved aside, a
    different one with a different ACL takes its place for exactly the length of the ACL read, and
    the original comes back, so a before and after comparison sees the same file and agrees.

    It cannot happen here because nothing is read by pathname: the descriptor keeps pointing at
    the file that was opened no matter what the name does. The clock is stopped for the whole test
    so that nothing can be attributed to `rename` moving a timestamp, which POSIX does not require
    it to do.
    """
    import os
    import shutil
    import stat
    import subprocess

    from firmauy.signing import _staged_output

    if not shutil.which("setfacl"):
        pytest.skip("no ACL support here")

    out = tmp_path / "doc.xml"
    out.write_bytes(b"MINE")
    os.chmod(out, 0o640)
    if subprocess.run(["setfacl", "-m", "u:daemon:r", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("no ACL support here")
    mine = _acl_of(out)

    intruder = tmp_path / "intruder"
    intruder.write_bytes(b"THEIRS")
    os.chmod(intruder, 0o604)
    subprocess.run(["setfacl", "-m", "u:nobody:rw", str(intruder)], check=True)
    theirs = _acl_of(intruder)
    assert mine != theirs, "the two files must be distinguishable for this to prove anything"

    danced = []

    with pytest.MonkeyPatch.context() as patch:
        _stop_the_clock(patch)
        real_getxattr = os.getxattr

        def swap_around_the_read(target, attribute, **kwargs):
            if isinstance(target, int) and not danced:
                danced.append(True)
                os.replace(out, tmp_path / "aside")
                os.replace(intruder, out)
                try:
                    return real_getxattr(target, attribute, **kwargs)
                finally:
                    os.replace(out, tmp_path / "gone")
                    os.replace(tmp_path / "aside", out)
            return real_getxattr(target, attribute, **kwargs)

        patch.setattr(os, "getxattr", swap_around_the_read)
        with _staged_output(out, overwrite=True) as handle:
            handle.write(b"SIGNED")

    assert danced, "the race never happened, the test proves nothing"
    assert out.read_bytes() == b"SIGNED"
    assert _acl_of(out) == mine, "the intruder's ACL reached the published file"
    assert stat.S_IMODE(out.stat().st_mode) == 0o640


def test_a_replacement_is_caught_with_the_clock_stopped_too(tmp_path):
    """The plain swap, where the intruder stays. Device and inode settle it, so this holds on a
    filesystem whose timestamps say nothing."""
    import os
    import stat

    from firmauy.signing import _staged_output

    previous = os.umask(0o022)
    try:
        out = tmp_path / "doc.xml"
        out.write_bytes(b"PUBLIC-OLD")
        os.chmod(out, 0o644)
        swapped = []

        with pytest.MonkeyPatch.context() as patch:
            _stop_the_clock(patch)
            real_getxattr = os.getxattr

            def swap_then_read(target, attribute, **kwargs):
                if isinstance(target, int) and not swapped:
                    swapped.append(True)
                    other = tmp_path / "other"
                    other.write_bytes(b"PRIVATE-NEW")
                    os.chmod(other, 0o600)
                    os.replace(other, out)
                return real_getxattr(target, attribute, **kwargs)

            patch.setattr(os, "getxattr", swap_then_read)
            with _staged_output(out, overwrite=True) as handle:
                handle.write(b"SIGNED")

        assert swapped, "the race never happened, the test proves nothing"
        assert stat.S_IMODE(out.stat().st_mode) == 0o600
    finally:
        os.umask(previous)


def test_an_output_its_owner_cannot_read_is_refused_rather_than_guessed(tmp_path):
    """The price of reading through a descriptor. Replacing a file never needed permission to read
    it, and now it does, so a file its own owner has made unreadable stops the signature instead
    of being overwritten with access control assembled from a second lookup. Nothing is mocked
    here: the kernel denies the open, owner or not."""
    import os

    from firmauy.errors import OutputAccessControlError
    from firmauy.signing import _staged_output

    out = tmp_path / "doc.xml"
    out.write_bytes(b"SECRET")
    os.chmod(out, 0o000)
    try:
        os.close(os.open(out, os.O_RDONLY))
        pytest.skip("this user can read anything, so there is no denial to observe")
    except PermissionError:
        pass

    with pytest.raises(OutputAccessControlError) as caught:
        with _staged_output(out, overwrite=True) as handle:
            handle.write(b"SIGNED")

    assert caught.value.path == out
    assert "chmod u+r" in str(caught.value)
    assert not list(tmp_path.glob(".firmauy-*.part")), "a staging file was left behind"

    os.chmod(out, 0o600)
    assert out.read_bytes() == b"SECRET", "the unreadable file was replaced anyway"


def test_a_symlink_at_the_output_does_not_lend_its_target_access_control(tmp_path):
    """The write already refuses to go through a symlink planted at the output. So must the read:
    following one would take the mode and ACL of whatever it points at, a file nobody asked to
    replace, and stamp them on the signature. The link is not the file being replaced, so it has
    nothing to hand over and the result gets what a new file gets."""
    import os
    import shutil
    import stat
    import subprocess

    from firmauy.signing import _staged_output

    if not shutil.which("setfacl"):
        pytest.skip("no ACL support here")

    target = tmp_path / "elsewhere.txt"
    target.write_bytes(b"DO NOT TOUCH")
    os.chmod(target, 0o600)
    if subprocess.run(["setfacl", "-m", "u:daemon:rw", str(target)],
                      capture_output=True).returncode != 0:
        pytest.skip("no ACL support here")

    out = tmp_path / "doc.xml"
    out.symlink_to(target)

    previous = os.umask(0o022)
    try:
        with _staged_output(out, overwrite=True) as handle:
            handle.write(b"SIGNED")
    finally:
        os.umask(previous)

    assert not out.is_symlink()
    assert out.read_bytes() == b"SIGNED"
    assert target.read_bytes() == b"DO NOT TOUCH"
    assert stat.S_IMODE(out.stat().st_mode) == 0o644, "it took the symlink target's mode"
    assert _acl_of(out) is None, "it took the symlink target's ACL"


def test_a_fifo_at_the_output_does_not_hang_the_signature(tmp_path):
    """Opening a FIFO for reading waits for a writer, and nobody is coming. Without O_NONBLOCK the
    signature stops there forever, after the card and the PIN and the TSA, with the document
    already written to the staging file. A FIFO is not the file being replaced either, so there is
    nothing to preserve from it."""
    import os
    import signal
    import stat

    from firmauy.signing import _staged_output

    out = tmp_path / "doc.xml"
    os.mkfifo(out)

    def give_up(signum, frame):
        raise AssertionError("the open blocked: a FIFO at the output hangs the signature")

    previous_handler = signal.signal(signal.SIGALRM, give_up)
    signal.alarm(10)
    previous = os.umask(0o022)
    try:
        with _staged_output(out, overwrite=True) as handle:
            handle.write(b"SIGNED")
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous_handler)
        os.umask(previous)

    assert stat.S_ISREG(out.stat().st_mode), "the FIFO was not replaced by a regular file"
    assert out.read_bytes() == b"SIGNED"
    assert stat.S_IMODE(out.stat().st_mode) == 0o644


@pytest.mark.parametrize("failing", ["fstat", "lstat"])
def test_an_unexpected_failure_reading_the_output_stays_a_typed_error(tmp_path, failing):
    """Every way of failing to read the replaced file's access control ends in the same exception,
    including the ones nobody expects. Failing closed is not the whole contract: a caller that
    catches OutputAccessControlError should not also have to catch a bare OSError to find out that
    the signature was not written."""
    import errno
    import os
    import pathlib

    from firmauy.errors import OutputAccessControlError
    from firmauy.signing import _staged_output

    out = tmp_path / "doc.xml"
    out.write_bytes(b"OLD")

    real_fstat, real_lstat = os.fstat, pathlib.Path.lstat
    fired = []

    target_inode = out.stat().st_ino

    def break_fstat(fd, *a, **kw):
        result = real_fstat(fd, *a, **kw)
        # Only the descriptor opened on the file being replaced. The staging file gets fstat'd
        # too, and a failure there is an environment problem rather than an access control one.
        if result.st_ino == target_inode and not fired:
            fired.append(True)
            raise OSError(errno.EIO, "Input/output error")
        return result

    def break_lstat(self, *a, **kw):
        if self == out and not fired:
            fired.append(True)
            raise OSError(errno.ENOTDIR, "Not a directory")
        return real_lstat(self, *a, **kw)

    with pytest.MonkeyPatch.context() as patch:
        if failing == "fstat":
            patch.setattr(os, "fstat", break_fstat)
        else:
            patch.setattr(pathlib.Path, "lstat", break_lstat)

        with pytest.raises(OutputAccessControlError) as caught:
            with _staged_output(out, overwrite=True) as handle:
                handle.write(b"SIGNED")

    assert fired, "the failure never happened, the test proves nothing"
    assert caught.value.path == out
    assert out.read_bytes() == b"OLD", "the original was replaced anyway"
    assert not list(tmp_path.glob(".firmauy-*.part")), "a staging file was left behind"


def test_a_failure_after_the_commit_is_a_typed_committed_error(tmp_path):
    """The one failure in this function that raises with the output already written. Every other
    one leaves nothing behind, so a caller that treats an exception as "no output" is right except
    here, and would sign again over a document that is already complete. It carries the fields
    needed to repair it, because deciding not to retry by matching text inside a message is the
    thing this error family exists to avoid."""
    import errno
    import os
    import stat

    from firmauy.errors import FirmaUYError, OutputCommittedError
    from firmauy.signing import _staged_output

    out = tmp_path / "doc.xml"
    out.write_bytes(b"OLD")
    os.chmod(out, 0o644)

    real_fchmod = os.fchmod

    def break_the_last_one(fd, mode):
        if mode != 0o600:                   # the only fchmod after the commit
            raise OSError(errno.EROFS, "Read-only file system")
        return real_fchmod(fd, mode)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(os, "fchmod", break_the_last_one)
        with pytest.raises(OutputCommittedError) as caught:
            with _staged_output(out, overwrite=True) as handle:
                handle.write(b"SIGNED")

    failure = caught.value
    assert isinstance(failure, FirmaUYError)
    assert not isinstance(failure, OSError), "the domain split keeps these off the built-in types"
    assert failure.path == out
    assert failure.final_mode == 0o644, "the mode it should have been given"
    assert failure.errno == errno.EROFS, "the operating system's reason was lost"
    assert "valid" not in str(failure), "it cannot claim validity: nothing verified the output"

    assert out.read_bytes() == b"SIGNED", "the signature was not committed"
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".firmauy-*.part")), "a staging file was left behind"


def test_a_batch_counts_a_committed_output_as_signed(monkeypatch, tmp_path):
    """The reason the type exists rather than a clearer message. The file is on disk, complete,
    with the wrong mode. Counting it as an error printed ERROR next to a path that held a valid
    signature, and the summary said fewer files were signed than there were."""
    from firmauy.errors import OutputCommittedError

    calls = _patch_signing(monkeypatch)

    def commit_then_fail(**k):
        calls.append(("xml", k["output_xml"]))
        raise OutputCommittedError("could not set the mode to 0o644 (Read-only file system)",
                                   path=k["output_xml"], final_mode=0o644, errno=30)

    monkeypatch.setattr(cli, "_sign_one_xml", commit_then_fail)

    src = tmp_path / "src"
    src.mkdir()
    (src / "a.pdf").write_bytes(b"%PDF-1.7\n")
    (src / "b.xml").write_bytes(b"<r/>")
    out = tmp_path / "out"

    r = runner.invoke(app, ["sign-batch", "--input-dir", str(src), "--output-dir", str(out)])

    assert "Signed: 2/2" in r.output, "the committed file was not counted as signed"
    assert "Needing a chmod: 1." in r.output
    assert "ERROR" not in r.output, "a file that is on disk was reported as an error"
    assert "WARN" in r.output
    assert "SIGNED: " in r.output, "it should not read OK when the mode was never set"
    # Signed is not the same as done. The command was asked to set the mode and did not, so a
    # script checking only the exit code must not be told everything went fine.
    assert r.exit_code == 1, r.output


def test_a_committed_output_is_reported_as_written_by_the_batch_api(monkeypatch, tmp_path):
    """The same promise on the programmatic side: `completed` holds one report per file on disk,
    and a file whose only problem is its mode is on disk."""
    import firmauy.api as api_module
    from firmauy.errors import BatchSignError, OutputCommittedError

    _patch_signing(monkeypatch)

    def commit_then_fail(**k):
        raise OutputCommittedError("mode", path=k["output_xml"], final_mode=0o644, errno=30)

    monkeypatch.setattr(signing, "_sign_one_xml", commit_then_fail)

    a = tmp_path / "a.xml"
    a.write_bytes(b"<r/>")
    b = tmp_path / "b.xml"
    b.write_bytes(b"<r/>")

    with pytest.raises(BatchSignError) as caught:
        api_module.sign_files([a, b], pin="1234", native=False)

    failure = caught.value
    assert len(failure.completed) == 1, "the committed file was reported as never produced"
    assert failure.completed[0].output_path.name == "a_firmado.xml"
    assert failure.completed[0].verified is False
    assert failure.failed_index == 0
    assert isinstance(failure.__cause__, OutputCommittedError)
    assert failure.__cause__.final_mode == 0o644


def test_a_batch_does_not_report_a_verification_that_never_ran(monkeypatch, tmp_path):
    """The verification step runs after the signing call returns, so a failure inside that call
    means it never ran. Printing OK for a file the user asked to have verified reports a check
    that did not happen."""
    from firmauy.errors import OutputCommittedError

    _patch_signing(monkeypatch)
    verified = []
    monkeypatch.setattr(cli, "_verify_after_xml", lambda out: verified.append(out))

    def commit_then_fail(**k):
        raise OutputCommittedError("could not set the mode", path=k["output_xml"],
                                   final_mode=0o644, errno=30)

    monkeypatch.setattr(cli, "_sign_one_xml", commit_then_fail)

    src = tmp_path / "src"
    src.mkdir()
    (src / "b.xml").write_bytes(b"<r/>")

    r = runner.invoke(app, ["sign-batch", "--input-dir", str(src),
                            "--output-dir", str(tmp_path / "out"), "--verify"])

    assert not verified, "the verification cannot have run: the signing call raised"
    assert "SIGNED (not verified)" in r.output
    assert "Signed: 1/1" in r.output
    assert r.exit_code == 1


def test_a_committed_output_reaches_the_progress_callback(monkeypatch, tmp_path):
    """`progress` is documented as running after each output is written, and this output is
    written. Skipping it showed a progress bar at zero while the file existed and `completed`
    already counted it."""
    import firmauy.api as api_module
    from firmauy.errors import BatchSignError, OutputCommittedError

    _patch_signing(monkeypatch)

    def commit_then_fail(**k):
        raise OutputCommittedError("mode", path=k["output_xml"], final_mode=0o644, errno=30)

    monkeypatch.setattr(signing, "_sign_one_xml", commit_then_fail)

    a = tmp_path / "a.xml"
    a.write_bytes(b"<r/>")
    seen = []

    with pytest.raises(BatchSignError) as caught:
        api_module.sign_files([a], pin="1234", native=False,
                              progress=lambda i, src, out: seen.append((i, out)))

    assert len(seen) == 1, "the written output never reached progress"
    assert seen[0][0] == 0
    assert seen[0][1].name == "a_firmado.xml"
    assert len(caught.value.completed) == 1, "progress and completed must agree"


def test_a_broken_progress_callback_cannot_bury_the_repair_information(monkeypatch, tmp_path):
    """`progress` is the caller's own code and can have bugs in it. When it does, it must not take
    with it the one thing that says the output exists and must not be signed again. Losing that
    turns a file needing a chmod into what looks like a failure before anything was written, and
    the obvious response to that is to sign it a second time."""
    import firmauy.api as api_module
    from firmauy.errors import BatchSignError, OutputCommittedError

    _patch_signing(monkeypatch)

    def commit_then_fail(**k):
        raise OutputCommittedError("mode", path=k["output_xml"], final_mode=0o644, errno=30)

    monkeypatch.setattr(signing, "_sign_one_xml", commit_then_fail)

    def boom(index, source, out):
        raise RuntimeError("progress exploded")

    a = tmp_path / "a.xml"
    a.write_bytes(b"<r/>")

    with pytest.raises(BatchSignError) as caught:
        api_module.sign_files([a], pin="1234", native=False, progress=boom)

    failure = caught.value
    assert isinstance(failure.__cause__, OutputCommittedError), "the repair information was lost"
    assert failure.__cause__.final_mode == 0o644
    assert failure.__cause__.errno == 30
    assert len(failure.completed) == 1, "the written output vanished from the report"
    assert isinstance(failure.callback_error, RuntimeError), "the caller's own bug was swallowed"
    assert "progress exploded" in str(failure.callback_error)


# The four batch commands each carry their own copy of the committed-output handling. A
# parametrised test over all of them is what stops a later change from fixing three and leaving
# the fourth printing OK for a file whose permissions were never set.
_BATCH_COMMANDS = [
    ("sign-pdf-batch", "a.pdf", b"%PDF-1.7\n", "_sign_one_pdf", "output_pdf"),
    ("sign-xml-batch", "a.xml", b"<r/>", "_sign_one_xml", "output_xml"),
    ("sign-any-batch", "a.zip", b"PKbin", "_sign_one_cms", "output_p7s"),
    ("sign-batch", "a.xml", b"<r/>", "_sign_one_xml", "output_xml"),
]


@pytest.mark.parametrize("command,name,body,worker,out_key", _BATCH_COMMANDS)
@pytest.mark.parametrize("verify", [False, True])
def test_every_batch_command_reports_a_committed_output_the_same_way(
        monkeypatch, tmp_path, command, name, body, worker, out_key, verify):
    from firmauy.errors import OutputCommittedError

    _patch_signing(monkeypatch)
    for after in ("_verify_after_pdf", "_verify_after_xml", "_verify_after_cms"):
        monkeypatch.setattr(cli, after, lambda *a, **k: None)

    def commit_then_fail(**k):
        raise OutputCommittedError("could not set the mode to 0o644 (Read-only file system)",
                                   path=k[out_key], final_mode=0o644, errno=30)

    monkeypatch.setattr(cli, worker, commit_then_fail)

    src = tmp_path / "src"
    src.mkdir()
    (src / name).write_bytes(body)
    args = [command, "--input-dir", str(src), "--output-dir", str(tmp_path / "out")]
    if verify:
        args.append("--verify")

    r = runner.invoke(app, args)

    expected = "SIGNED (not verified)" if verify else "SIGNED"
    assert expected in r.output, f"{command} did not say {expected!r}"
    assert "OK:" not in r.output, f"{command} still claims OK for a mode that was never set"
    assert "WARN" in r.output, f"{command} did not warn"
    assert "Signed: 1/1" in r.output, f"{command} did not count the file as signed"
    assert "Needing a chmod: 1." in r.output, f"{command} did not say what is pending"
    assert r.exit_code == 1, f"{command} reported success"


def test_a_signature_that_fails_its_own_check_is_not_reported_as_done(monkeypatch, tmp_path):
    """A post-sign verification failure also leaves a file on disk, and it is deliberately not in
    `completed`. That list is what a caller reads to know what it does not have to redo, and this
    is a file it very probably does: the check that failed says the produced signature is not
    intact. Not the same case as a mode that could not be set, where the bytes were committed
    whole and only a permission bit is wrong, so signing again would be waste.

    What it must not do is stay quiet about the file existing."""
    import firmauy.api as api_module
    from firmauy.errors import BatchSignError

    _patch_signing(monkeypatch)
    written = []

    def write_it(**k):
        k["output_xml"].write_bytes(b"<signed/>")
        written.append(k["output_xml"])

    monkeypatch.setattr(signing, "_sign_one_xml", write_it)
    monkeypatch.setattr(signing, "_verify_after_xml", signing._verify_after_xml)

    a = tmp_path / "a.xml"
    a.write_bytes(b"<r/>")
    seen = []

    with pytest.raises(BatchSignError) as caught:
        api_module.sign_files([a], pin="1234", native=False, verify=True,
                              progress=lambda i, src, out: seen.append(out))

    failure = caught.value
    assert written and written[0].exists(), "the test needs the output to have been written"
    assert failure.completed == [], "a signature that failed its own check was reported as done"
    assert not seen, "progress announces finished work, and this is not finished"
    assert failure.failed_path == a
    assert "is on disk" in str(failure.__cause__), "nothing said the file exists"
    assert written[0].name in str(failure.__cause__)


def test_a_verification_that_could_not_run_still_names_the_output(monkeypatch, tmp_path):
    """The self-check saying no is not the only way it fails to happen. The verifier can raise
    before it ever produces a result, and then the output exists with nobody having established
    anything about it. Saying only that something went wrong leaves a file on disk that will be
    found later and taken for a signature."""
    import firmauy.api as api_module
    from firmauy.errors import BatchSignError, PostSignVerificationError

    _patch_signing(monkeypatch)
    written = []

    def write_it(**k):
        k["output_xml"].write_bytes(b"<signed/>")
        written.append(k["output_xml"])

    def explode(*a, **k):
        raise RuntimeError("XML parser exploded")

    monkeypatch.setattr(signing, "_sign_one_xml", write_it)
    monkeypatch.setattr(signing, "verify_xml", explode)

    a = tmp_path / "a.xml"
    a.write_bytes(b"<r/>")

    with pytest.raises(BatchSignError) as caught:
        api_module.sign_files([a], pin="1234", native=False, verify=True)

    cause = caught.value.__cause__
    assert written[0].exists()
    assert isinstance(cause, PostSignVerificationError), "an unreadable outcome stayed untyped"
    assert cause.path == written[0]
    assert cause.outcome == "inconclusive", "it cannot claim the signature was found broken"
    assert written[0].name in str(cause)
    # Not in `completed`, which is what can be handed to somebody, and this cannot be. The caller
    # is told not to sign it again through `__cause__`, not by its absence from a list.
    assert caught.value.completed == []
    assert "do not use it" in str(cause) and "before signing again" in str(cause)


def test_a_detached_signature_does_not_blame_itself_for_a_changed_original(tmp_path):
    """A detached signature covers bytes in a different file, and the self-check re-opens that
    file by name. If it changed after signing, the .p7s can be a perfectly good signature over
    what was actually signed and the check still reports a mismatch. It cannot tell the two apart,
    so it must not say the signature is broken and send somebody to sign whatever the file holds
    now, which may not be what they meant to sign at all."""
    from firmauy.errors import PostSignVerificationError

    data = b"the signed content\n"
    doc = tmp_path / "d.bin"
    doc.write_bytes(data)
    sig = tmp_path / "d.bin.p7s"
    sig.write_bytes(_software_p7s(data))

    _verify_after_cms(doc, sig)                     # matches -> no raise

    doc.write_bytes(b"somebody edited this!!\n")    # the original moved on
    with pytest.raises(PostSignVerificationError) as caught:
        _verify_after_cms(doc, sig)

    message = str(caught.value)
    # Not "failed", which is documented as delete and sign again: doing that here would sign the
    # edited content. The field has to carry the same uncertainty the message does.
    assert caught.value.outcome == "detached-mismatch"
    assert caught.value.path == sig
    assert caught.value.covers == doc
    assert "does not verify against d.bin as it is now" in message
    assert "or d.bin changed after it was signed" in message
    assert "cannot tell which" in message
    assert "the produced signature is not intact" not in message, "it blamed the wrong file"
    assert "delete it and sign again" not in message, "that would sign the edited content"


def test_a_self_contained_signature_does_say_the_signature_is_broken(tmp_path):
    """The other half of the same rule. With nothing external to compare against there is only
    one explanation left, so the message is allowed to name it."""
    from firmauy.errors import PostSignVerificationError

    out = tmp_path / "salida.xml"
    with pytest.raises(PostSignVerificationError) as caught:
        _check_post_sign(VerifyResult("INVALID", [Check("intact", False, "tampered")]), out)

    assert "the produced signature is not intact" in str(caught.value)
    assert "delete it and sign again" in str(caught.value)


def test_every_post_sign_outcome_is_one_the_contract_names(tmp_path):
    """Three outcomes, and a program branches on them. A fourth appearing by accident, or one of
    these being spelled differently in one code path, falls through every caller's branches into
    whatever their else does."""
    from pathlib import Path

    from firmauy.errors import PostSignVerificationError

    named = {"failed", "detached-mismatch", "inconclusive"}
    source = (Path(__file__).resolve().parent.parent
              / "src" / "firmauy" / "signing.py").read_text()
    used = set(re.findall(r'outcome="([^"]+)"', source))
    assert used <= named, f"an outcome nobody documented: {used - named}"
    assert used == named, f"an outcome the contract names but nothing raises: {named - used}"

    assert PostSignVerificationError("x").covers is None


# --- --json for signing: per-file results, and every failure on stdout -------

def test_error_codes_follow_the_class_hierarchy():
    """Keyed on classes, so a subclass nobody listed still gets its parent's code, and renaming a
    class cannot quietly change what a script reads."""
    import typer

    from firmauy.cli import _error_code
    from firmauy.errors import IncorrectPinError, OutputExistsError, PinError

    class SomeNewPinError(PinError):
        pass

    assert _error_code(IncorrectPinError("x")) == "incorrect_pin"
    assert _error_code(SomeNewPinError("x")) == "pin_error"
    assert _error_code(OutputExistsError("x")) == "output_exists"
    assert _error_code(typer.BadParameter("x")) == "invalid_argument"
    assert _error_code(RuntimeError("x")) == "operation_failed"


def test_the_two_pin_refusals_keep_the_code_scripts_already_read():
    """Both were a bare PinError until 1.20.0, so a script reading pin_error has always seen them
    as that. The classes are for the API, where a caller branches on the type; on the terminal
    the message already says which. A code of their own would turn pin_error into one this
    script does not know, which the documentation says to treat as operation_failed."""
    from firmauy.cli import _error_code
    from firmauy.errors import PinFormatError

    assert _error_code(PinFormatError("x")) == "pin_error"
    assert _error_code(PinLastTryError("x")) == "pin_error"


def test_a_timestamp_that_did_not_come_back_has_codes_of_its_own():
    """Before 1.19.0 it was pyHanko's OSError and the table had nothing for it: operation_failed,
    the code a script cannot act on, for the one failure where the fix is usually a setting."""
    from firmauy.cli import _error_code
    from firmauy.errors import TimestampDestinationRefusedError, TimestampError

    assert _error_code(TimestampError("x")) == "timestamp_failed"
    assert _error_code(TimestampDestinationRefusedError("x")) == "timestamp_destination_refused"


def test_sign_batch_json_reports_each_file(monkeypatch, tmp_path):
    """Counts alone cannot tell a script which file failed or why, which is the reason to ask a
    batch for JSON in the first place."""
    from firmauy.errors import OutputExistsError

    _patch_signing(monkeypatch)

    def refuse(**kwargs):
        raise OutputExistsError("Output file already exists.")

    monkeypatch.setattr(cli, "_sign_one_xml", refuse)
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.pdf").write_bytes(b"%PDF-1.7\n")
    (src / "b.xml").write_bytes(b"<r/>")
    (src / "c.zip").write_bytes(b"PKbin")

    r = runner.invoke(app, ["sign-batch", "--input-dir", str(src),
                            "--output-dir", str(tmp_path / "out"), "--json"])
    assert r.exit_code == 1
    out = json.loads(r.stdout)
    assert (out["ok"], out["signed"], out["errors"], out["total"]) == (False, 2, 1, 3)
    files = {f["input"].rsplit("/", 1)[-1]: f for f in out["files"]}
    assert files["a.pdf"]["status"] == "ok" and files["a.pdf"]["kind"] == "pades"
    assert files["c.zip"]["status"] == "ok" and files["c.zip"]["kind"] == "cades"
    assert files["b.xml"]["status"] == "error"
    assert files["b.xml"]["error_code"] == "output_exists"
    assert files["b.xml"]["error"] == "Output file already exists."


def test_json_failures_reach_stdout(monkeypatch, tmp_path):
    """A script reading --json output should never have to read stderr to learn why it failed:
    not for a check the command makes itself, nor for an error from deeper down."""
    from contextlib import contextmanager

    from firmauy.errors import CardNotFoundError

    empty = tmp_path / "empty"
    empty.mkdir()
    r = runner.invoke(app, ["sign-pdf-batch", "--input-dir", str(empty),
                            "--output-dir", str(tmp_path / "o1"), "--json"])
    assert r.exit_code == 1
    assert json.loads(r.stdout) == {
        "schema_version": 2, "ok": False, "error_code": "invalid_argument",
        "error": "No input files specified. Use positional arguments or --input-dir.",
    }

    @contextmanager
    def no_card(**kwargs):
        raise CardNotFoundError("No card in the reader.")
        yield

    monkeypatch.setattr(cli, "_signing_session", no_card)
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.pdf").write_bytes(b"%PDF-1.7\n")
    r = runner.invoke(app, ["sign-batch", "--input-dir", str(src),
                            "--output-dir", str(tmp_path / "o2"), "--json"])
    assert r.exit_code == 1
    assert json.loads(r.stdout)["error_code"] == "card_not_found"

    bad = tmp_path / "bad.pem"
    bad.write_text("not a certificate\n")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    r = runner.invoke(app, ["fetch-cas", "--from-file", str(bad), "--json"])
    assert r.exit_code == 1
    failure = json.loads(r.stdout)
    assert failure["ok"] is False and "not a PEM/DER certificate" in failure["error"]


def test_sign_json_names_the_kind_like_the_api(monkeypatch, tmp_path):
    """`sign` dispatches on internal names ("any" for CAdES). The JSON uses the ones sign-any and
    the API's SignReport use."""
    _patch_signing(monkeypatch)
    target = tmp_path / "c.zip"
    target.write_bytes(b"PKbin")
    r = runner.invoke(app, ["sign", str(target), "--json"])
    assert r.exit_code == 0, r.output
    assert json.loads(r.stdout)["kind"] == "cades"


def test_list_readers_json_keeps_the_exit_status(monkeypatch):
    """No reader is a failure without --json, and --json does not change exit codes."""
    monkeypatch.setattr(cli, "list_readers", lambda: [])
    r = runner.invoke(app, ["list-readers", "--json"])
    assert r.exit_code == 1
    assert json.loads(r.stdout) == {"schema_version": 2, "readers": []}


# --- --dry-run ----------------------------------------------------------------

def _refuse_the_card(monkeypatch):
    """Any attempt to open a signing session fails the test: a dry run must never reach it."""
    def no_session(**kwargs):
        raise AssertionError("a dry run opened the signing session")

    monkeypatch.setattr(cli, "_signing_session", no_session)


def test_dry_run_stops_before_the_card(monkeypatch, tmp_path):
    _refuse_the_card(monkeypatch)
    source = tmp_path / "input.pdf"
    source.write_bytes(b"%PDF-1.7\n%%EOF\n")
    output = tmp_path / "signed.pdf"

    r = runner.invoke(app, ["sign-pdf", str(source), str(output), "--dry-run"])
    assert r.exit_code == 0, r.output
    assert "1 file(s) would be signed" in r.output
    assert "only opened when they are signed" in r.output
    assert not output.exists()


def test_batch_dry_run_stops_where_the_real_run_would(monkeypatch, tmp_path):
    """A dry run that says yes where signing says no is worse than none. Both of these stop the
    real run before the PIN, so they stop the dry run too."""
    _refuse_the_card(monkeypatch)
    for folder in ("d1", "d2"):
        (tmp_path / folder).mkdir()
        (tmp_path / folder / "a.pdf").write_bytes(b"%PDF-1.7\n")
    out = tmp_path / "out"

    r = runner.invoke(app, ["sign-pdf-batch", str(tmp_path / "d1" / "a.pdf"),
                            str(tmp_path / "d2" / "a.pdf"), "--output-dir", str(out), "--dry-run"])
    assert r.exit_code == 1 and "Output path collision" in r.output

    r = runner.invoke(app, ["sign-pdf-batch", str(tmp_path / "d1" / "a.pdf"), "--output-dir", str(out),
                            "--x1", "300", "--x2", "100", "--dry-run"])
    assert r.exit_code == 1 and "Coordinates must satisfy" in r.output
    assert not out.exists()


def test_dry_run_json_lists_what_would_be_signed(monkeypatch, tmp_path):
    _refuse_the_card(monkeypatch)
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.pdf").write_bytes(b"%PDF-1.7\n")
    (src / "b.xml").write_bytes(b"<r/>")
    out = tmp_path / "out"

    r = runner.invoke(app, ["sign-batch", "--input-dir", str(src), "--output-dir", str(out),
                            "--dry-run", "--json"])
    assert r.exit_code == 0, r.output
    payload = json.loads(r.stdout)
    assert (payload["ok"], payload["dry_run"], payload["total"]) == (True, True, 2)
    assert [(f["kind"], f["status"], f["output"].rsplit("/", 1)[-1]) for f in payload["files"]] == [
        ("pades", "would_sign", "a_firmado.pdf"), ("xades", "would_sign", "b_firmado.xml")]
    assert not out.exists(), "a dry run created the output directory"


# --- PDFs past what verify-pdf reads -------------------------------------------

def _shrink_the_pdf_limit(monkeypatch, limit=2000, headroom=100):
    """verify-pdf's real limit is 128 MiB. The check reads it from firmauy.signing, so a small one
    stands in for it here."""
    from firmauy import signing

    monkeypatch.setattr(signing, "MAX_PDF_BYTES", limit)
    monkeypatch.setattr(signing, "_SIGNED_PDF_HEADROOM", headroom)


def test_a_pdf_past_the_verify_limit_is_signed_with_a_warning(monkeypatch, tmp_path):
    _refuse_the_card(monkeypatch)
    _shrink_the_pdf_limit(monkeypatch)
    big = tmp_path / "big.pdf"
    big.write_bytes(b"%PDF-1.7\n" + b"0" * 1950)

    r = runner.invoke(app, ["sign-pdf", str(big), str(tmp_path / "out.pdf"), "--dry-run"])
    assert r.exit_code == 0, r.output
    assert "will not be able to verify the signed copy" in r.output
    assert "would be signed" in r.output


def test_verify_on_a_pdf_past_the_limit_stops_before_the_pin(monkeypatch, tmp_path):
    """It would sign, and then report its own check as inconclusive: a verdict that says not to
    use a document with nothing wrong in it."""
    _refuse_the_card(monkeypatch)
    _shrink_the_pdf_limit(monkeypatch)
    big = tmp_path / "big.pdf"
    big.write_bytes(b"%PDF-1.7\n" + b"0" * 1950)
    small = tmp_path / "small.pdf"
    small.write_bytes(b"%PDF-1.7\n")

    for argv in (["sign-pdf", str(big), str(tmp_path / "o.pdf")],
                 ["sign-batch", str(small), str(big), "--output-dir", str(tmp_path / "out")]):
        r = runner.invoke(app, argv + ["--verify"])
        assert r.exit_code == 1
        assert "Sign it without --verify" in r.output

    r = runner.invoke(app, ["sign-pdf", str(small), str(tmp_path / "o.pdf"), "--verify", "--dry-run"])
    assert r.exit_code == 0, r.output


def test_a_batch_passes_the_listing_identity_to_the_signer(monkeypatch, tmp_path):
    """A file found in --input-dir is signed only if it is still the file the listing checked,
    which the signer can tell only if it is handed what the listing saw. A file named as an
    argument gets None and is opened as named."""
    import os

    _patch_signing(monkeypatch)
    seen = {}
    monkeypatch.setattr(cli, "_sign_one_pdf",
                        lambda **k: seen.update({k["input_pdf"].name: k["listed_identity"]}))
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.pdf").write_bytes(b"%PDF-1.7\n")
    extra = tmp_path / "extra.pdf"
    extra.write_bytes(b"%PDF-1.7\n")

    r = runner.invoke(app, ["sign-pdf-batch", str(extra), "--input-dir", str(src),
                            "--output-dir", str(tmp_path / "out")])
    assert r.exit_code == 0, r.output
    st = os.lstat(src / "a.pdf")
    assert seen == {"extra.pdf": None, "a.pdf": (st.st_dev, st.st_ino)}


# --- --allow-private-network --------------------------------------------------------------------

@pytest.mark.parametrize("command, verifier, name", [
    ("verify-pdf", "verify_pdf", "a.pdf"), ("verify-xml", "verify_xml", "a.xml"),
    ("verify-any", "verify_cms", "doc.bin"), ("verify", "verify_pdf", "a.pdf"),
])
def test_allow_private_network_reaches_the_verifier(tmp_path, monkeypatch, command, verifier, name):
    """An accepted-and-ignored flag is worse than no flag: each verify command hands it on."""
    import firmauy.cli as cli

    seen = {}

    def _spy(*args, **kwargs):
        seen.update(kwargs)
        raise RuntimeError("stop here")

    monkeypatch.setattr(cli, verifier, _spy)
    (tmp_path / "a.pdf").write_bytes(b"%PDF-1.7\n")
    (tmp_path / "a.xml").write_bytes(b"<r/>")
    (tmp_path / "doc.bin").write_bytes(b"contenido")
    (tmp_path / "doc.bin.p7s").write_bytes(b"no importa")
    ca = tmp_path / "ca.pem"
    ca.write_bytes(_ANCHOR_PEM)

    runner.invoke(app, [command, str(tmp_path / name), "--ca-file", str(ca),
                        "--check-revocation", "--allow-private-network"])

    assert seen.get("allow_private_network") is True, f"{command} dropped --allow-private-network"


@pytest.mark.parametrize("argv", [
    ["sign", "doc.bin"], ["sign-any", "doc.bin"], ["sign-pdf", "a.pdf"], ["sign-xml", "a.xml"],
    ["sign-batch", "doc.bin", "--output-dir", "out"], ["sign-any-batch", "doc.bin", "--output-dir", "out"],
    ["sign-pdf-batch", "a.pdf", "--output-dir", "out"], ["sign-xml-batch", "a.xml", "--output-dir", "out"],
])
def test_allow_private_network_reaches_the_timestamper(tmp_path, monkeypatch, argv):
    import firmauy.cli as cli

    seen = {}
    real = cli._build_timestamper

    def _spy(**kwargs):
        seen.update(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(cli, "_build_timestamper", _spy)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "a.pdf").write_bytes(b"%PDF-1.7\n")
    (tmp_path / "a.xml").write_bytes(b"<r/>")
    (tmp_path / "doc.bin").write_bytes(b"contenido")

    r = runner.invoke(app, argv + ["--dry-run", "--tsa-url", "https://tsa.example/tsr",
                                   "--allow-private-network"])

    assert r.exit_code == 0, r.output
    assert seen.get("allow_private_network") is True, f"{argv[0]} dropped --allow-private-network"


def test_allow_private_network_without_what_it_applies_to_is_noted(tmp_path, monkeypatch):
    """Given where it does nothing, it says so, on stderr, so --json output still parses."""
    import firmauy.cli as cli

    monkeypatch.setattr(cli, "verify_pdf", lambda *a, **k: [])
    pdf = tmp_path / "a.pdf"
    pdf.write_bytes(b"%PDF-1.7\n")
    r = runner.invoke(app, ["verify-pdf", str(pdf), "--no-trust", "--allow-private-network"])
    assert "only applies to the --check-revocation fetches" in r.output

    doc = tmp_path / "doc.bin"
    doc.write_bytes(b"contenido")
    r = runner.invoke(app, ["sign-any", str(doc), "--dry-run", "--allow-private-network", "--json"])
    assert r.exit_code == 0, r.output
    assert "only applies to the --tsa-url request" in r.stderr
    assert json.loads(r.stdout)["dry_run"] is True
