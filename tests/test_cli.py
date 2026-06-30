"""CLI-level smoke tests (Typer app wiring, --version, --json verify contract)."""

import datetime
import json
from importlib.metadata import version

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

from cedula_uy_pdf_sign.cli import (
    _check_post_sign,
    _detached_original,
    _detect_signature_kind,
    _doctor_emit,
    _emit_verify,
    _emit_verify_error,
    _verify_after_cms,
    app,
)
from cedula_uy_pdf_sign.cms_sign import sign_cms_detached
from cedula_uy_pdf_sign.verify_common import Check, VerifyResult

runner = CliRunner()


# --- --version --------------------------------------------------------------

def test_version_flag_reports_package_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert f"firmauy {version('cedula-uy-pdf-sign')}" in result.output


def test_help_still_shows_app_description():
    # The --version callback must not clobber the app's help text.
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Sign and verify PDF (PAdES)" in result.output
    assert "--version" in result.output


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
    assert out["schema_version"] == 1 and out["indication"] == "VALID"
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
    sig = json.loads(capsys.readouterr().out)["signatures"][0]
    assert sig["signer"]["common_name"] == "[REDACTED]"
    assert sig["signer"]["serial_number"] == "[REDACTED]"
    assert sig["signer"]["certificate_serial"] == "[REDACTED]"
    assert sig["signer"]["country"] == "UY"            # not personal -> kept
    assert sig["issuer"]["common_name"] == "AC MI"     # issuer (public CA) never redacted


def test_emit_verify_pretty_is_indented(capsys):
    r = VerifyResult("VALID", [], signer={"common_name": "X"}, issuer={}, trusted=True)
    _emit_verify([r], json_output=True, pretty=True)
    out = capsys.readouterr().out
    assert "\n  " in out
    assert json.loads(out)["schema_version"] == 1


def test_emit_verify_overall_is_worst_signature(capsys):
    rs = [VerifyResult("VALID", []), VerifyResult("INVALID", []), VerifyResult("INDETERMINATE", [])]
    assert _emit_verify(rs, json_output=True) == "INVALID"
    out = json.loads(capsys.readouterr().out)
    assert out["indication"] == "INVALID"
    assert len(out["signatures"]) == 3


def test_emit_verify_error_json(capsys):
    _emit_verify_error(ValueError("boom"), json_output=True)
    out = json.loads(capsys.readouterr().out)
    assert out["schema_version"] == 1
    assert out["error"] == "boom"


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
    assert payload["schema_version"] == 1
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
    assert out["schema_version"] == 1 and out["ok"] is True
    assert len(out["checks"]) == 2


def test_doctor_emit_not_ok_on_fail(capsys):
    checks = [{"status": "FAIL", "name": "a", "detail": "x", "fix": "fix it"}]
    assert _doctor_emit(checks, json_output=True) is False
    assert json.loads(capsys.readouterr().out)["ok"] is False


def test_doctor_command_json_contract():
    # Environment-independent: assert the contract shape and exit/ok consistency.
    result = runner.invoke(app, ["doctor", "--json"])
    payload = json.loads(result.output)
    assert payload["schema_version"] == 1
    assert isinstance(payload["ok"], bool)
    assert payload["checks"]
    for c in payload["checks"]:
        assert {"status", "name", "detail", "fix"} <= set(c)
        assert c["status"] in {"PASS", "WARN", "FAIL"}
    assert result.exit_code == (0 if payload["ok"] else 1)


# --- --verify (post-sign self-check) ----------------------------------------

def test_check_post_sign_passes_and_raises():
    # All checks ok -> no raise (post-sign self-check passes).
    _check_post_sign(VerifyResult("INDETERMINATE", [Check("intact", True), Check("valid", True)]))
    # Any failed check -> raise (the produced signature is not intact).
    with pytest.raises(RuntimeError, match="post-sign verification failed"):
        _check_post_sign(VerifyResult("INVALID", [Check("intact", False, "tampered"), Check("valid", True)]))


def test_verify_after_cms_catches_a_broken_signature(tmp_path):
    data = b"the signed content\n"
    doc = tmp_path / "d.bin"
    doc.write_bytes(data)
    sig = tmp_path / "d.bin.p7s"
    sig.write_bytes(_software_p7s(data))

    _verify_after_cms(doc, sig)  # intact -> no raise

    doc.write_bytes(b"TAMPERED content!!\n")  # mutate the bytes the signature covers
    with pytest.raises(RuntimeError, match="not intact"):
        _verify_after_cms(doc, sig)


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
    from cedula_uy_pdf_sign.cli import _cert_record

    rec = _cert_record("5c10d3", _make_id_cert(), include_pem=True)
    assert rec["id"] == "5c10d3"
    assert rec["subject"]["common_name"] == "PEREZ JUAN" and rec["subject"]["serial_number"] == "DNI123"
    assert rec["issuer"]["common_name"] == "AC MI"
    assert rec["certificate_serial"] == "78191"
    assert rec["digital_signature"] is True
    assert rec["pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert "pem" not in _cert_record("5c10d3", _make_id_cert(), include_pem=False)


def test_redact_cert_record_hides_holder_keeps_issuer():
    from cedula_uy_pdf_sign.cli import _cert_record, _redact_cert_record

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

    from cedula_uy_pdf_sign.cli import _validate_image

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


def test_batch_output_preserves_subdirs_and_avoids_collisions(tmp_path):
    from pathlib import Path

    from cedula_uy_pdf_sign.cli import _batch_output

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


def test_image_opacity_warning_only_outside_background(capsys):
    from cedula_uy_pdf_sign.cli import _warn_image_opacity_unused
    from cedula_uy_pdf_sign.constants import DEFAULT_IMAGE_OPACITY, ImageMode

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
