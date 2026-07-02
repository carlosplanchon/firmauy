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

from firmauy.cli import (
    _check_post_sign,
    _detached_original,
    _detect_signature_kind,
    _doctor_emit,
    _emit_verify,
    _emit_verify_error,
    _verify_after_cms,
    app,
)
from firmauy.cms_sign import sign_cms_detached
from firmauy.verify_common import Check, VerifyResult

runner = CliRunner()


# --- --version --------------------------------------------------------------

def test_version_flag_reports_package_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert f"firmauy {version('firmauy')}" in result.output


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
    import firmauy.cli as cli

    p7s = tmp_path / "sig.p7s"
    p7s.write_bytes(_software_p7s(b"hi"))              # a real, valid detached CMS
    assert cli._detect_signature_kind(p7s) == "cms"    # detected normally under the real cap

    monkeypatch.setattr(cli, "_CMS_DETECT_MAX_BYTES", 16)
    with pytest.raises(ValueError, match="could not detect"):
        cli._detect_signature_kind(p7s)                # same file now exceeds the (tiny) budget


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
    from firmauy.cli import _atomic_write_bytes

    out = tmp_path / "o.bin"
    _atomic_write_bytes(out, b"hello")
    assert out.read_bytes() == b"hello"
    assert not (tmp_path / "o.bin.part").exists()   # the sibling temp is gone after os.replace


def test_atomic_write_bytes_replaces_symlink_without_writing_through(tmp_path):
    # The XML/CMS signed outputs go through _atomic_write_bytes, which must REPLACE a pre-existing
    # output symlink with the real file -- not follow it and clobber its target (what write_bytes did).
    from firmauy.cli import _atomic_write_bytes

    target = tmp_path / "target.txt"
    target.write_bytes(b"DO NOT TOUCH")
    link = tmp_path / "out.xml"
    link.symlink_to(target)

    _atomic_write_bytes(link, b"<signed/>")

    assert not link.is_symlink()                    # symlink replaced by a regular file
    assert link.read_bytes() == b"<signed/>"
    assert target.read_bytes() == b"DO NOT TOUCH"   # the symlink target was never written through
    assert not (tmp_path / "out.xml.part").exists()


class _RecordingConn:
    def __init__(self):
        self.disconnected = False

    def disconnect(self):
        self.disconnected = True


def test_fetch_identity_disconnects_the_reader(monkeypatch):
    import firmauy.cli as cli

    conn = _RecordingConn()
    monkeypatch.setattr(cli, "open_reader", lambda reader_name=None: conn)
    monkeypatch.setattr(cli, "read_card", lambda c: {"bio": {}, "doc_num": None, "mrz": None})

    result = runner.invoke(app, ["fetch-identity", "--json"])
    assert result.exit_code == 0, result.output
    assert conn.disconnected is True   # the PC/SC connection is released, like fetch-photo


def test_fetch_identity_disconnects_even_when_read_fails(monkeypatch):
    # The disconnect lives in a finally, so a read error must still release the reader.
    import firmauy.cli as cli

    conn = _RecordingConn()

    def boom(_c):
        raise RuntimeError("read failed")

    monkeypatch.setattr(cli, "open_reader", lambda reader_name=None: conn)
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


def test_verify_tsa_ca_ignored_for_non_xml_warns(tmp_path):
    # --tsa-ca applies only to a XAdES-T XML; for a PDF/CMS it is warned, not silently dropped.
    pdf = tmp_path / "a.pdf"
    pdf.write_bytes(b"%PDF-1.7\n")
    tsaca = tmp_path / "tsa.pem"
    tsaca.write_bytes(b"-----BEGIN CERTIFICATE-----\nnot real\n-----END CERTIFICATE-----\n")
    result = runner.invoke(app, ["verify", str(pdf), "--tsa-ca", str(tsaca), "--no-trust"])
    assert "--tsa-ca is ignored" in result.output


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

    from firmauy import cli

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

    from firmauy import cli

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
    from firmauy import cli

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
    from firmauy import cli
    monkeypatch.setattr(cli, "open_reader", lambda name=None: conn)
    monkeypatch.setattr(cli, "read_photo", lambda c: _JPEG)


def test_fetch_photo_dash_streams_raw_jpeg_to_stdout(monkeypatch):
    # `fetch-photo -` writes the raw JPEG bytes to stdout (for pipes/redirects) and nothing else:
    # the status line must go to stderr so it never corrupts the stream.
    import io
    from pathlib import Path

    from firmauy import cli

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

    from firmauy import cli

    opened = {"n": 0}

    def _should_not_open(name=None):
        opened["n"] += 1
        return _FakeConn()

    monkeypatch.setattr(cli, "open_reader", _should_not_open)

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
    from firmauy import cli

    conn = _FakeConn()
    _patch_card(monkeypatch, conn)

    out = tmp_path / "foto.jpg"
    cli.fetch_photo_cmd(output=out, reader_name=None, overwrite=False,
                        json_output=False, json_pretty=False, redact=False)

    assert out.read_bytes() == _JPEG
    assert conn.disconnected
    assert "Photo saved" in capsys.readouterr().out


# --- fetch-photo --json record (stdout, redaction, conflict with a file/'-') ----------------------

def test_fetch_photo_json_emits_record_to_stdout(monkeypatch, capsys):
    import base64
    from pathlib import Path

    from firmauy import cli

    conn = _FakeConn()
    _patch_card(monkeypatch, conn)

    cli.fetch_photo_cmd(output=Path("cedula_foto.jpg"), reader_name=None, overwrite=False,
                        json_output=True, json_pretty=False, redact=False)

    obj = json.loads(capsys.readouterr().out)
    assert obj["schema_version"] == 1
    assert obj["redacted"] is False                     # flag present (and false) on the full record
    assert obj["format"] == "jpeg" and obj["mime"] == "image/jpeg"
    assert obj["bytes"] == len(_JPEG)
    assert base64.b64decode(obj["base64"]) == _JPEG     # the record carries the exact image
    assert conn.disconnected


def test_fetch_photo_json_redact_drops_image_and_hash(monkeypatch, capsys):
    from pathlib import Path

    from firmauy import cli

    _patch_card(monkeypatch, _FakeConn())

    cli.fetch_photo_cmd(output=Path("cedula_foto.jpg"), reader_name=None, overwrite=False,
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

    from firmauy import cli

    opened = {"n": 0}
    monkeypatch.setattr(cli, "open_reader",
                        lambda name=None: opened.__setitem__("n", opened["n"] + 1))

    with pytest.raises(typer.Exit):
        cli.fetch_photo_cmd(output=Path("out.jpg"), reader_name=None, overwrite=False,
                            json_output=True, json_pretty=False, redact=False)

    assert opened["n"] == 0
    assert "cannot be combined" in capsys.readouterr().err.lower()


# --- fetch-identity carries the same top-level redacted flag -------------------------------------

def test_fetch_identity_json_carries_redacted_flag(monkeypatch, capsys):
    from firmauy import cli

    card = {"bio": {0x01: "PEREZ"}, "doc_num": None, "mrz": None}
    monkeypatch.setattr(cli, "open_reader", lambda name=None: _FakeConn())
    monkeypatch.setattr(cli, "read_card", lambda conn: card)

    cli.fetch_identity_cmd(reader_name=None, json_output=True, json_pretty=False, redact=False)
    full = json.loads(capsys.readouterr().out)
    assert full["redacted"] is False and full["first_lastname"] == "PEREZ"

    cli.fetch_identity_cmd(reader_name=None, json_output=True, json_pretty=False, redact=True)
    red = json.loads(capsys.readouterr().out)
    assert red["redacted"] is True and red["first_lastname"] == "[REDACTED]"


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


def test_validate_ci_json_full_record():
    result = runner.invoke(app, ["validate-ci", "1.234.567-2", "--json"])
    assert result.exit_code == 0
    obj = json.loads(result.stdout)
    assert obj["redacted"] is False and obj["valid"] is True
    assert obj["normalized"] == "12345672" and obj["expected_check_digit"] == "2"


def test_validate_ci_json_redact_drops_number_keeps_validity():
    result = runner.invoke(app, ["validate-ci", "12345678", "--json", "--redact"])
    assert result.exit_code == 1                                   # exit code still reflects validity
    assert json.loads(result.stdout) == {"schema_version": 1, "redacted": True, "valid": False}


def test_validate_ci_complete_prints_completed_number():
    result = runner.invoke(app, ["validate-ci", "1234567", "--complete"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "12345672"


def test_validate_ci_complete_with_redact_conflicts():
    assert runner.invoke(app, ["validate-ci", "1234567", "--complete", "--redact"]).exit_code == 2


# --- sign / sign-batch: auto-detect + dispatch ----------------------------------------------------

def test_detect_input_kind(tmp_path):
    from firmauy.cli import _detect_input_kind
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


class _FakeToken:
    label = "tok"

    def open(self, user_pin=None):
        class _Ctx:
            def __enter__(self_): return object()      # the session
            def __exit__(self_, *a): return False
        return _Ctx()


def _patch_signing(monkeypatch):
    """Patch the PKCS#11/cert path so sign/sign-batch reach the dispatch without a card. Returns a
    list that records (kind, output_path) for each worker call."""
    from firmauy import cli
    calls = []
    monkeypatch.setattr(cli, "load_pkcs11_lib", lambda lib: object())
    monkeypatch.setattr(cli, "find_token", lambda lib, label: _FakeToken())
    monkeypatch.setattr(cli, "get_pin", lambda *a, **k: "1234")
    monkeypatch.setattr(cli, "select_certificate", lambda session, cid: (b"\x01", _FakeCert()))
    monkeypatch.setattr(cli, "get_common_name", lambda name: "SIGNER")
    monkeypatch.setattr(cli, "normalize_issuer_name", lambda s: "ISSUER")
    monkeypatch.setattr(cli, "PKCS11Signer", lambda **k: object())
    monkeypatch.setattr(cli, "_make_raw_signer", lambda session, key_id: (lambda data: b"sig"))
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


def test_signing_session_yields_context_and_respects_quiet(monkeypatch, capsys):
    # The shared PKCS#11 bootstrap of every sign-* command: open the session, select the cert, print
    # the identity block (unless --quiet), and yield a backend-agnostic context whose lazy factories
    # build the pyHanko / raw signers the command bodies consume.
    from firmauy import cli
    monkeypatch.setattr(cli, "load_pkcs11_lib", lambda lib: object())
    monkeypatch.setattr(cli, "find_token", lambda lib, label: _FakeToken())
    monkeypatch.setattr(cli, "get_pin", lambda *a, **k: "1234")
    monkeypatch.setattr(cli, "select_certificate", lambda session, cid: (b"\x01", _FakeCert()))
    monkeypatch.setattr(cli, "get_common_name", lambda name: "SIGNER")
    monkeypatch.setattr(cli, "normalize_issuer_name", lambda s: "ISSUER")
    monkeypatch.setattr(cli, "PKCS11Signer", lambda **kw: ("pk-signer", kw))
    monkeypatch.setattr(cli, "_make_raw_signer", lambda session, key_id: ("raw-signer", key_id))

    common = dict(native=False, reader=None, pkcs11_lib="lib.so", token_label=None, cert_id=None,
                  pin_source=None, pin_env_var=None, pin_fd=None, tsa_url=None)

    # Not quiet: exposes the fields the command bodies read, and prints the identity block.
    with cli._signing_session(**common, quiet=False) as ctx:
        assert ctx.cert is not None
        assert (ctx.signer_name, ctx.issuer_name) == ("SIGNER", "ISSUER")
        assert ctx.cert_serial == format(_FakeCert.serial_number, "X")     # "1A"
        # The PKCS#11 backend builds a PKCS11Signer bound to the selected key, and the XML raw signer
        # via _make_raw_signer; each factory is memoized (built at most once).
        pk = ctx.pyhanko_signer()
        assert pk[0] == "pk-signer" and pk[1]["cert_id"] == b"\x01"
        assert ctx.pyhanko_signer() is pk                                  # cached, not rebuilt
        assert ctx.raw_signer() == ("raw-signer", b"\x01")
    out = capsys.readouterr().out
    assert "SIGNER" in out and "ISSUER" in out and "tok" in out         # identity block printed

    # Quiet: yields the same context but prints nothing identifying.
    with cli._signing_session(**common, quiet=True) as ctx:
        assert ctx.signer_name == "SIGNER" and ctx.cert_serial == "1A"
    assert capsys.readouterr().out == ""                                # silent under --quiet


def test_signing_session_warns_on_backend_mismatched_options(monkeypatch, capsys):
    # The backend-option pre-flight lives inside _signing_session (shared by all 8 sign commands),
    # so no command can forget it: --reader without --native warns on stderr, pre-PIN.
    from firmauy import cli
    monkeypatch.setattr(cli, "load_pkcs11_lib", lambda lib: object())
    monkeypatch.setattr(cli, "find_token", lambda lib, label: _FakeToken())
    monkeypatch.setattr(cli, "get_pin", lambda *a, **k: "1234")
    monkeypatch.setattr(cli, "select_certificate", lambda session, cid: (b"\x01", _FakeCert()))
    monkeypatch.setattr(cli, "get_common_name", lambda name: "SIGNER")
    monkeypatch.setattr(cli, "normalize_issuer_name", lambda s: "ISSUER")

    with cli._signing_session(native=False, reader="ACS ACR39U 00 00", pkcs11_lib="lib.so",
                              token_label=None, cert_id=None, pin_source=None, pin_env_var=None,
                              pin_fd=None, tsa_url=None, quiet=True):
        pass
    assert "--reader only applies to --native" in capsys.readouterr().err


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
    from firmauy import cli
    monkeypatch.setattr(cli, "IncrementalPdfFileWriter", _FakeHybridWriter)
    src = tmp_path / "in.pdf"
    src.write_bytes(b"%PDF-1.7\n")

    with pytest.raises(RuntimeError) as ei:
        cli._sign_one_pdf(input_pdf=src, output_pdf=tmp_path / "out.pdf", **_SIGN_ONE_PDF_ARGS)
    msg = str(ei.value)
    assert "hybrid cross-reference" in msg
    assert "qpdf" in msg and "--allow-hybrid-xref" in msg
    assert _FakeHybridWriter.last_strict is True                 # default opens strict


def test_sign_one_pdf_allows_hybrid_xref_with_flag(monkeypatch, tmp_path, capsys):
    # --allow-hybrid-xref opens the PDF non-strict and warns instead of refusing; we stop right
    # after the guard (before the real pyHanko machinery) via a sentinel from enumerate_sig_fields.
    from firmauy import cli
    monkeypatch.setattr(cli, "IncrementalPdfFileWriter", _FakeHybridWriter)

    class _Sentinel(Exception):
        pass

    def _stop(_writer):
        raise _Sentinel
    monkeypatch.setattr(cli.fields, "enumerate_sig_fields", _stop)

    src = tmp_path / "in.pdf"
    src.write_bytes(b"%PDF-1.7\n")
    with pytest.raises(_Sentinel):                               # got past the guard, no RuntimeError
        cli._sign_one_pdf(input_pdf=src, output_pdf=tmp_path / "out.pdf",
                          allow_hybrid_xref=True, **_SIGN_ONE_PDF_ARGS)
    assert _FakeHybridWriter.last_strict is False                # opened non-strict to allow signing
    err = capsys.readouterr().err
    assert "hybrid cross-reference sections" in err and "--allow-hybrid-xref" in err
