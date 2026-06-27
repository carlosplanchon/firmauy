"""End-to-end PKCS#11 integration test against a SoftHSM2 token.

Unlike the rest of the suite (which builds certs in memory and never touches a
real PKCS#11 module), this test drives the actual signing path: token discovery,
certificate scoring, PIN handling, pyHanko signing and a cryptographic
verification of the resulting PDF.

It builds a throwaway "fake cédula" token with SoftHSM2 — same approach as
scripts/dev-softhsm-setup.sh — so it never uses the real card. The whole test is
skipped when SoftHSM2 / OpenSC / OpenSSL are not installed.
"""

import os
import shutil
import subprocess

import pytest
from typer.testing import CliRunner

from cedula_uy_pdf_sign.cli import app

PIN = "1234"
SO_PIN = "0000"
TOKEN_LABEL = "test-cedula"
CKA_ID = "01"

_MODULE_CANDIDATES = (
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/pkcs11/libsofthsm2.so",
    "/usr/lib/libsofthsm2.so",
    "/usr/lib64/softhsm/libsofthsm2.so",
)


def _softhsm_module() -> str | None:
    return next((p for p in _MODULE_CANDIDATES if os.path.exists(p)), None)


_HAVE_STACK = (
    _softhsm_module() is not None
    and shutil.which("softhsm2-util") is not None
    and shutil.which("pkcs11-tool") is not None
    and shutil.which("openssl") is not None
)

pytestmark = pytest.mark.skipif(
    not _HAVE_STACK,
    reason="SoftHSM2 + OpenSC (pkcs11-tool) + OpenSSL required for PKCS#11 integration test",
)


def _run(cmd: list[str], env: dict) -> None:
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        raise AssertionError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )


@pytest.fixture
def softhsm_token(tmp_path, monkeypatch):
    """Provision a fake-cédula SoftHSM token; yield the module path."""
    module = _softhsm_module()
    assert module is not None  # guarded by pytestmark

    conf = tmp_path / "softhsm2.conf"
    tokendir = tmp_path / "tokens"
    tokendir.mkdir()
    conf.write_text(
        f"directories.tokendir = {tokendir}\n"
        "objectstore.backend = file\n"
        "log.level = ERROR\n"
    )

    env = {**os.environ, "SOFTHSM2_CONF": str(conf)}
    # The in-process pkcs11 load (via CliRunner) reads SOFTHSM2_CONF too.
    monkeypatch.setenv("SOFTHSM2_CONF", str(conf))

    _run(
        ["softhsm2-util", "--init-token", "--free", "--label", TOKEN_LABEL,
         "--so-pin", SO_PIN, "--pin", PIN],
        env,
    )

    # Fake "Ministerio del Interior" CA + leaf identity cert. The subject carries
    # serialNumber + CN and the issuer name matches the heuristic in
    # select_certificate, so it scores as the cédula identity certificate.
    ca_key = tmp_path / "ca.key"
    ca_crt = tmp_path / "ca.crt"
    leaf_key = tmp_path / "leaf.key"
    leaf_csr = tmp_path / "leaf.csr"
    leaf_crt = tmp_path / "leaf.crt"
    leaf_der = tmp_path / "leaf.der"
    leaf_ext = tmp_path / "leaf.ext"

    _run(["openssl", "genpkey", "-algorithm", "RSA",
          "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(ca_key)], env)
    _run(["openssl", "req", "-x509", "-new", "-key", str(ca_key), "-days", "3650",
          "-out", str(ca_crt),
          "-subj", "/C=UY/CN=Autoridad Certificadora del Ministerio del Interior"], env)

    _run(["openssl", "genpkey", "-algorithm", "RSA",
          "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(leaf_key)], env)
    _run(["openssl", "req", "-new", "-key", str(leaf_key), "-out", str(leaf_csr),
          "-subj", "/C=UY/CN=PEREZ PEREZ JUAN/serialNumber=1.2.3.4-12345678"], env)

    leaf_ext.write_text(
        "keyUsage = critical, digitalSignature, nonRepudiation\n"
        "extendedKeyUsage = emailProtection, clientAuth\n"
    )
    _run(["openssl", "x509", "-req", "-in", str(leaf_csr), "-CA", str(ca_crt),
          "-CAkey", str(ca_key), "-CAcreateserial", "-days", "825",
          "-extfile", str(leaf_ext), "-out", str(leaf_crt)], env)
    _run(["openssl", "x509", "-in", str(leaf_crt), "-outform", "DER",
          "-out", str(leaf_der)], env)

    # Import key + cert under the same CKA_ID so has_private_key() pairs them.
    _run(["softhsm2-util", "--import", str(leaf_key), "--token", TOKEN_LABEL,
          "--label", "leaf", "--id", CKA_ID, "--pin", PIN], env)
    _run(["pkcs11-tool", "--module", module, "--token-label", TOKEN_LABEL,
          "--login", "--pin", PIN, "--write-object", str(leaf_der),
          "--type", "cert", "--id", CKA_ID, "--label", "leaf"], env)

    return module


def _make_sample_pdf(path) -> None:
    from reportlab.pdfgen import canvas

    c = canvas.Canvas(str(path))
    c.drawString(100, 750, "Documento de prueba - firmauy integration test")
    c.showPage()
    c.save()


def test_sign_via_softhsm_produces_valid_signature(softhsm_token, tmp_path):
    module = softhsm_token
    input_pdf = tmp_path / "sample.pdf"
    output_pdf = tmp_path / "signed.pdf"
    _make_sample_pdf(input_pdf)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "sign", str(input_pdf), str(output_pdf),
            "--pkcs11-lib", module,
            "--token-label", TOKEN_LABEL,  # SoftHSM also exposes a free slot
            "--pin-source", "stdin",
        ],
        input=PIN + "\n",
    )

    assert result.exit_code == 0, result.output
    # select_certificate picked our fake-cédula identity cert.
    assert "PEREZ PEREZ JUAN" in result.output
    assert output_pdf.exists()

    # Cryptographically verify the produced signature. We supply no trust roots:
    # the fake CA is untrusted by design, so we assert integrity/validity and
    # full-file coverage rather than trust.
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext

    with output_pdf.open("rb") as f:
        reader = PdfFileReader(f)
        embedded = reader.embedded_signatures
        assert len(embedded) == 1

        status = validate_pdf_signature(
            embedded[0], ValidationContext(allow_fetching=False)
        )
        assert status.intact, "signed bytes were altered"
        assert status.valid, "signature cryptography did not verify"
        assert status.coverage.name == "ENTIRE_FILE"
