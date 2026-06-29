"""End-to-end PKCS#11 integration tests against SoftHSM2 tokens.

Unlike the rest of the suite (which builds certs in memory and never touches a
real PKCS#11 module), these tests drive the actual signing path: token
discovery, certificate scoring, PIN handling and pyHanko signing, plus the
error branches that are impossible or dangerous to reproduce on the real card
(expired cert, cert without private key, multiple tokens, certificate scoring).

Each test provisions a throwaway "fake cédula" token with SoftHSM2 (same idea as
scripts/dev-softhsm-setup.sh) and runs `firmauy` in a subprocess, so every case
gets its own freshly-initialised module. The whole module is skipped when
SoftHSM2 / OpenSC / OpenSSL are not installed.
"""

import datetime
import os
import shutil
import subprocess
import sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from PIL import Image

PIN = "1234"
SO_PIN = "0000"
MI_ISSUER = "Autoridad Certificadora del Ministerio del Interior"
TEST_CEDULA = "DNI00000000"  # Real cédula subject serialNumber format: DNI + 8 digits

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
)

pytestmark = pytest.mark.skipif(
    not _HAVE_STACK,
    reason="SoftHSM2 + OpenSC (pkcs11-tool) required for PKCS#11 integration tests",
)


def _run(cmd: list[str], env: dict) -> None:
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        raise AssertionError(
            f"setup command failed ({proc.returncode}): {' '.join(cmd)}\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )


def _write_cert(
    tmp,
    name: str,
    *,
    cn: str,
    issuer_cn: str,
    serial_number: str | None = None,
    not_after: datetime.datetime | None = None,
    digital_signature: bool = True,
    content_commitment: bool = True,
) -> tuple:
    """Build a self-signed cert + PKCS#8 key on disk; return (key_pem, cert_der)."""
    if not_after is None:
        not_after = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject_attrs = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "UY"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ]
    if serial_number:
        subject_attrs.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, serial_number))

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name(subject_attrs))
        .issuer_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "UY"),
                    x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
                ]
            )
        )
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_after - datetime.timedelta(days=365))
        .not_valid_after(not_after)
        .add_extension(
            x509.KeyUsage(
                digital_signature=digital_signature,
                content_commitment=content_commitment,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    key_path = tmp / f"{name}.key.pem"
    cert_path = tmp / f"{name}.cert.der"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    return key_path, cert_path


class _SoftHSM:
    """Builds tokens in an isolated SoftHSM store and runs firmauy against it."""

    def __init__(self, module: str, env: dict, tmp):
        self.module = module
        self.env = env
        self.tmp = tmp

    def init_token(self, label: str) -> None:
        _run(
            ["softhsm2-util", "--init-token", "--free", "--label", label,
             "--so-pin", SO_PIN, "--pin", PIN],
            self.env,
        )

    def import_pair(self, label, key_path, cert_path, cka_id: str) -> None:
        _run(
            ["softhsm2-util", "--import", str(key_path), "--token", label,
             "--label", f"key{cka_id}", "--id", cka_id, "--pin", PIN],
            self.env,
        )
        self.import_cert_only(label, cert_path, cka_id)

    def import_cert_only(self, label, cert_path, cka_id: str) -> None:
        _run(
            ["pkcs11-tool", "--module", self.module, "--token-label", label,
             "--login", "--pin", PIN, "--write-object", str(cert_path),
             "--type", "cert", "--id", cka_id, "--label", f"cert{cka_id}"],
            self.env,
        )

    def firmauy(self, *args: str, input_text: str | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "cedula_uy_pdf_sign", *args],
            env=self.env,
            input=input_text,
            capture_output=True,
            text=True,
        )


@pytest.fixture
def softhsm(tmp_path):
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
    return _SoftHSM(module, env, tmp_path)


@pytest.fixture
def sample_pdf(tmp_path):
    from reportlab.pdfgen import canvas

    path = tmp_path / "sample.pdf"
    c = canvas.Canvas(str(path))
    c.drawString(100, 750, "Documento de prueba - firmauy integration test")
    c.showPage()
    c.save()
    return path


def _output(proc: subprocess.CompletedProcess) -> str:
    return proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# Happy path: sign and cryptographically verify the produced PDF.
# ---------------------------------------------------------------------------

def test_sign_via_softhsm_produces_valid_signature(softhsm, sample_pdf, tmp_path):
    key, cert = _write_cert(
        tmp_path, "identity",
        cn="PEREZ PEREZ JUAN", issuer_cn=MI_ISSUER, serial_number=TEST_CEDULA,
    )
    softhsm.init_token("test-cedula")
    softhsm.import_pair("test-cedula", key, cert, "01")

    output_pdf = tmp_path / "signed.pdf"
    proc = softhsm.firmauy(
        "sign-pdf", str(sample_pdf), str(output_pdf),
        "--pkcs11-lib", softhsm.module, "--token-label", "test-cedula",
        "--pin-source", "stdin",
        input_text=PIN + "\n",
    )
    assert proc.returncode == 0, _output(proc)
    assert "PEREZ PEREZ JUAN" in _output(proc)
    assert output_pdf.exists()

    # Verify the signature cryptographically. No trust roots are supplied: the
    # CA is a local fake, so we assert integrity/validity and full-file coverage
    # rather than trust.
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext

    with output_pdf.open("rb") as f:
        reader = PdfFileReader(f)
        embedded = reader.embedded_signatures
        assert len(embedded) == 1
        status = validate_pdf_signature(embedded[0], ValidationContext(allow_fetching=False))
        assert status.intact, "signed bytes were altered"
        assert status.valid, "signature cryptography did not verify"
        assert status.coverage.name == "ENTIRE_FILE"


def test_sign_with_image_appearance_stays_valid(softhsm, sample_pdf, tmp_path):
    key, cert = _write_cert(
        tmp_path, "identity",
        cn="PEREZ PEREZ JUAN", issuer_cn=MI_ISSUER, serial_number=TEST_CEDULA,
    )
    softhsm.init_token("test-cedula")
    softhsm.import_pair("test-cedula", key, cert, "01")

    png = tmp_path / "sig.png"
    Image.new("RGBA", (120, 48), (10, 30, 200, 160)).save(png)

    output_pdf = tmp_path / "signed.pdf"
    proc = softhsm.firmauy(
        "sign-pdf", str(sample_pdf), str(output_pdf),
        "--pkcs11-lib", softhsm.module, "--token-label", "test-cedula",
        "--pin-source", "stdin", "--image", str(png), "--image-mode", "side",
        input_text=PIN + "\n",
    )
    assert proc.returncode == 0, _output(proc)
    assert output_pdf.exists()

    # An image appearance is cosmetic: the signature must still be intact, valid and full-file.
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext

    with output_pdf.open("rb") as f:
        reader = PdfFileReader(f)
        embedded = reader.embedded_signatures
        assert len(embedded) == 1
        status = validate_pdf_signature(embedded[0], ValidationContext(allow_fetching=False))
        assert status.intact and status.valid
        assert status.coverage.name == "ENTIRE_FILE"


def test_quiet_suppresses_identity_block(softhsm, sample_pdf, tmp_path):
    key, cert = _write_cert(
        tmp_path, "identity",
        cn="PEREZ PEREZ JUAN", issuer_cn=MI_ISSUER, serial_number=TEST_CEDULA,
    )
    softhsm.init_token("test-cedula")
    softhsm.import_pair("test-cedula", key, cert, "01")

    common = [
        "--pkcs11-lib", softhsm.module, "--token-label", "test-cedula",
        "--pin-source", "stdin",
    ]

    # Without --quiet, the identity block (signer name) is printed.
    out_verbose = tmp_path / "verbose.pdf"
    proc = softhsm.firmauy(
        "sign-pdf", str(sample_pdf), str(out_verbose), *common, input_text=PIN + "\n",
    )
    assert proc.returncode == 0, _output(proc)
    assert "PEREZ PEREZ JUAN" in _output(proc)

    # With --quiet, signing still succeeds but no identifying data is printed.
    out_quiet = tmp_path / "quiet.pdf"
    proc = softhsm.firmauy(
        "sign-pdf", str(sample_pdf), str(out_quiet), *common, "--quiet", input_text=PIN + "\n",
    )
    assert proc.returncode == 0, _output(proc)
    assert out_quiet.exists()
    assert "PEREZ PEREZ JUAN" not in _output(proc)
    assert "Certificate serial:" not in _output(proc)
    assert "PKCS#11 ID:" not in _output(proc)


def test_verify_pdf_integrity_and_tamper(softhsm, sample_pdf, tmp_path):
    key, cert = _write_cert(
        tmp_path, "identity",
        cn="PEREZ PEREZ JUAN", issuer_cn=MI_ISSUER, serial_number=TEST_CEDULA,
    )
    softhsm.init_token("test-cedula")
    softhsm.import_pair("test-cedula", key, cert, "01")

    output_pdf = tmp_path / "signed.pdf"
    proc = softhsm.firmauy(
        "sign-pdf", str(sample_pdf), str(output_pdf),
        "--pkcs11-lib", softhsm.module, "--token-label", "test-cedula",
        "--pin-source", "stdin", input_text=PIN + "\n",
    )
    assert proc.returncode == 0, _output(proc)

    from cedula_uy_pdf_sign.pdf_verify import verify_pdf

    # Integrity holds; no trust anchors -> INDETERMINATE, all integrity checks pass.
    results = verify_pdf(output_pdf, trust_roots=None)
    assert len(results) == 1
    assert results[0].indication == "INDETERMINATE"
    assert all(c.ok for c in results[0].checks), \
        [(c.name, c.detail) for c in results[0].checks if not c.ok]

    # Tampering a byte inside the signed range breaks integrity -> INVALID.
    data = bytearray(output_pdf.read_bytes())
    data[len(data) // 4] ^= 0x01
    tampered = tmp_path / "tampered.pdf"
    tampered.write_bytes(data)
    res_bad = verify_pdf(tampered, trust_roots=None)
    assert res_bad[0].indication == "INVALID"


def test_list_certs_pem_outputs_parseable_certificate(softhsm, tmp_path):
    key, cert = _write_cert(
        tmp_path, "identity",
        cn="PEREZ PEREZ JUAN", issuer_cn=MI_ISSUER, serial_number=TEST_CEDULA,
    )
    softhsm.init_token("test-cedula")
    softhsm.import_pair("test-cedula", key, cert, "01")

    # No --pin-source: certificates are public PKCS#11 objects, listed without login.
    proc = softhsm.firmauy(
        "list-certs", "--pkcs11-lib", softhsm.module, "--token-label", "test-cedula", "--pem",
    )
    assert proc.returncode == 0, _output(proc)
    # --pem emits only PEM on stdout (no human listing), and it parses as a certificate.
    assert "-----BEGIN CERTIFICATE-----" in proc.stdout
    assert "Subject:" not in proc.stdout
    x509.load_pem_x509_certificate(proc.stdout.encode())


# ---------------------------------------------------------------------------
# Error / selection branches that the real card cannot safely reproduce.
# ---------------------------------------------------------------------------

def test_expired_certificate_is_rejected(softhsm, sample_pdf, tmp_path):
    past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    key, cert = _write_cert(
        tmp_path, "expired",
        cn="PEREZ PEREZ JUAN", issuer_cn=MI_ISSUER,
        serial_number=TEST_CEDULA, not_after=past,
    )
    softhsm.init_token("test-cedula")
    softhsm.import_pair("test-cedula", key, cert, "01")

    proc = softhsm.firmauy(
        "sign-pdf", str(sample_pdf), str(tmp_path / "out.pdf"),
        "--pkcs11-lib", softhsm.module, "--token-label", "test-cedula",
        "--pin-source", "stdin",
        input_text=PIN + "\n",
    )
    assert proc.returncode != 0
    assert "expired" in _output(proc).lower()


def test_certificate_without_private_key_is_rejected(softhsm, sample_pdf, tmp_path):
    _, cert = _write_cert(
        tmp_path, "nokey",
        cn="PEREZ PEREZ JUAN", issuer_cn=MI_ISSUER, serial_number=TEST_CEDULA,
    )
    softhsm.init_token("test-cedula")
    softhsm.import_cert_only("test-cedula", cert, "01")  # cert only, no key

    proc = softhsm.firmauy(
        "sign-pdf", str(sample_pdf), str(tmp_path / "out.pdf"),
        "--pkcs11-lib", softhsm.module, "--token-label", "test-cedula",
        "--pin-source", "stdin",
        input_text=PIN + "\n",
    )
    assert proc.returncode != 0
    assert "private key" in _output(proc).lower()


def test_multiple_tokens_require_label(softhsm, sample_pdf, tmp_path):
    key, cert = _write_cert(
        tmp_path, "identity",
        cn="PEREZ PEREZ JUAN", issuer_cn=MI_ISSUER, serial_number=TEST_CEDULA,
    )
    softhsm.init_token("token-a")
    softhsm.init_token("token-b")
    softhsm.import_pair("token-a", key, cert, "01")

    proc = softhsm.firmauy(
        "sign-pdf", str(sample_pdf), str(tmp_path / "out.pdf"),
        "--pkcs11-lib", softhsm.module,  # deliberately no --token-label
        "--pin-source", "stdin",
        input_text=PIN + "\n",
    )
    assert proc.returncode != 0
    assert "multiple tokens" in _output(proc).lower()


def test_identity_cert_is_preferred_over_generic(softhsm, sample_pdf, tmp_path):
    # A high-scoring cédula identity cert and a low-scoring generic one share a
    # token; selection must pick the identity cert.
    id_key, id_cert = _write_cert(
        tmp_path, "identity",
        cn="PEREZ PEREZ JUAN", issuer_cn=MI_ISSUER, serial_number=TEST_CEDULA,
    )
    gen_key, gen_cert = _write_cert(
        tmp_path, "generic",
        cn="GENERIC NON IDENTITY", issuer_cn="Some Unrelated Test CA",
        content_commitment=False,
    )
    softhsm.init_token("test-cedula")
    softhsm.import_pair("test-cedula", id_key, id_cert, "01")
    softhsm.import_pair("test-cedula", gen_key, gen_cert, "02")

    proc = softhsm.firmauy(
        "sign-pdf", str(sample_pdf), str(tmp_path / "out.pdf"),
        "--pkcs11-lib", softhsm.module, "--token-label", "test-cedula",
        "--pin-source", "stdin",
        input_text=PIN + "\n",
    )
    assert proc.returncode == 0, _output(proc)
    assert "PEREZ PEREZ JUAN" in _output(proc)
    assert "GENERIC NON IDENTITY" not in _output(proc)


def test_cert_id_overrides_selection(softhsm, sample_pdf, tmp_path):
    # With two certs present, --cert-id forces the otherwise-lower-scoring one.
    id_key, id_cert = _write_cert(
        tmp_path, "identity",
        cn="PEREZ PEREZ JUAN", issuer_cn=MI_ISSUER, serial_number=TEST_CEDULA,
    )
    gen_key, gen_cert = _write_cert(
        tmp_path, "generic",
        cn="GENERIC NON IDENTITY", issuer_cn="Some Unrelated Test CA",
        content_commitment=False,
    )
    softhsm.init_token("test-cedula")
    softhsm.import_pair("test-cedula", id_key, id_cert, "01")
    softhsm.import_pair("test-cedula", gen_key, gen_cert, "02")

    proc = softhsm.firmauy(
        "sign-pdf", str(sample_pdf), str(tmp_path / "out.pdf"),
        "--pkcs11-lib", softhsm.module, "--token-label", "test-cedula",
        "--cert-id", "02", "--pin-source", "stdin",
        input_text=PIN + "\n",
    )
    assert proc.returncode == 0, _output(proc)
    assert "GENERIC NON IDENTITY" in _output(proc)
