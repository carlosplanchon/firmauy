"""End-to-end XAdES (sign-xml) integration test against a SoftHSM2 token.

Signs an XML through the real PKCS#11 path (`firmauy sign-xml`) and verifies the
result with an independent library (signxml). Skipped when SoftHSM2 / OpenSC or
signxml are not available.
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

PIN = "1234"
SO_PIN = "0000"
MI_ISSUER = "Autoridad Certificadora del Ministerio del Interior"
TEST_CEDULA = "DNI00000000"  # real cédula subject serialNumber format: DNI + digits
TOKEN_LABEL = "test-cedula"

DSIG = "http://www.w3.org/2000/09/xmldsig#"
XADES = "http://uri.etsi.org/01903/v1.3.2#"

_MODULE_CANDIDATES = (
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/pkcs11/libsofthsm2.so",
    "/usr/lib/libsofthsm2.so",
    "/usr/lib64/softhsm/libsofthsm2.so",
)


def _softhsm_module():
    return next((p for p in _MODULE_CANDIDATES if os.path.exists(p)), None)


def _have_signxml():
    return __import__("importlib").util.find_spec("signxml") is not None


_HAVE_STACK = (
    _softhsm_module() is not None
    and shutil.which("softhsm2-util") is not None
    and shutil.which("pkcs11-tool") is not None
    and _have_signxml()
)

pytestmark = pytest.mark.skipif(
    not _HAVE_STACK,
    reason="SoftHSM2 + OpenSC + signxml required for the XAdES integration test",
)


def _run(cmd, env):
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        raise AssertionError(f"setup failed: {' '.join(cmd)}\n{proc.stdout}\n{proc.stderr}")


@pytest.fixture
def softhsm_token(tmp_path):
    module = _softhsm_module()
    conf = tmp_path / "softhsm2.conf"
    tokendir = tmp_path / "tokens"
    tokendir.mkdir()
    conf.write_text(
        f"directories.tokendir = {tokendir}\n"
        "objectstore.backend = file\n"
        "log.level = ERROR\n"
    )
    env = {**os.environ, "SOFTHSM2_CONF": str(conf)}
    _run(["softhsm2-util", "--init-token", "--free", "--label", TOKEN_LABEL,
          "--so-pin", SO_PIN, "--pin", PIN], env)

    # Fake-cédula identity cert + key.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UY"),
            x509.NameAttribute(NameOID.COMMON_NAME, "PEREZ PEREZ JUAN"),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, TEST_CEDULA),
        ]))
        .issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UY"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ministerio del Interior"),
            x509.NameAttribute(NameOID.COMMON_NAME, MI_ISSUER),
        ]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=True, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .sign(key, hashes.SHA256())
    )
    key_path = tmp_path / "leaf.key.pem"
    cert_path = tmp_path / "leaf.cert.der"
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.DER))

    _run(["softhsm2-util", "--import", str(key_path), "--token", TOKEN_LABEL,
          "--label", "key01", "--id", "01", "--pin", PIN], env)
    _run(["pkcs11-tool", "--module", module, "--token-label", TOKEN_LABEL,
          "--login", "--pin", PIN, "--write-object", str(cert_path),
          "--type", "cert", "--id", "01", "--label", "cert01"], env)
    return module, env, cert


def test_sign_xml_produces_valid_xades(softhsm_token, tmp_path):
    module, env, cert = softhsm_token

    input_xml = tmp_path / "doc.xml"
    input_xml.write_bytes(
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<Documento xmlns="http://example.uy/test"><Dato>hola</Dato></Documento>'
    )
    output_xml = tmp_path / "doc_firmado.xml"

    proc = subprocess.run(
        [sys.executable, "-m", "cedula_uy_pdf_sign", "sign-xml",
         str(input_xml), str(output_xml),
         "--pkcs11-lib", module, "--token-label", TOKEN_LABEL, "--pin-source", "stdin"],
        env=env, input=PIN + "\n", capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert output_xml.exists()

    signed = output_xml.read_bytes()

    # Structural sanity: XAdES-BES enveloped, rsa-sha256.
    assert b"xmldsig-more#rsa-sha256" in signed
    assert b"QualifyingProperties" in signed
    assert b'standalone="no"' in signed

    # Independent cryptographic verification with signxml.
    from signxml import XMLVerifier

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    verified = XMLVerifier().verify(signed, x509_cert=cert_pem, expect_references=2)
    refs = verified if isinstance(verified, list) else [verified]
    assert len(refs) == 2


def test_sign_xml_batch_signs_all(softhsm_token, tmp_path):
    module, env, cert = softhsm_token

    in_dir = tmp_path / "in"
    out_dir = tmp_path / "out"
    in_dir.mkdir()
    names = ["a", "b", "c"]
    for n in names:
        (in_dir / f"{n}.xml").write_bytes(
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<Doc xmlns="http://example.uy/test"><n>{n}</n></Doc>'.encode()
        )

    # One PKCS#11 session, whole directory, PIN entered once (via stdin).
    proc = subprocess.run(
        [sys.executable, "-m", "cedula_uy_pdf_sign", "sign-xml-batch",
         "--input-dir", str(in_dir), "--output-dir", str(out_dir),
         "--pkcs11-lib", module, "--token-label", TOKEN_LABEL, "--pin-source", "stdin"],
        env=env, input=PIN + "\n", capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr

    from signxml import XMLVerifier
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    for n in names:
        out = out_dir / f"{n}_firmado.xml"
        assert out.exists(), f"missing {out}"
        verified = XMLVerifier().verify(out.read_bytes(), x509_cert=cert_pem, expect_references=2)
        refs = verified if isinstance(verified, list) else [verified]
        assert len(refs) == 2
