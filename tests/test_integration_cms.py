"""End-to-end CAdES (sign-any) integration test against a SoftHSM2 token.

Signs an arbitrary file through the real PKCS#11 path (`firmauy sign-any`) and
verifies the detached `.p7s` both with the project's own verifier and, when
available, with `openssl cms -verify`. Skipped when SoftHSM2 / OpenSC are missing.
"""

import datetime
import os
import shutil
import subprocess
import sys

import pytest
from asn1crypto import cms as asn1cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

PIN = "1234"
SO_PIN = "0000"
MI_ISSUER = "Autoridad Certificadora del Ministerio del Interior"
TEST_CEDULA = "DNI00000000"
TOKEN_LABEL = "test-cedula"

_MODULE_CANDIDATES = (
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/pkcs11/libsofthsm2.so",
    "/usr/lib/libsofthsm2.so",
    "/usr/lib64/softhsm/libsofthsm2.so",
)


def _softhsm_module():
    return next((p for p in _MODULE_CANDIDATES if os.path.exists(p)), None)


_HAVE_STACK = (
    _softhsm_module() is not None
    and shutil.which("softhsm2-util") is not None
    and shutil.which("pkcs11-tool") is not None
)

pytestmark = pytest.mark.skipif(
    not _HAVE_STACK,
    reason="SoftHSM2 + OpenSC required for the CAdES integration test",
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


def _sign_any(module, env, input_file, output_p7s, *extra):
    return subprocess.run(
        [sys.executable, "-m", "cedula_uy_pdf_sign", "sign-any",
         str(input_file), str(output_p7s),
         "--pkcs11-lib", module, "--token-label", TOKEN_LABEL, "--pin-source", "stdin",
         *extra],
        env=env, input=PIN + "\n", capture_output=True, text=True,
    )


def test_sign_any_produces_valid_detached_cms(softhsm_token, tmp_path):
    module, env, cert = softhsm_token

    input_file = tmp_path / "payload.bin"
    input_file.write_bytes(b"arbitrary \x00\x01\x02 any file contents\n")
    output_p7s = tmp_path / "payload.bin.p7s"

    proc = _sign_any(module, env, input_file, output_p7s)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert output_p7s.exists()

    # Structural: detached CMS SignedData (the original file is left untouched).
    ci = asn1cms.ContentInfo.load(output_p7s.read_bytes())
    assert ci["content_type"].native == "signed_data"
    assert ci["content"]["encap_content_info"]["content"].native is None
    assert input_file.read_bytes() == b"arbitrary \x00\x01\x02 any file contents\n"

    # Own verifier: integrity holds; no trust anchors -> INDETERMINATE.
    # (The fixture's signing cert is not a real chain to a trustable root, the same
    # reason the XAdES integration test verifies the signature only. The VALID
    # trust-chain path is covered by the self-signed cert in tests/test_cms.py.)
    from cedula_uy_pdf_sign.cms_verify import verify_cms
    res = verify_cms(input_file.read_bytes(), output_p7s.read_bytes(), trust_roots=None)
    assert res.indication == "INDETERMINATE"
    assert all(c.ok for c in res.checks), [(c.name, c.detail) for c in res.checks if not c.ok]

    # Independent signature check with openssl (integrity only, -noverify skips the
    # signer-cert chain, which has no trustable issuer in this fixture).
    if shutil.which("openssl"):
        ossl = subprocess.run(
            ["openssl", "cms", "-verify", "-binary", "-inform", "DER",
             "-in", str(output_p7s), "-content", str(input_file), "-noverify"],
            capture_output=True, text=True,
        )
        assert ossl.returncode == 0, ossl.stdout + ossl.stderr


def test_verify_any_tamper_is_invalid(softhsm_token, tmp_path):
    module, env, cert = softhsm_token

    input_file = tmp_path / "doc.txt"
    input_file.write_bytes(b"original content\n")
    output_p7s = tmp_path / "doc.txt.p7s"
    proc = _sign_any(module, env, input_file, output_p7s)
    assert proc.returncode == 0, proc.stdout + proc.stderr

    from cedula_uy_pdf_sign.cms_verify import verify_cms
    tampered = b"tampered content\n"
    res_bad = verify_cms(tampered, output_p7s.read_bytes(), trust_roots=None)
    assert res_bad.indication == "INVALID"

    # verify-any CLI: integrity OK, no trust -> INDETERMINATE -> exit code 2.
    proc_v = subprocess.run(
        [sys.executable, "-m", "cedula_uy_pdf_sign", "verify-any",
         str(input_file), str(output_p7s), "--no-trust"],
        env=env, capture_output=True, text=True,
    )
    assert proc_v.returncode == 2, proc_v.stdout + proc_v.stderr


def test_sign_any_batch_signs_all(softhsm_token, tmp_path):
    module, env, cert = softhsm_token

    in_dir = tmp_path / "in"
    out_dir = tmp_path / "out"
    in_dir.mkdir()
    # Top-level files plus a nested one with the same basename as a top-level file, to
    # exercise --recursive subdirectory preservation (no collision in the flat output dir).
    names = ["a.bin", "b.dat", "c.txt"]
    for n in names:
        (in_dir / n).write_bytes(f"contents of {n}\n".encode())
    (in_dir / "sub").mkdir()
    (in_dir / "sub" / "a.bin").write_bytes(b"nested contents\n")

    proc = subprocess.run(
        [sys.executable, "-m", "cedula_uy_pdf_sign", "sign-any-batch",
         "--input-dir", str(in_dir), "--output-dir", str(out_dir), "--recursive",
         "--pkcs11-lib", module, "--token-label", TOKEN_LABEL, "--pin-source", "stdin"],
        env=env, input=PIN + "\n", capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr

    from cedula_uy_pdf_sign.cms_verify import verify_cms
    # Each output mirrors the input's relative path; the nested a.bin does not clobber the
    # top-level a.bin.
    outputs = {
        "a.bin": out_dir / "a.bin.p7s",
        "b.dat": out_dir / "b.dat.p7s",
        "c.txt": out_dir / "c.txt.p7s",
        "sub/a.bin": out_dir / "sub" / "a.bin.p7s",
    }
    for rel, out in outputs.items():
        assert out.exists(), f"missing {out}"
        res = verify_cms((in_dir / rel).read_bytes(), out.read_bytes(), trust_roots=None)
        assert res.indication == "INDETERMINATE"
        assert all(c.ok for c in res.checks), [(c.name, c.detail) for c in res.checks if not c.ok]
