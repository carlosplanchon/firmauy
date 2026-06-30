import datetime

import pytest
import typer
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cedula_uy_pdf_sign.pkcs11_utils import (
    cert_is_expired,
    cert_not_yet_valid,
    has_private_key,
    normalize_cert_id_hex,
)


class _FakeSession:
    def __init__(self, items=(), error=None):
        self.items = items
        self.error = error

    def get_objects(self, query):
        if self.error is not None:
            raise self.error
        return iter(self.items)


class TestHasPrivateKey:
    def test_true_when_present(self):
        assert has_private_key(_FakeSession(items=[object()]), b"\x01") is True

    def test_false_when_absent(self):
        assert has_private_key(_FakeSession(items=[]), b"\x01") is False

    def test_propagates_errors_instead_of_swallowing(self):
        # A genuine PKCS#11 error must surface, not be hidden as "no key" (which could drop the
        # only usable certificate).
        with pytest.raises(RuntimeError, match="device error"):
            has_private_key(_FakeSession(error=RuntimeError("device error")), b"\x01")


class TestNormalizeCertIdHex:
    def test_clean_hex_uppercased(self):
        assert normalize_cert_id_hex("abcdef") == "ABCDEF"

    def test_already_uppercase(self):
        assert normalize_cert_id_hex("ABCDEF") == "ABCDEF"

    def test_strips_colons(self):
        assert normalize_cert_id_hex("ab:cd:ef") == "ABCDEF"

    def test_strips_spaces(self):
        assert normalize_cert_id_hex("ab cd ef") == "ABCDEF"

    def test_strips_colons_and_spaces(self):
        assert normalize_cert_id_hex("ab: cd :ef") == "ABCDEF"

    def test_digits_only(self):
        assert normalize_cert_id_hex("0123456789") == "0123456789"

    def test_invalid_raises_bad_parameter(self):
        with pytest.raises(typer.BadParameter):
            normalize_cert_id_hex("zz")

    def test_empty_raises_bad_parameter(self):
        with pytest.raises(typer.BadParameter):
            normalize_cert_id_hex("")


class TestCertIsExpired:
    def test_valid_cert_not_expired(self, cert_valid):
        assert cert_is_expired(cert_valid) is False

    def test_expired_cert_is_expired(self, cert_expired):
        assert cert_is_expired(cert_expired) is True


def _future_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FUTURE")])
    return (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(now + datetime.timedelta(days=10))
        .not_valid_after(now + datetime.timedelta(days=380))
        .sign(key, hashes.SHA256())
    )


class TestCertNotYetValid:
    def test_currently_valid_cert_is_not_future(self, cert_valid):
        assert cert_not_yet_valid(cert_valid) is False

    def test_future_cert_is_not_yet_valid(self):
        cert = _future_cert()
        assert cert_not_yet_valid(cert) is True
        assert cert_is_expired(cert) is False   # future != expired
