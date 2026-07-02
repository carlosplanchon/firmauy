"""Shared fixtures: in-memory x509 test certificates."""

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _build_cert(
    subject_attrs: list[x509.NameAttribute],
    issuer_attrs: list[x509.NameAttribute],
    not_valid_after: datetime.datetime,
) -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name(subject_attrs))
        .issuer_name(x509.Name(issuer_attrs))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_after - datetime.timedelta(days=365))
        .not_valid_after(not_valid_after)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
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


_SUBJECT = [
    x509.NameAttribute(NameOID.COMMON_NAME, "Juan Test"),
    x509.NameAttribute(NameOID.SERIAL_NUMBER, "DNI00000000"),
]

_ISSUER = [
    x509.NameAttribute(
        NameOID.COMMON_NAME,
        "Autoridad Certificadora del Ministerio del Interior",
    ),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ministerio del Interior"),
]


@pytest.fixture(scope="session")
def cert_valid() -> x509.Certificate:
    future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    return _build_cert(_SUBJECT, _ISSUER, future)


@pytest.fixture(scope="session")
def cert_expired() -> x509.Certificate:
    past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=400)
    return _build_cert(_SUBJECT, _ISSUER, past)
