"""Shared fixtures: in-memory x509 test certificates, and the Hypothesis profiles."""

import datetime
import os

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
def _can_symlink(tmp_path_factory) -> bool:
    probe = tmp_path_factory.mktemp("symlink-probe")
    try:
        (probe / "link").symlink_to(probe / "target")
    except OSError:
        return False
    return True


@pytest.fixture
def symlinks(_can_symlink) -> None:
    """Skip unless this account can create symbolic links. Windows only allows that to an
    administrator or with Developer Mode on (WinError 1314 otherwise); CI runners have it."""
    if not _can_symlink:
        pytest.skip("this account cannot create symbolic links")


@pytest.fixture(scope="session")
def cert_valid() -> x509.Certificate:
    future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    return _build_cert(_SUBJECT, _ISSUER, future)


@pytest.fixture(scope="session")
def cert_expired() -> x509.Certificate:
    past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=400)
    return _build_cert(_SUBJECT, _ISSUER, past)


# --- property-based testing profiles ------------------------------------------
#
# Two depths for the same properties. The shallow one runs with the normal suite, across every
# Python version in the matrix, so it has to stay cheap enough that nobody is tempted to skip it.
# The deep one runs once in the sweep job, on every pull request and every push to main, where
# finding something rare matters more than finishing quickly.
#
#   FIRMAUY_DEEP=1    the deep profile, forty times the examples
#
# Every example does a real cryptographic verification whose cost depends on how far into
# validation the damage is caught, so there is no meaningful per-example deadline to enforce.
# The suite's own runtime is the budget that matters, and the example count is what sets it.
from hypothesis import HealthCheck, settings  # noqa: E402

settings.register_profile(
    "shallow", max_examples=50, deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.register_profile(
    "deep", max_examples=2000, deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile("deep" if os.environ.get("FIRMAUY_DEEP") else "shallow")
