"""Regression tests: CMS and PDF verification stay quiet on chain-building failure.

pyHanko logs a full traceback at WARNING (on the ``pyhanko.sign.validation.generic_cms``
logger) when it cannot build a trust path — an expected outcome with no/untrusted anchors,
already surfaced cleanly as INDETERMINATE through the per-check breakdown. ``verify_cms`` and
``verify_pdf`` wrap that path in ``muted_path_building_warnings`` so the traceback never
reaches the user's terminal. These tests lock that in (verify-xml is not affected: it does
its own chain validation and never hits ``generic_cms``).
"""

import datetime
import io
import logging
from contextlib import contextmanager

from asn1crypto import keys as asn1keys
from asn1crypto import x509 as asn1x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.writer import PageObject, PdfFileWriter
from pyhanko.sign.signers import PdfSignatureMetadata, SimpleSigner, sign_pdf
from pyhanko_certvalidator.registry import SimpleCertificateStore

from cedula_uy_pdf_sign.cms_sign import sign_cms_detached
from cedula_uy_pdf_sign.cms_verify import verify_cms
from cedula_uy_pdf_sign.pdf_verify import verify_pdf
from cedula_uy_pdf_sign.verify_common import muted_path_building_warnings

_PYHANKO_PATH_LOGGER = "pyhanko.sign.validation.generic_cms"


def _self_signed(cn: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
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
    return key, cert


def _simple_signer(key, cert) -> SimpleSigner:
    der = cert.public_bytes(serialization.Encoding.DER)
    return SimpleSigner(
        signing_cert=asn1x509.Certificate.load(der),
        signing_key=asn1keys.PrivateKeyInfo.load(key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())),
        cert_registry=SimpleCertificateStore(),
    )


def _sign_blank_pdf(key, cert) -> bytes:
    w = PdfFileWriter()
    media_box = generic.ArrayObject([generic.NumberObject(n) for n in (0, 0, 200, 200)])
    contents = w.add_object(generic.StreamObject(stream_data=b""))
    w.insert_page(PageObject(contents=contents, media_box=media_box))
    base = io.BytesIO()
    w.write(base)
    base.seek(0)
    out = io.BytesIO()
    sign_pdf(IncrementalPdfFileWriter(base), PdfSignatureMetadata(field_name="Sig1"),
             signer=_simple_signer(key, cert), output=out)
    return out.getvalue()


@contextmanager
def _capture_generic_cms_records():
    """Collect log records emitted on pyHanko's path-building logger."""
    logger = logging.getLogger(_PYHANKO_PATH_LOGGER)
    records: list = []
    handler = logging.Handler()
    handler.emit = records.append  # type: ignore[method-assign]
    logger.addHandler(handler)
    try:
        yield records
    finally:
        logger.removeHandler(handler)


def test_muted_path_building_warnings_suppresses_and_restores():
    logger = logging.getLogger(_PYHANKO_PATH_LOGGER)
    before = logger.level
    with _capture_generic_cms_records() as records:
        with muted_path_building_warnings():
            assert logger.level == logging.ERROR
            logger.warning("Failed to build path (should be muted)", exc_info=ValueError("x"))
        assert records == []  # muted: the WARNING never reaches the handler

        # Positive control: outside the context the same logger does emit, so the
        # assertions above would actually catch a regression.
        logger.warning("control warning (not muted)")
        assert len(records) == 1

    assert logger.level == before  # original level restored


def test_verify_cms_chain_failure_is_quiet():
    key, leaf = _self_signed("LEAF SIGNER")
    _, wrong_root = _self_signed("UNRELATED ROOT")
    data = b"payload to sign"
    p7s = sign_cms_detached(data, signer=_simple_signer(key, leaf))

    with _capture_generic_cms_records() as records:
        res = verify_cms(data, p7s, trust_roots=[wrong_root])

    assert res.indication == "INDETERMINATE"  # integrity OK, chain not trusted
    assert records == [], [r.getMessage() for r in records]  # no traceback spew


def test_verify_pdf_chain_failure_is_quiet(tmp_path):
    key, leaf = _self_signed("LEAF SIGNER")
    _, wrong_root = _self_signed("UNRELATED ROOT")
    pdf_path = tmp_path / "signed.pdf"
    pdf_path.write_bytes(_sign_blank_pdf(key, leaf))

    with _capture_generic_cms_records() as records:
        results = verify_pdf(pdf_path, trust_roots=[wrong_root])

    assert results[0].indication == "INDETERMINATE"
    assert records == [], [r.getMessage() for r in records]
