"""Security checks for the XML signing input parser."""

import datetime

import pytest
from lxml import etree

from firmauy.xml_sign import MAX_XML_BYTES, _ds, sign_xml


def test_external_entity_is_not_resolved_when_signing(tmp_path, cert_valid):
    payload = tmp_path / "secret.txt"
    payload.write_text("TOPSECRET")
    xml = (
        f"<!DOCTYPE root [<!ENTITY xxe SYSTEM 'file://{payload}'>]>"
        "<root>&xxe;</root>"
    ).encode()

    with pytest.raises(etree.C14NError):
        sign_xml(
            xml,
            cert=cert_valid,
            signer=lambda data: b"signature",
            signing_time=datetime.datetime.now(datetime.timezone.utc),
        )


def test_a_document_already_signed_over_its_whole_content_is_refused(cert_valid):
    """A second enveloped signature covers the first and leaves it no longer matching the document
    under the transform as specified. There is no version of that file worth producing."""
    signed = sign_xml(
        b"<root><d>x</d></root>",
        cert=cert_valid,
        signer=lambda data: b"signature",
        signing_time=datetime.datetime.now(datetime.timezone.utc),
    )

    with pytest.raises(RuntimeError, match="already carries a signature"):
        sign_xml(
            signed,
            cert=cert_valid,
            signer=lambda data: b"signature",
            signing_time=datetime.datetime.now(datetime.timezone.utc),
        )


def test_a_signature_over_one_element_does_not_block_signing(cert_valid):
    """Only a whole-document reference is broken by the new signature covering it. A signature
    over an element by Id stays as valid as it was, so the document may take another."""
    xml = (
        b"<root xmlns:ds='http://www.w3.org/2000/09/xmldsig#'><d Id='a'>x</d>"
        b"<ds:Signature><ds:SignedInfo><ds:Reference URI='#a'/></ds:SignedInfo>"
        b"<ds:SignatureValue>QUJD</ds:SignatureValue></ds:Signature></root>"
    )

    signed = sign_xml(
        xml,
        cert=cert_valid,
        signer=lambda data: b"signature",
        signing_time=datetime.datetime.now(datetime.timezone.utc),
    )

    assert len(etree.fromstring(signed).findall(_ds("Signature"))) == 2


def test_oversized_xml_is_rejected_before_parsing(cert_valid):
    xml = b"<root>" + b"x" * MAX_XML_BYTES + b"</root>"

    with pytest.raises(ValueError, match="exceeds the .* byte limit"):
        sign_xml(
            xml,
            cert=cert_valid,
            signer=lambda data: b"signature",
            signing_time=datetime.datetime.now(datetime.timezone.utc),
        )
