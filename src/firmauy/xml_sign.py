# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Standards-based XAdES-BES enveloped XML signing (ETSI EN 319 132).

The cédula private key is non-extractable, so the raw RSA-SHA256 operation is
delegated to the token via a `signer` callable (two-phase / delegated signing):
this module builds the SignedInfo, and the caller signs its canonical form on the
card. The produced signature follows the XAdES-BES profile: enveloped, inclusive
C14N 1.0, RSA-SHA256 / SHA-256, signature appended as the last child of the
document root.
"""

import base64
import copy
import hashlib
import uuid
from datetime import datetime
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from lxml import etree

MAX_XML_BYTES = 16 * 1024 * 1024


def _secure_parser() -> etree.XMLParser:
    """Parser hardening for untrusted XML documents.

    Explicitly forbid DTD loading, network access and entity resolution so a malicious XML
    cannot read local files, issue outbound requests, or expand an entity bomb.
    """
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        huge_tree=False,
    )


# Namespaces
DSIG = "http://www.w3.org/2000/09/xmldsig#"
XADES = "http://uri.etsi.org/01903/v1.3.2#"
XADES141 = "http://uri.etsi.org/01903/v1.4.1#"

# Algorithm URIs (XAdES / XMLDSig standard)
ALG_C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
ALG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
ALG_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
ALG_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
SIGNED_PROPS_TYPE = "http://uri.etsi.org/01903#SignedProperties"

XML_DECLARATION = b'<?xml version="1.0" encoding="UTF-8" standalone="no"?>'

# A callable that signs the canonical SignedInfo on the token and returns the raw
# RSA-SHA256 (PKCS#1 v1.5) signature bytes.
RawSigner = Callable[[bytes], bytes]


def _ds(tag: str) -> str:
    return f"{{{DSIG}}}{tag}"


def _xades(tag: str) -> str:
    return f"{{{XADES}}}{tag}"


def _c14n(node) -> bytes:
    """Inclusive C14N 1.0, no comments (REC-xml-c14n-20010315)."""
    return etree.tostring(node, method="c14n", exclusive=False, with_comments=False)


def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


def _wrap_b64(data: bytes, width: int = 76) -> str:
    """Base64 wrapped at `width` chars with leading/trailing newline (Santuario style)."""
    s = base64.b64encode(data).decode()
    return "\n" + "\n".join(s[i:i + width] for i in range(0, len(s), width)) + "\n"


def _nl_block(elem) -> None:
    """Put each child of `elem` on its own line (newline, no indentation)."""
    elem.text = "\n"
    for child in elem:
        child.tail = "\n"


def _remove_keeping_tail(elem) -> None:
    """Take ``elem`` out of its parent and leave the text that followed it where it was.

    lxml hands an element's tail to the element, so ``remove()`` takes the tail along. In the XML
    data model that text is a sibling node of the element and belongs to the parent, and the
    enveloped transform below removes the element and nothing else. A pretty-printed document has
    a newline between ``</ds:Signature>`` and the closing root tag, a validator following the
    specification digests that newline, and dropping it computed a digest nobody else would.
    """
    parent = elem.getparent()
    if elem.tail:
        previous = elem.getprevious()
        if previous is not None:
            previous.tail = (previous.tail or "") + elem.tail
        else:
            parent.text = (parent.text or "") + elem.tail
    parent.remove(elem)


def _compute_enveloped_digest(root, sig) -> str:
    """The enveloped-signature transform of XMLDSig section 6.6.4, then C14N and SHA-256: the
    document with *this* ``<ds:Signature>`` removed and every other one left in place.

    Only this one, which is what the transform says and what every other validator computes.
    The convention here used to be to strip every signature, so that two of them could each
    cover the same signature-free content. That made a document carrying two firmauy signatures
    verify here and nowhere else: a validator following the specification computes each digest
    over the document with the other signature still in it, and reports both as not matching.

    ``sig`` must be a direct child of ``root``, which is where this module puts it and the only
    place ``xml_verify`` looks for one. It is found in the copy by position, since a deep copy
    keeps no identities.
    """
    index = list(root).index(sig)
    root_copy = copy.deepcopy(root)
    _remove_keeping_tail(root_copy[index])
    return _sha256_b64(_c14n(root_copy))


def _build_signature(root, cert: x509.Certificate, signing_time: datetime) -> dict:
    """Build the full <ds:Signature> with placeholder digests/value; append to root."""
    cert_der = cert.public_bytes(Encoding.DER)
    sig_id = f"xmldsig-{uuid.uuid4()}"
    ref0_id = f"{sig_id}-ref0"
    sprops_id = f"{sig_id}-signedprops"

    sig = etree.SubElement(root, _ds("Signature"), nsmap={"ds": DSIG})
    sig.set("Id", sig_id)

    # SignedInfo
    si = etree.SubElement(sig, _ds("SignedInfo"))
    etree.SubElement(si, _ds("CanonicalizationMethod")).set("Algorithm", ALG_C14N)
    etree.SubElement(si, _ds("SignatureMethod")).set("Algorithm", ALG_RSA_SHA256)

    ref0 = etree.SubElement(si, _ds("Reference"))
    ref0.set("Id", ref0_id)
    ref0.set("URI", "")
    transforms = etree.SubElement(ref0, _ds("Transforms"))
    etree.SubElement(transforms, _ds("Transform")).set("Algorithm", ALG_ENVELOPED)
    etree.SubElement(ref0, _ds("DigestMethod")).set("Algorithm", ALG_SHA256)
    ref0_dv = etree.SubElement(ref0, _ds("DigestValue"))

    refp = etree.SubElement(si, _ds("Reference"))
    refp.set("Type", SIGNED_PROPS_TYPE)
    refp.set("URI", f"#{sprops_id}")
    etree.SubElement(refp, _ds("DigestMethod")).set("Algorithm", ALG_SHA256)
    refp_dv = etree.SubElement(refp, _ds("DigestValue"))

    # SignatureValue (placeholder)
    sv = etree.SubElement(sig, _ds("SignatureValue"))
    sv.set("Id", f"{sig_id}-sigvalue")

    # KeyInfo / X509Certificate
    ki = etree.SubElement(sig, _ds("KeyInfo"))
    x509data = etree.SubElement(ki, _ds("X509Data"))
    x509cert = etree.SubElement(x509data, _ds("X509Certificate"))

    # Object / QualifyingProperties / SignedProperties
    obj = etree.SubElement(sig, _ds("Object"))
    qp = etree.SubElement(obj, _xades("QualifyingProperties"),
                          nsmap={"xades": XADES, "xades141": XADES141})
    qp.set("Target", f"#{sig_id}")
    sp = etree.SubElement(qp, _xades("SignedProperties"))
    sp.set("Id", sprops_id)

    ssp = etree.SubElement(sp, _xades("SignedSignatureProperties"))
    etree.SubElement(ssp, _xades("SigningTime")).text = \
        signing_time.isoformat(timespec="milliseconds")

    scert = etree.SubElement(ssp, _xades("SigningCertificate"))
    cert_el = etree.SubElement(scert, _xades("Cert"))
    cdig = etree.SubElement(cert_el, _xades("CertDigest"))
    etree.SubElement(cdig, _ds("DigestMethod")).set("Algorithm", ALG_SHA256)
    etree.SubElement(cdig, _ds("DigestValue")).text = _sha256_b64(cert_der)
    issuer_serial = etree.SubElement(cert_el, _xades("IssuerSerial"))
    etree.SubElement(issuer_serial, _ds("X509IssuerName")).text = cert.issuer.rfc4514_string()
    etree.SubElement(issuer_serial, _ds("X509SerialNumber")).text = str(cert.serial_number)

    sdop = etree.SubElement(sp, _xades("SignedDataObjectProperties"))
    dof = etree.SubElement(sdop, _xades("DataObjectFormat"))
    dof.set("ObjectReference", f"#{ref0_id}")
    etree.SubElement(dof, _xades("MimeType")).text = "text/xml"

    # Serialization style: newlines between the Signature block children (no indent);
    # the Object / QualifyingProperties subtree stays inline.
    for elem in (sig, si, ref0, transforms, refp, ki, x509data):
        _nl_block(elem)
    x509cert.text = _wrap_b64(cert_der)

    return {"sig": sig, "si": si, "sp": sp, "ref0_dv": ref0_dv,
            "refp_dv": refp_dv, "sv": sv}


def _add_signature_timestamp(sig, sv, timestamper) -> None:
    """Add a XAdES-T <SignatureTimeStamp> over the canonicalized <ds:SignatureValue>.

    The timestamp lives in UnsignedProperties: it is computed over the SignatureValue, so it
    cannot be covered by the main signature. `timestamper` is a pyHanko TimeStamper; it returns
    an RFC 3161 token (asn1crypto ContentInfo) that is DER-encoded into EncapsulatedTimeStamp."""
    import asyncio

    digest = hashlib.sha256(_c14n(sv)).digest()
    token = asyncio.run(timestamper.async_timestamp(digest, "sha256"))

    qp = sig.find(f"{_ds('Object')}/{_xades('QualifyingProperties')}")
    up = etree.SubElement(qp, _xades("UnsignedProperties"))
    usp = etree.SubElement(up, _xades("UnsignedSignatureProperties"))
    sts = etree.SubElement(usp, _xades("SignatureTimeStamp"))
    etree.SubElement(sts, _ds("CanonicalizationMethod")).set("Algorithm", ALG_C14N)
    etree.SubElement(sts, _xades("EncapsulatedTimeStamp")).text = _wrap_b64(token.dump())
    for elem in (up, usp, sts):
        _nl_block(elem)


def sign_xml(
    xml_bytes: bytes,
    *,
    cert: x509.Certificate,
    signer: RawSigner,
    signing_time: datetime,
    timestamper=None,
) -> bytes:
    """Produce a XAdES-BES enveloped signature over `xml_bytes`.

    `signer` receives the canonical SignedInfo and must return the raw RSA-SHA256
    signature (the PKCS#11 SHA256_RSA_PKCS mechanism, i.e. hash + sign).

    With `timestamper` (a pyHanko TimeStamper), a XAdES-T SignatureTimeStamp is added over the
    SignatureValue, upgrading the result from XAdES-BES to XAdES-T.
    Returns the signed XML as UTF-8 bytes.

    Raises ``RuntimeError`` for a document that already carries a signature over its whole
    content at the root: see :func:`_refuse_to_countersign` for why there is no version of that
    file worth producing.
    """
    if len(xml_bytes) > MAX_XML_BYTES:
        raise ValueError(
            f"XML input exceeds the {MAX_XML_BYTES} byte limit; refusing to parse it"
        )
    root = etree.fromstring(xml_bytes, parser=_secure_parser())
    _refuse_to_countersign(root)
    return _sign_root(root, cert=cert, signer=signer, signing_time=signing_time,
                      timestamper=timestamper)


def _refuse_to_countersign(root) -> None:
    """Raise if a signature already at the root covers the whole document.

    An enveloped signature over the root covers everything under it, an existing signature
    included, and that existing signature was computed before the new one was there. Under the
    enveloped transform as specified, every validator then reports it as no longer matching the
    document. Refused rather than warned about, because there is no version of that file worth
    having: the way to put a second signature on a signed XML without touching it is a detached
    CAdES over the whole file, which ``sign --as cades`` produces.

    Only a whole-document reference counts, ``URI=""`` or no URI at all. A signature over one
    element by Id is covered by the new signature like any other content and stays exactly as
    valid as it was.
    """
    for existing in root.findall(_ds("Signature")):
        refs = existing.findall(f"{_ds('SignedInfo')}/{_ds('Reference')}")
        if any((ref.get("URI") or "") == "" for ref in refs):
            raise RuntimeError(
                "The document already carries a signature over its whole content. A second "
                "enveloped signature would cover the existing one and leave it no longer matching "
                "the document under the XMLDSig enveloped transform, which every validator would "
                "report as a broken signature. To add a signature to a signed XML, sign the signed "
                "file as a detached CAdES .p7s (`sign --as cades`), or sign the original unsigned "
                "document."
            )


def _sign_root(root, *, cert: x509.Certificate, signer: RawSigner, signing_time: datetime,
               timestamper=None) -> bytes:
    """Append a signature to an already parsed root and serialize the result.

    What :func:`sign_xml` does once it has decided the document may take one. Separate so the
    countersignature the specification describes can be built where it is wanted, which is in
    the tests that show what it does to the signature already there.
    """
    p = _build_signature(root, cert, signing_time)

    # Phase 1: reference digests.
    p["ref0_dv"].text = _compute_enveloped_digest(root, p["sig"])
    p["refp_dv"].text = _sha256_b64(_c14n(p["sp"]))

    # Phase 2: sign the canonical SignedInfo on the token.
    p["sv"].text = _wrap_b64(signer(_c14n(p["si"])))

    # Optional XAdES-T: a trusted RFC 3161 timestamp over the SignatureValue.
    if timestamper is not None:
        _add_signature_timestamp(p["sig"], p["sv"], timestamper)

    body = etree.tostring(root, encoding="UTF-8", xml_declaration=False)
    return XML_DECLARATION + body
