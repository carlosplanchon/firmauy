# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Native (PKCS#11-free) signing for the Uruguayan cédula over PC/SC APDUs.

Drives the Gemalto IAS Classic v4 signing key directly with ISO 7816-4 APDUs over pyscard, with no
proprietary PKCS#11 middleware (``libgclib.so``) and no OpenSC. The card computes the RSA-2048
signature; this module builds the exact APDU sequence and hands the result to pyHanko through a
``Signer`` subclass (PDF/CMS) or a raw callable (XML).

Standard IAS-ECC flow: VERIFY PIN -> MSE:SET DST -> PSO:HASH -> PSO:CDS. The message is hashed in
Python and the final 32-byte SHA-256 digest is handed to the card in PSO:HASH as ``90 <len> <digest>``
(the card echoes it with ``61 20``, which is success, then discards the echo). The card wraps that
digest in the PKCS#1 DigestInfo and returns the RSA signature from PSO:CDS.

NOTE: this card does NOT use the intermediate-hash ``90 28 <state><counter> 80 <len><data>`` flow --
it rejects that with 6A80. The pre-computed-digest form above is what empirically signs and verifies
VALID on the real card. Because the card only ever receives a 32-byte digest, PSO:HASH is always a
single short APDU regardless of payload size (no message-size / multi-block concern). The card-level
protocol is documented in ``docs/card-protocol.md``.

Contact interface, no Secure Messaging, SHA-256 the only algorithm exercised in practice. Do not run
while a PKCS#11 sign session is open on the same card: both go through pcscd and will conflict.
"""

from __future__ import annotations

import hashlib

from asn1crypto import x509 as asn1_x509
from cryptography import x509 as _crypto_x509
from cryptography.hazmat.primitives.serialization import Encoding
from pyhanko.sign.signers import Signer
from pyhanko_certvalidator.registry import SimpleCertificateStore

from firmauy.card_reader import read_file
from firmauy.national_ca import load_bundled_trust_anchors

CERT_FID = 0xB001   # signing certificate EF (public, no PIN)
KEY_REF = 0x01      # signing private key reference
PIN_REF = 0x11      # User (Global) PIN reference

# pyHanko digest name -> on-card AlgoID (high nibble = hash, low nibble = PKCS#1 v1.5). With these the
# card builds the DigestInfo itself, yielding a standard RSA signature. SHA-256 (0x42) is the only one
# exercised in practice.
ALGO_ID = {"sha256": 0x42, "sha384": 0x52, "sha512": 0x62, "sha224": 0x32}
# On-card AlgoID -> hashlib name, to compute the digest the card expects for that algorithm.
_ALGO_HASH = {v: k for k, v in ALGO_ID.items()}


def _ok(sw1: int, sw2: int, what: str) -> None:
    if (sw1, sw2) != (0x90, 0x00):
        raise RuntimeError(f"{what} failed: {sw1:02X} {sw2:02X}")


# ── Certificate ─────────────────────────────────────────────────────────────────

def _der_total_length(buf: bytes, what: str) -> int:
    """Total length (header + content) of the DER SEQUENCE at the start of ``buf``."""
    if len(buf) < 2 or buf[0] != 0x30:
        raise RuntimeError(f"{what} does not start with a DER SEQUENCE.")
    first = buf[1]
    if first < 0x80:                    # short form
        return 2 + first
    n = first & 0x7F                    # long form: n length bytes follow
    if n == 0 or len(buf) < 2 + n:
        raise RuntimeError(f"Malformed DER length in {what}.")
    return 2 + n + int.from_bytes(buf[2:2 + n], "big")


def read_signing_certificate(conn) -> "_crypto_x509.Certificate":
    """Read the public signing certificate (EF B001) and return it as a cryptography x509 object.

    No PIN required; the certificate is public. Returned as a ``cryptography`` certificate so the CLI
    display helpers and the XAdES signer can consume it unchanged."""
    der = bytes(read_file(conn, CERT_FID))
    # read_file returns the EF's full allocated size (FCI tag 81), which may exceed the certificate
    # (zero/FF padding after the DER on some personalizations); trim to the outer SEQUENCE length,
    # since load_der_x509_certificate rejects any trailing byte (ParseError: ExtraData).
    der = der[:_der_total_length(der, "EF B001")]
    return _crypto_x509.load_der_x509_certificate(der)


# ── PIN ───────────────────────────────────────────────────────────────────────

def _pin_status(conn):
    """Query the retry counter without consuming a try (empty VERIFY)."""
    _, sw1, sw2 = conn.transmit([0x00, 0x20, 0x00, PIN_REF])
    if (sw1, sw2) == (0x90, 0x00):
        return "verified"
    if sw1 == 0x63:
        return sw2 & 0x0F           # tries left
    if (sw1, sw2) == (0x69, 0x83):
        return "blocked"
    return f"{sw1:02X}{sw2:02X}"


def verify_pin(conn, pin: str) -> None:
    """VERIFY the User PIN, refusing to spend the last try.

    Probes the retry counter first (a status-only VERIFY consumes no try): aborts if the PIN is
    already blocked or has <=1 try left, and returns early if the session is already verified. The
    guard fails closed: an unrecognized probe answer (a card generation that does not support the
    status-only VERIFY) also aborts, since sending the PIN without knowing the remaining tries could
    spend the last one. A wrong VERIFY consumes a retry and can lock the card, so the empty-PIN guard
    lives in ``pin.get_pin`` and this only runs once we already have a candidate PIN."""
    status = _pin_status(conn)
    if status == "blocked":
        raise RuntimeError("The PIN is blocked (too many incorrect attempts).")
    if status == "verified":
        return
    if not isinstance(status, int):
        # Unmodeled status word from the probe: refuse to send the PIN blind rather than risk
        # consuming the last try on a card whose retry counter we could not read.
        raise RuntimeError(
            f"Unexpected card response {status} to the PIN status probe; refusing to send the PIN "
            "with an unknown retry counter. This card may not support native mode."
        )
    if status <= 1:
        raise RuntimeError(
            f"Only {status} PIN try left; aborting for safety. Unblock the cédula before retrying."
        )
    try:
        pin_bytes = pin.encode("ascii")
    except UnicodeEncodeError:
        raise RuntimeError("PIN must be ASCII digits.")
    if not 4 <= len(pin_bytes) <= 8:
        raise RuntimeError("PIN must be 4..8 digits.")
    body = list(pin_bytes) + [0x00] * (12 - len(pin_bytes))   # zero-pad to the stored length of 12
    _, sw1, sw2 = conn.transmit([0x00, 0x20, 0x00, PIN_REF, 0x0C] + body)
    if sw1 == 0x63:
        raise RuntimeError(f"Incorrect PIN, {sw2 & 0x0F} tries left.")
    if (sw1, sw2) == (0x69, 0x83):
        raise RuntimeError("The PIN is blocked (too many incorrect attempts).")
    _ok(sw1, sw2, "VERIFY PIN")


# ── Signing ──────────────────────────────────────────────────────────────────

def sign_message(conn, message: bytes, algo: int = 0x42, *,
                 expected_len: int | None = None) -> bytes:
    """Sign ``message`` with the cédula's RSA-2048 key and return the raw signature bytes.

    Assumes the PIN has already been verified (see ``verify_pin``). Runs MSE:SET DST -> PSO:HASH ->
    PSO:CDS. ``message`` is the raw to-be-signed data (CMS SignedAttributes / XAdES SignedInfo / PDF
    byte range); it is hashed here in Python and only the final digest is sent to the card, which
    builds the DigestInfo and signs it. ``expected_len`` (the key's modulus size in bytes) makes a
    truncated card response a hard error instead of an invalid signature embedded in the output."""
    hash_name = _ALGO_HASH.get(algo)
    if hash_name is None:
        raise RuntimeError(f"unsupported on-card algorithm 0x{algo:02X}")
    digest = hashlib.new(hash_name, message).digest()

    # MSE:SET DST -- select the signing key (ref 0x01) and algorithm (0x42 = RSA-PKCS#1v1.5 / SHA-256).
    _, sw1, sw2 = conn.transmit(
        [0x00, 0x22, 0x41, 0xB6, 0x06, 0x80, 0x01, algo, 0x84, 0x01, KEY_REF])
    _ok(sw1, sw2, "MSE:SET DST")

    # PSO:HASH -- hand the card the pre-computed digest under tag 0x90. It always fits one short APDU
    # (32 bytes for SHA-256). The card answers 61 20 (echoing the on-card digest); the command is
    # CASE_3 (no Le), so no GET RESPONSE is issued and the echo is discarded -- 61 XX is success here,
    # not an error. This card rejects the intermediate-hash 90 28/80 flow (6A80); see module docstring.
    do = [0x90, len(digest)] + list(digest)
    _, sw1, sw2 = conn.transmit([0x00, 0x2A, 0x90, 0xA0, len(do)] + do)
    if sw1 != 0x61:
        _ok(sw1, sw2, "PSO:HASH")

    # PSO:CDS -- compute the RSA signature; collect it via GET RESPONSE while more data is announced
    # (a T=0 reader may deliver the 256-byte signature in chained 61 xx chunks).
    resp, sw1, sw2 = conn.transmit([0x00, 0x2A, 0x9E, 0x9A, 0x00])
    sig = list(resp)
    while sw1 == 0x61:
        resp, sw1, sw2 = conn.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
        sig.extend(resp)
        if not resp and sw1 == 0x61:
            # No bytes but still "more data available": bail out rather than loop forever.
            raise RuntimeError("PSO:CDS GET RESPONSE returned no data despite more being announced.")
    _ok(sw1, sw2, "PSO:CDS")
    if not sig:
        raise RuntimeError("PSO:CDS returned an empty signature despite success status.")
    if expected_len is not None and len(sig) != expected_len:
        raise RuntimeError(
            f"PSO:CDS returned {len(sig)} signature bytes, expected {expected_len}."
        )
    return bytes(sig)


# ── pyHanko Signer ─────────────────────────────────────────────────────────────

def _bundled_cert_registry():
    """Build a pyHanko certificate store seeded with the bundled national CA chain, or None.

    Parity with ``PKCS11Signer``, which embeds the issuer chain it finds on the token; the native path
    reads only the leaf (EF B001), so the chain is supplied from the package's pinned trust anchors so
    CAdES/PAdES signatures embed it."""
    roots, intermediates = load_bundled_trust_anchors()
    certs = [asn1_x509.Certificate.load(c.public_bytes(Encoding.DER))
             for c in (*roots, *intermediates)]
    return SimpleCertificateStore.from_certs(certs) if certs else None


def make_native_signer(conn, cert: "_crypto_x509.Certificate"):
    """Build a ``NativeCardSigner`` for an already-authenticated connection.

    The construction seam the CLI calls (and tests monkeypatch) instead of naming the class."""
    return NativeCardSigner(conn, cert)


class NativeCardSigner(Signer):
    """pyHanko ``Signer`` that produces RSA signatures via raw APDUs on a pyscard connection.

    The connection must already be open, the applet selected and the PIN verified. ``async_sign_raw``
    receives the bytes pyHanko wants signed (it does not pre-hash); the card computes SHA-256 and the
    RSA signature over them."""

    def __init__(self, conn, cert: "_crypto_x509.Certificate"):
        self._conn = conn
        asn1_cert = asn1_x509.Certificate.load(cert.public_bytes(Encoding.DER))
        self._sig_len = (cert.public_key().key_size + 7) // 8   # 256 for RSA-2048
        super().__init__(
            signing_cert=asn1_cert,
            cert_registry=_bundled_cert_registry(),
            prefer_pss=False,
        )

    async def async_sign_raw(self, data: bytes, digest_algorithm: str,
                             dry_run: bool = False) -> bytes:
        # pyHanko calls with dry_run=True first to size the signature placeholder; the card is not
        # touched then. The real call signs the actual bytes.
        if dry_run:
            return b"\x00" * self._sig_len
        algo = ALGO_ID.get(digest_algorithm)
        if algo is None:
            raise RuntimeError(f"unsupported digest {digest_algorithm!r}")
        return sign_message(self._conn, data, algo, expected_len=self._sig_len)
