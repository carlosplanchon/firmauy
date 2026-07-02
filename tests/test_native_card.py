"""Unit tests for the native (PKCS#11-free) cédula signing path.

These drive a fake pyscard connection (a stub ``transmit`` recording APDUs and returning scripted
status words, like ``tests/test_card_reader.py``) -- no card, no PC/SC, no PKCS#11. They pin the exact
APDU byte sequences against ``docs/card-protocol.md``, the pre-computed-digest PSO:HASH form, the
pyHanko ``Signer`` adapter, the PIN-safety guards, and that ``--native`` routes the CLI to the native
backend without ever touching PKCS#11."""

import asyncio
import hashlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from firmauy import native_card
from firmauy.native_card import _ALGO_HASH, sign_message, verify_pin

# APDU headers from docs/card-protocol.md.
MSE_SET_DST = [0x00, 0x22, 0x41, 0xB6, 0x06, 0x80, 0x01, 0x42, 0x84, 0x01, 0x01]
PSO_HASH_HEADER = [0x00, 0x2A, 0x90, 0xA0]
PSO_CDS = [0x00, 0x2A, 0x9E, 0x9A, 0x00]
_SIG = bytes(range(256))   # a recognizable fake 256-byte RSA-2048 signature


# ── test double ────────────────────────────────────────────────────────────────

class FakeConn:
    """A pyscard-like connection: records every transmitted APDU and answers by INS/P1-P2.

    ``pin_status`` is the (sw1, sw2) returned by the status-probe VERIFY (empty body); ``verify_sw``
    the answer to a real VERIFY; ``hash_sw`` the answer to PSO:HASH (default 61 20, the card's
    success form). The 256-byte signature is delivered via GET RESPONSE, as on the real card;
    ``get_responses`` overrides it with scripted (data, sw1, sw2) answers consumed in order, to
    exercise chained 61 xx delivery."""

    def __init__(self, *, pin_status=(0x90, 0x00), verify_sw=(0x90, 0x00),
                 hash_sw=(0x61, 0x20), signature=_SIG, get_responses=None):
        self.log = []
        self._pin_status = pin_status
        self._verify_sw = verify_sw
        self._hash_sw = hash_sw
        self._signature = signature
        self._get_responses = list(get_responses) if get_responses else None

    def transmit(self, apdu):
        apdu = list(apdu)
        self.log.append(apdu)
        ins, p1, p2 = apdu[1], apdu[2], apdu[3]
        if ins == 0x20:                                   # VERIFY
            return ([], *(self._pin_status if len(apdu) == 4 else self._verify_sw))
        if ins == 0x22:                                   # MSE:SET DST
            return ([], 0x90, 0x00)
        if ins == 0x2A and (p1, p2) == (0x90, 0xA0):      # PSO:HASH
            return ([], *self._hash_sw)
        if ins == 0x2A and (p1, p2) == (0x9E, 0x9A):      # PSO:CDS
            return ([], 0x61, 0x00)                        # 256 bytes available -> GET RESPONSE
        if ins == 0xC0:                                   # GET RESPONSE
            if self._get_responses is not None:
                data, sw1, sw2 = self._get_responses.pop(0)
                return (list(data), sw1, sw2)
            return (list(self._signature), 0x90, 0x00)
        raise AssertionError(f"unexpected APDU: {bytes(apdu).hex()}")

    def disconnect(self):
        self.log.append("disconnect")

    def getReader(self):
        # pyscard CardConnection API: the resolved reader name (shown in the identity block).
        return "Fake Reader 00"


def _make_cert(not_before=None, not_after=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "UY"),
        x509.NameAttribute(NameOID.COMMON_NAME, "PEREZ JUAN"),
    ])
    import datetime
    return (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key()).serial_number(0x1A)
        .not_valid_before(not_before or datetime.datetime(2020, 1, 1))
        .not_valid_after(not_after or datetime.datetime(2030, 1, 1))
        .sign(key, hashes.SHA256())
    )


# ── sign_message APDU sequence ───────────────────────────────────────────────

def _pso_hash_apdu(msg, algo=0x42):
    digest = hashlib.new(_ALGO_HASH[algo], msg).digest()
    do = [0x90, len(digest)] + list(digest)              # tag 0x90 + pre-computed digest
    return PSO_HASH_HEADER + [len(do)] + do


def test_sign_message_apdu_sequence():
    conn = FakeConn()
    msg = b"CMS SignedAttributes bytes to be signed"
    sig = sign_message(conn, msg)
    assert sig == _SIG
    # Exact command order: MSE:SET DST -> PSO:HASH -> PSO:CDS -> GET RESPONSE.
    assert conn.log[0] == MSE_SET_DST
    assert conn.log[1] == _pso_hash_apdu(msg)
    assert conn.log[1][5:7] == [0x90, 0x20]              # tag 0x90 + 32-byte SHA-256 digest
    assert conn.log[2] == PSO_CDS
    assert conn.log[3] == [0x00, 0xC0, 0x00, 0x00, 0x00]


def test_sign_message_sends_sha256_of_message():
    # The card is handed the SHA-256 of the message, not the raw message.
    conn = FakeConn()
    sign_message(conn, b"hello world")
    digest = hashlib.sha256(b"hello world").digest()
    assert conn.log[1] == PSO_HASH_HEADER + [0x22, 0x90, 0x20] + list(digest)


def test_sign_message_hash_apdu_is_single_short_apdu_any_size():
    # The digest is always 32 bytes, so PSO:HASH is one short APDU regardless of payload size.
    conn = FakeConn()
    sign_message(conn, bytes(50_000))
    pso_hash = conn.log[1]
    assert pso_hash[4] == 0x22 and len(pso_hash) == 5 + 0x22   # Lc = 34 = 2 (90 20) + 32-byte digest


def test_sign_message_rejects_hash_error():
    conn = FakeConn(hash_sw=(0x6A, 0x80))                 # the empty-DO rejection code
    with pytest.raises(RuntimeError, match="PSO:HASH"):
        sign_message(conn, b"data")


def test_sign_message_accepts_61_on_hash():
    # 61 20 after PSO:HASH is success, not an error (quirk #5): no exception, signature returned.
    conn = FakeConn(hash_sw=(0x61, 0x20))
    assert sign_message(conn, b"data") == _SIG


def test_sign_message_collects_chained_get_response():
    # A T=0 reader may deliver the 256-byte signature in chained 61 xx chunks; they must be
    # accumulated (not overwritten), with one GET RESPONSE per announcement.
    conn = FakeConn(get_responses=[(_SIG[:128], 0x61, 0x80), (_SIG[128:], 0x90, 0x00)])
    assert sign_message(conn, b"data") == _SIG
    get_responses = [a for a in conn.log if a[1] == 0xC0]
    assert get_responses == [[0x00, 0xC0, 0x00, 0x00, 0x00], [0x00, 0xC0, 0x00, 0x00, 0x80]]


def test_sign_message_rejects_empty_signature():
    # Success status but no signature bytes must be a hard error, not b"" embedded in the output.
    conn = FakeConn(signature=b"")
    with pytest.raises(RuntimeError, match="empty signature"):
        sign_message(conn, b"data")


def test_sign_message_validates_expected_length():
    # A truncated card response must fail loudly when the caller states the modulus size.
    assert sign_message(FakeConn(), b"data", expected_len=256) == _SIG
    with pytest.raises(RuntimeError, match="100 signature bytes, expected 256"):
        sign_message(FakeConn(signature=_SIG[:100]), b"data", expected_len=256)


# ── PIN safety ────────────────────────────────────────────────────────────────

def test_verify_pin_blocked_aborts():
    conn = FakeConn(pin_status=(0x69, 0x83))
    with pytest.raises(RuntimeError, match="blocked"):
        verify_pin(conn, "1234")
    assert all(len(a) == 4 for a in conn.log)            # only the status probe; no VERIFY attempt


def test_verify_pin_one_try_left_aborts():
    conn = FakeConn(pin_status=(0x63, 0x01))
    with pytest.raises(RuntimeError, match="try left"):
        verify_pin(conn, "1234")
    assert conn.log == [[0x00, 0x20, 0x00, 0x11]]        # probed, then refused to spend the last try


def test_verify_pin_already_verified_is_noop():
    conn = FakeConn(pin_status=(0x90, 0x00))
    verify_pin(conn, "1234")
    assert conn.log == [[0x00, 0x20, 0x00, 0x11]]        # session already authenticated; no VERIFY


def test_verify_pin_sends_padded_pin():
    conn = FakeConn(pin_status=(0x63, 0x03))             # 3 tries left -> proceed
    verify_pin(conn, "1234")
    body = list(b"1234") + [0x00] * 8                    # zero-padded to the stored length of 12
    assert conn.log[-1] == [0x00, 0x20, 0x00, 0x11, 0x0C] + body


def test_verify_pin_wrong_reports_tries():
    conn = FakeConn(pin_status=(0x63, 0x03), verify_sw=(0x63, 0x02))
    with pytest.raises(RuntimeError, match="2 tries left"):
        verify_pin(conn, "1234")


def test_verify_pin_unknown_probe_status_fails_closed():
    # A card whose status probe answers something unmodeled (e.g. 67 00 on another applet
    # generation) must abort WITHOUT sending the PIN: the retry counter is unknown, so a real
    # VERIFY could silently spend the last try.
    conn = FakeConn(pin_status=(0x67, 0x00))
    with pytest.raises(RuntimeError, match="status probe"):
        verify_pin(conn, "1234")
    assert conn.log == [[0x00, 0x20, 0x00, 0x11]]        # only the probe; no PIN ever transmitted


# ── certificate + pyHanko adapter ───────────────────────────────────────────────

def test_read_signing_certificate(monkeypatch):
    cert = _make_cert()
    monkeypatch.setattr(native_card, "read_file", lambda conn, fid: list(cert.public_bytes(Encoding.DER)))
    got = native_card.read_signing_certificate(FakeConn())
    assert got.serial_number == 0x1A
    assert got.subject == cert.subject


@pytest.mark.parametrize("padding", [b"\x00" * 16, b"\xff" * 16])
def test_read_signing_certificate_tolerates_ef_padding(monkeypatch, padding):
    # read_file returns the EF's full allocated size (FCI tag 81); a personalization that pads
    # B001 past the DER must not break parsing (load_der rejects any trailing byte).
    cert = _make_cert()
    padded = cert.public_bytes(Encoding.DER) + padding
    monkeypatch.setattr(native_card, "read_file", lambda conn, fid: list(padded))
    got = native_card.read_signing_certificate(FakeConn())
    assert got.serial_number == 0x1A


def test_read_signing_certificate_rejects_non_der_content(monkeypatch):
    monkeypatch.setattr(native_card, "read_file", lambda conn, fid: list(b"\x00garbage"))
    with pytest.raises(RuntimeError, match="DER SEQUENCE"):
        native_card.read_signing_certificate(FakeConn())


def test_native_signer_sign_and_dry_run():
    conn = FakeConn()
    signer = native_card.make_native_signer(conn, _make_cert())
    # dry_run never touches the card (used by pyHanko to size the placeholder).
    dry = asyncio.run(signer.async_sign_raw(b"anything", "sha256", dry_run=True))
    assert dry == b"\x00" * 256
    assert conn.log == []
    # A real sign runs the full APDU flow and returns the card's signature.
    real = asyncio.run(signer.async_sign_raw(b"to-be-signed", "sha256"))
    assert real == _SIG
    assert conn.log[0] == MSE_SET_DST


def test_native_signer_rejects_unknown_digest():
    signer = native_card.make_native_signer(FakeConn(), _make_cert())
    with pytest.raises(RuntimeError, match="unsupported digest"):
        asyncio.run(signer.async_sign_raw(b"x", "md5"))


def test_native_signer_rejects_truncated_signature():
    # The adapter passes the modulus size as expected_len, so a short card response never
    # reaches pyHanko as a "signature".
    signer = native_card.make_native_signer(FakeConn(signature=_SIG[:100]), _make_cert())
    with pytest.raises(RuntimeError, match="expected 256"):
        asyncio.run(signer.async_sign_raw(b"x", "sha256"))


# ── CLI dispatch: --native must not touch PKCS#11 ───────────────────────────────

def test_cli_native_routes_to_native_backend(monkeypatch, tmp_path):
    from typer.testing import CliRunner
    from firmauy import cli
    from firmauy.cli import app

    conn = FakeConn()
    cert = _make_cert()
    recorded = {}

    # Native backend seams: reader open, applet select, cert read and PIN verify are all stubbed.
    monkeypatch.setattr(cli, "open_reader", lambda reader=None: conn)
    monkeypatch.setattr(cli, "select_applet", lambda c: None)
    monkeypatch.setattr(native_card, "read_signing_certificate", lambda c: cert)
    monkeypatch.setattr(native_card, "verify_pin", lambda c, pin: recorded.setdefault("pin", pin))
    monkeypatch.setattr(native_card, "make_native_signer", lambda c, ct: object())
    monkeypatch.setattr(cli, "get_pin", lambda *a, **k: "1234")
    # Record that the CMS worker got the native signer, without doing real CMS signing.
    monkeypatch.setattr(cli, "_sign_one_cms", lambda **k: recorded.setdefault("signed", True))
    # Any PKCS#11 access is a bug in native mode.
    def _boom(*a, **k):
        raise AssertionError("PKCS#11 must not be used with --native")
    monkeypatch.setattr(cli, "load_pkcs11_lib", _boom)

    src = tmp_path / "data.bin"
    src.write_bytes(b"payload")
    out = tmp_path / "data.bin.p7s"
    r = CliRunner().invoke(app, ["sign-any", str(src), str(out), "--native"])

    assert r.exit_code == 0, r.output
    assert recorded == {"pin": "1234", "signed": True}
    assert "Reader:" in r.output                          # native identity block, not "Token:"
    assert "Fake Reader 00" in r.output                   # the resolved device name, not a placeholder
    assert "pcscd" in r.output                            # the backend pre-flight note still fires
    assert "disconnect" in conn.log                       # connection closed on exit


def test_cli_native_rejects_expired_certificate(monkeypatch, tmp_path):
    # Same validity guard the PKCS#11 path gets from select_certificate: an expired card
    # certificate aborts the native session BEFORE the PIN is ever requested.
    import datetime
    from typer.testing import CliRunner
    from firmauy import cli
    from firmauy.cli import app

    conn = FakeConn()
    expired = _make_cert(not_after=datetime.datetime(2021, 1, 1))

    monkeypatch.setattr(cli, "open_reader", lambda reader=None: conn)
    monkeypatch.setattr(cli, "select_applet", lambda c: None)
    monkeypatch.setattr(native_card, "read_signing_certificate", lambda c: expired)

    def _no_pin(*a, **k):
        raise AssertionError("the PIN must not be requested for an expired certificate")
    monkeypatch.setattr(cli, "get_pin", _no_pin)

    src = tmp_path / "data.bin"
    src.write_bytes(b"payload")
    r = CliRunner().invoke(app, ["sign-any", str(src), str(tmp_path / "data.bin.p7s"), "--native"])

    assert r.exit_code != 0
    assert "expired" in r.output
    assert "disconnect" in conn.log                       # connection still closed on the way out
