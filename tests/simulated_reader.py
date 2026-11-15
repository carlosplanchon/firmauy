"""A virtual PC/SC reader and cédula, for integration tests that need no hardware.

The reader speaks the same APDU exchange as ``firmauy.card_reader`` expects: SELECT AID, SELECT
FILE with an FCI carrying the file size, and 0xF8-byte READ BINARY chunks. It can answer T=0 style
``61 xx`` continuations (GET RESPONSE), report absent optional files with ``6A 82`` and report a
transport failure with another status word, so the reader code and the CLI commands above it can
be exercised end to end without pyscard, pcscd or a card.

The data is fictitious. No value here belongs to a real person."""

from __future__ import annotations


AIS_AID = [0xA0, 0x00, 0x00, 0x00, 0x18, 0x40, 0x00, 0x00, 0x01, 0x63, 0x42, 0x00]


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([0x1F, tag, len(value)]) + value


def _ber_tlv(tag: bytes, value: bytes) -> bytes:
    """Wrap *value* in a BER-TLV with *tag*, long-form length above 127 bytes (as file 7004)."""
    n = len(value)
    if n < 0x80:
        length = bytes([n])
    elif n <= 0xFFFF:
        length = bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    else:
        length = bytes([0x83, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])
    return tag + length + value


def jpeg_with_dimensions(width: int, height: int, padding: int = 300) -> bytes:
    """A synthetic JPEG with a real SOF0 so the photo record's dimensions can be checked."""
    soi = b"\xff\xd8"
    app0 = b"\xff\xe0\x00\x10" + b"JFIF\x00" + b"\x00" * 9
    sof0 = (
        b"\xff\xc0\x00\x11\x08"
        + bytes([height >> 8, height & 0xFF])
        + bytes([width >> 8, width & 0xFF])
        + b"\x03"
        + b"\x00" * 9
    )
    return soi + app0 + sof0 + (b"\x00" * padding) + b"\xff\xd9"


def card_files(*, include_optional: bool = True, include_photo: bool = True) -> dict[int, bytes]:
    """The AIS files the reader commands consume, with fictitious personal data."""
    bio = (
        _tlv(0x01, b"PEREZ")
        + _tlv(0x02, b"GOMEZ")
        + _tlv(0x03, b"JUAN")
        + _tlv(0x04, b"URY")
        + _tlv(0x05, b"01011970")
        + _tlv(0x06, b"MONTEVIDEO")
        + _tlv(0x07, b"12345672")
        + _tlv(0x09, b"01012099")
    )
    files = {0x7002: bio}
    if include_optional:
        files[0x7001] = bytes([0x5F, 0x01, 0x09]) + b"00000TXXX"
        mrz = (
            b"I<URY00000" + b"0" * 20
            + b"7001010<99" + b"0" * 20
            + b"PEREZ<GOMEZ" + b"0" * 20
        )
        files[0x700B] = b"\x7f\x01" + bytes([len(mrz)]) + mrz
    if include_photo:
        files[0x7004] = _ber_tlv(b"\x3f\x01", jpeg_with_dimensions(240, 320))
    return files


class SimulatedCard:
    """A cédula state machine driven by ISO 7816-4 APDUs.

    ``chunked`` makes SELECT and READ BINARY answer ``61 xx`` and serve the body through GET
    RESPONSE, as a T=0 stack may. ``absent`` and ``status`` let a test model files that a
    personalization omits, or that fail for a reason other than absence."""

    def __init__(
        self,
        files: dict[int, bytes],
        *,
        chunked: bool = False,
        chunk_size: int = 0x40,
        absent: set[int] | None = None,
        status: dict[int, tuple[int, int]] | None = None,
    ):
        self.files = {fid: bytes(value) for fid, value in files.items()}
        self.chunked = chunked
        self.chunk_size = chunk_size
        self.absent = set(absent or ())
        self.status = dict(status or {})
        self.selected: int | None = None
        self._pending: list[int] = []
        self.apdus: list[list[int]] = []

    # -- helpers ---------------------------------------------------------

    def _fci(self, fid: int) -> list[int]:
        size = len(self.files[fid])
        body = [0x81, 0x02, (size >> 8) & 0xFF, size & 0xFF]
        return [0x6F, len(body)] + body

    def _chunked(self, body: list[int]) -> tuple[list[int], int, int]:
        """First chunk plus ``61 xx`` for the rest, or the whole body plus 90 00."""
        if not self.chunked or len(body) <= self.chunk_size:
            return body, 0x90, 0x00
        self._pending = body[self.chunk_size:]
        return body[: self.chunk_size], 0x61, len(self._pending)

    # -- APDU dispatch ---------------------------------------------------

    def transmit(self, apdu):
        self.apdus.append(list(apdu))
        apdu = list(apdu)
        if not apdu:
            return [], 0x67, 0x00

        if apdu[:4] == [0x00, 0xA4, 0x04, 0x00]:          # SELECT AID
            return self._chunked([0x6F, 0x00])

        if apdu[:2] == [0x00, 0xC0]:                       # GET RESPONSE
            if not self._pending:
                return [], 0x6D, 0x00
            body, self._pending = self._pending, []
            return self._chunked(body)

        if apdu[:4] == [0x00, 0xA4, 0x00, 0x00]:          # SELECT FILE
            fid = (apdu[5] << 8) | apdu[6]
            if fid in self.absent or fid not in self.files:
                return [], 0x6A, 0x82
            if fid in self.status:
                sw1, sw2 = self.status[fid]
                return [], sw1, sw2
            self.selected = fid
            return self._chunked(self._fci(fid))

        if apdu[:2] == [0x00, 0xB0]:                       # READ BINARY
            if self.selected is None:
                return [], 0x69, 0x86
            offset = ((apdu[2] & 0x7F) << 8) | apdu[3]
            wanted = apdu[4] if len(apdu) > 4 else 0
            data = self.files[self.selected][offset : offset + wanted]
            return self._chunked(list(data))

        return [], 0x6D, 0x00


class SimulatedConnection:
    """What ``reader.createConnection()`` returns; ``connect`` mimics a card in the reader."""

    def __init__(self, card: SimulatedCard | None, *, connect_error: Exception | None = None):
        self.card = card
        self.connect_error = connect_error
        self.connected = False
        self.disconnected = False

    def connect(self):
        if self.connect_error is not None:
            raise self.connect_error
        if self.card is None:
            raise RuntimeError("No card in the reader.")
        self.connected = True

    def disconnect(self):
        self.disconnected = True
        self.connected = False

    def transmit(self, apdu):
        if not self.connected or self.card is None:
            raise RuntimeError("not connected")
        return self.card.transmit(apdu)


class SimulatedReader:
    """A pyscard-style reader: a printable name and a factory for connections."""

    def __init__(self, name: str, card: SimulatedCard | None, *, connect_error=None):
        self.name = name
        self.card = card
        self.connect_error = connect_error
        self.connections: list[SimulatedConnection] = []

    def __str__(self) -> str:
        return self.name

    def createConnection(self) -> SimulatedConnection:
        conn = SimulatedConnection(self.card, connect_error=self.connect_error)
        self.connections.append(conn)
        return conn


def install_readers(monkeypatch, readers: list[SimulatedReader]) -> None:
    """Route ``smartcard.System.readers`` to the simulated set for one test.

    ``card_reader.list_readers`` imports the function lazily, so replacing the module attribute is
    enough and the real pyscard stack is never touched."""
    smartcard_system = __import__("smartcard.System", fromlist=["readers"])
    monkeypatch.setattr(smartcard_system, "readers", lambda: list(readers))
