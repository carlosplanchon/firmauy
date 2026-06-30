# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""PC/SC reader access for the Uruguayan cédula AIS applet (biographical data).

Reads the biographical fields, document number and MRZ from the card via
raw ISO 7816-4 APDUs over a pyscard PC/SC connection. No PIN is required:
the AIS applet data is public. Do not call while a PKCS#11 session is open
on the same card; both paths go through pcscd and may conflict.

The AID, file identifiers (7001 document number, 7002 biographical data, 700B MRZ), APDUs and TLV
layout follow AGESIC's public technical documentation for the ID Uruguay card (IAS CLASSIC; ISO/IEC
7816, ICAO 9303), not any reverse engineering of the middleware:
https://www.gub.uy/agencia-gobierno-electronico-sociedad-informacion-conocimiento/comunicacion/publicaciones/documentacion-tecnica-id-uruguay
"""

import base64
import hashlib
from typing import Optional

AIS_AID = [0xA0, 0x00, 0x00, 0x00, 0x18, 0x40, 0x00, 0x00, 0x01, 0x63, 0x42, 0x00]

# tag -> (display_label, is_date, json_key)
# Every field here is the cardholder's personal data, so --redact hides them all (a partial
# redaction of an identity dump, e.g. keeping birth date or birthplace, defeats the purpose).
BIO_FIELDS = {
    0x01: ("Primer apellido",      False, "first_lastname"),
    0x02: ("Segundo apellido",     False, "second_lastname"),
    0x03: ("Nombre(s)",            False, "given_names"),
    0x04: ("Nacionalidad",         False, "nationality"),
    0x05: ("Fecha de nacimiento",  True,  "birth_date"),
    0x06: ("Lugar de nacimiento",  False, "birthplace"),
    0x07: ("Número de cédula",     False, "id_number"),
    0x09: ("Fecha de vencimiento", True,  "expiry_date"),
}


# ── APDU helpers ──────────────────────────────────────────────────────────────

def select_applet(conn) -> None:
    apdu = [0x00, 0xA4, 0x04, 0x00, len(AIS_AID)] + AIS_AID
    _, sw1, sw2 = conn.transmit(apdu)
    if (sw1, sw2) != (0x90, 0x00):
        raise RuntimeError(f"SELECT AID failed: {sw1:02X} {sw2:02X}")


def _fci_file_size(fci: list) -> int:
    for i in range(len(fci) - 3):
        if fci[i] == 0x81 and fci[i + 1] == 0x02:
            return (fci[i + 2] << 8) | fci[i + 3]
    raise RuntimeError(f"Tag 81 not found in FCI: {bytes(fci).hex()}")


def select_file(conn, fid: int) -> list:
    apdu = [0x00, 0xA4, 0x00, 0x00, 0x02, fid >> 8, fid & 0xFF, 0x00]
    data, sw1, sw2 = conn.transmit(apdu)
    if sw1 == 0x61:
        data, sw1, sw2 = conn.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
    if (sw1, sw2) != (0x90, 0x00):
        raise RuntimeError(f"SELECT {fid:04X} failed: {sw1:02X} {sw2:02X}")
    return data


def read_file(conn, fid: int) -> list:
    fci = select_file(conn, fid)
    size = _fci_file_size(fci)
    buf, offset = [], 0
    while offset < size:
        chunk = min(size - offset, 0xF8)
        p1, p2 = (offset >> 8) & 0x7F, offset & 0xFF
        data, sw1, sw2 = conn.transmit([0x00, 0xB0, p1, p2, chunk])
        if (sw1, sw2) != (0x90, 0x00):
            raise RuntimeError(f"READ BINARY @{offset} failed: {sw1:02X} {sw2:02X}")
        buf.extend(data)
        offset += len(data)
    return buf


# ── Parsers ───────────────────────────────────────────────────────────────────

def parse_bio(data: list) -> dict:
    """Parse 1F-prefixed TLV biographical data (file 7002)."""
    fields, i = {}, 0
    while i + 2 < len(data):
        if data[i] != 0x1F:
            break
        tag, length = data[i + 1], data[i + 2]
        if length > 0:
            raw = bytes(data[i + 3: i + 3 + length])
            try:
                fields[tag] = raw.decode("utf-8")
            except UnicodeDecodeError:
                fields[tag] = raw.hex()
        i += 3 + length
    return fields


def parse_doc_number(data: list) -> Optional[str]:
    """Extract document number from file 7001 (tag 5F01)."""
    if len(data) >= 4 and data[0] == 0x5F and data[1] == 0x01:
        length = data[2]
        return bytes(data[3: 3 + length]).decode("ascii", errors="replace").strip()
    return None


def parse_mrz(data: list) -> Optional[list]:
    """Return MRZ lines from file 700B: TD1 (3×30) or TD3 (2×44)."""
    if len(data) >= 3 and data[0] == 0x7F and data[1] == 0x01:
        length = data[2]
        raw_bytes = data[3: 3 + length]
    else:
        raw_bytes = data
    raw = bytes(raw_bytes).decode("ascii", errors="replace")
    n = len(raw)
    if n >= 90:
        return [raw[0:30], raw[30:60], raw[60:90]]
    if n >= 88:
        return [raw[0:44], raw[44:88]]
    return [raw] if raw.strip() else None


def parse_photo(data: list) -> Optional[bytes]:
    """Extract the JPEG image from file 7004.

    The file is BER-TLV: tag 3F01, a length (short form, or long form 81/82/83), then the JPEG
    value. If the wrapper differs, fall back to locating the JPEG SOI marker (FF D8 FF) directly.
    Returns the JPEG bytes, or None if no JPEG is present."""
    b = bytes(data)
    if b[:2] == b"\x3f\x01" and len(b) > 2:
        first, i, length = b[2], 3, None
        if first < 0x80:
            length = first
        elif first in (0x81, 0x82, 0x83):
            nbytes = first & 0x0F
            length = int.from_bytes(b[3:3 + nbytes], "big")
            i = 3 + nbytes
        if length is not None:
            value = b[i:i + length]
            if value[:3] == b"\xff\xd8\xff":
                return value
    # Fallback: an unexpected wrapper -- locate the JPEG by its start-of-image marker.
    j = b.find(b"\xff\xd8\xff")
    return b[j:] if j != -1 else None


def _jpeg_dimensions(jpeg: bytes) -> Optional[tuple]:
    """Return (width, height) from the JPEG's Start-Of-Frame marker, or None.

    Pure Python, no image library: walk the JPEG segments until an SOFn marker (FF C0..CF, excluding
    the non-SOF markers DHT/JPG/DAC) and read the 16-bit height and width it carries."""
    n = len(jpeg)
    if n < 4 or jpeg[0] != 0xFF or jpeg[1] != 0xD8:        # must start with SOI
        return None
    i = 2
    while i + 9 <= n:
        if jpeg[i] != 0xFF:
            i += 1
            continue
        marker = jpeg[i + 1]
        if marker == 0xD9 or 0xD0 <= marker <= 0xD7:       # EOI / RSTn: no length field
            i += 2
            continue
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):   # SOFn (not DHT/JPG/DAC)
            height = (jpeg[i + 5] << 8) | jpeg[i + 6]
            width = (jpeg[i + 7] << 8) | jpeg[i + 8]
            return width, height
        seg_len = (jpeg[i + 2] << 8) | jpeg[i + 3]          # other segments: skip by length
        if seg_len < 2:
            break
        i += 2 + seg_len
    return None


# ── High-level read ───────────────────────────────────────────────────────────

def read_card(conn) -> dict:
    """Read all available data from the card. Returns {"bio", "doc_num", "mrz"}."""
    select_applet(conn)
    bio = parse_bio(read_file(conn, 0x7002))
    doc_num = None
    try:
        doc_num = parse_doc_number(read_file(conn, 0x7001))
    except RuntimeError:
        pass
    mrz = None
    try:
        mrz = parse_mrz(read_file(conn, 0x700B))
    except RuntimeError:
        pass
    return {"bio": bio, "doc_num": doc_num, "mrz": mrz}


def read_photo(conn) -> bytes:
    """Select the applet and return the cardholder's JPEG photo (file 7004).

    Raises RuntimeError if the file holds no JPEG. No PIN is required; the photo is public."""
    select_applet(conn)
    photo = parse_photo(read_file(conn, 0x7004))
    if photo is None:
        raise RuntimeError("No JPEG image found in file 7004.")
    return photo


# ── Reader discovery ──────────────────────────────────────────────────────────

def list_readers() -> list:
    """Return all available PC/SC readers.

    pyscard is imported lazily so that signing/verification never depend on the PC/SC stack being
    loadable; only this reader path does."""
    try:
        from smartcard.System import readers as _readers
    except ImportError as exc:
        raise RuntimeError(
            "PC/SC reader support could not be loaded. Install the smart-card stack and start "
            "pcscd (Arch: sudo pacman -S pcsclite ccid; sudo systemctl enable --now pcscd)."
        ) from exc
    return list(_readers())


def open_reader(reader_name: Optional[str] = None):
    """Open a card connection, auto-detecting the reader when only one is present.

    Returns a connected pyscard CardConnection ready for APDU exchange.
    Raises RuntimeError with a user-friendly message on any failure.
    """
    available = list_readers()
    if not available:
        raise RuntimeError(
            "No PC/SC readers found. Is pcscd running and a reader connected?"
        )
    if reader_name is not None:
        matches = [r for r in available if str(r) == reader_name]
        if not matches:
            names = "\n".join(f"  {r}" for r in available)
            raise RuntimeError(
                f"Reader '{reader_name}' not found. Available readers:\n{names}"
            )
        reader = matches[0]
    elif len(available) == 1:
        reader = available[0]
    else:
        names = "\n".join(f"  {r}" for r in available)
        raise RuntimeError(
            f"Multiple PC/SC readers found. Use --reader to select one:\n{names}"
        )
    conn = reader.createConnection()
    try:
        conn.connect()
    except Exception as exc:
        raise RuntimeError(
            f"No card found in reader \"{reader}\". "
            "Insert the cédula and try again."
        ) from exc
    return conn


# ── Output helpers ────────────────────────────────────────────────────────────

_W = 56


def _border(left: str, fill: str, right: str) -> str:
    return left + fill * _W + right


def _row(label: str, value: str, label_w: int = 24) -> str:
    val_w = _W - 2 - label_w - 2
    return f"║  {label:<{label_w}}  {str(value)[:val_w]:<{val_w}}║"


def _center(text: str) -> str:
    return f"║{text:^{_W}}║"


def _fmt_date(s: str) -> str:
    return f"{s[0:2]}/{s[2:4]}/{s[4:8]}"


def format_card_human(card: dict, redact: bool = False) -> str:
    """Render card data as a bordered text table."""
    bio     = card["bio"]
    doc_num = card["doc_num"]
    mrz     = card["mrz"]
    lines = [
        _border("╔", "═", "╗"),
        _center(" CÉDULA DE IDENTIDAD - URUGUAY "),
        _border("╠", "═", "╣"),
    ]
    if doc_num is not None:
        lines.append(_row("Número de documento", "[REDACTED]" if redact else doc_num))
        lines.append("╟" + "─" * _W + "╢")
    for tag, (label, is_date, _) in BIO_FIELDS.items():
        val = bio.get(tag)
        if val is None:
            continue
        display = "[REDACTED]" if redact else (_fmt_date(val) if is_date else val)
        lines.append(_row(label, display))
    if mrz is not None:
        lines.extend([
            _border("╠", "═", "╣"),
            _center(" MRZ "),
            _border("╠", "═", "╣"),
        ])
        if redact:
            lines.append(f"║  {'[REDACTED]':<{_W - 2}}║")
        else:
            for line in mrz:
                lines.append(f"║  {line:<{_W - 2}}║")
    lines.append(_border("╚", "═", "╝"))
    return "\n".join(lines)


def card_to_json_obj(card: dict, redact: bool = False) -> dict:
    """Build the JSON-serialisable dict for a card read result."""
    bio = card["bio"]
    out: dict = {}
    for tag, (_, is_date, key) in BIO_FIELDS.items():
        val = bio.get(tag)
        if val is None:
            continue
        if redact:
            out[key] = "[REDACTED]"
        elif is_date:
            out[key] = _fmt_date(val)
        else:
            out[key] = val
    if card["doc_num"] is not None:
        out["document_number"] = "[REDACTED]" if redact else card["doc_num"]
    if card["mrz"] is not None:
        out["mrz"] = "[REDACTED]" if redact else card["mrz"]
    return out


def photo_to_json_obj(photo: bytes, redact: bool = False) -> dict:
    """Build the JSON-serialisable record for the cardholder's photo.

    The full form carries the image (base64) plus identifying metadata (byte count, SHA-256). With
    ``redact`` the image and every value that could fingerprint or correlate the cardholder are
    dropped (the SHA-256 of a face photo is a stable per-card identifier, and the byte count leaks
    the same way), leaving only the non-identifying shape of the file: format, MIME type and pixel
    dimensions, which are the same for every card."""
    out: dict = {"format": "jpeg", "mime": "image/jpeg"}
    dims = _jpeg_dimensions(photo)
    if dims is not None:
        out["width"], out["height"] = dims
    if redact:
        out["base64"] = "[REDACTED]"
        return out
    out["bytes"] = len(photo)
    out["sha256"] = hashlib.sha256(photo).hexdigest()
    out["base64"] = base64.b64encode(photo).decode("ascii")
    return out
