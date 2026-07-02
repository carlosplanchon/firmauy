"""Unit tests for the cédula AIS reader's pure parsing/formatting/redaction logic.

These exercise only the pure functions (no PC/SC / pyscard, no card), in particular that --redact
hides *every* biographical field: an identity dump is all personal data, so a partial redaction
(e.g. leaking birth date or birthplace) would defeat the purpose."""

import base64
import hashlib
import json

import pytest

from firmauy.card_reader import (
    card_to_json_obj,
    format_card_human,
    parse_bio,
    parse_doc_number,
    parse_mrz,
    parse_photo,
    photo_to_json_obj,
    _fmt_date,
    _jpeg_dimensions,
)


def _tlv(tag: int, value: bytes) -> list:
    return [0x1F, tag, len(value)] + list(value)


# A fictitious card record (no real personal data).
_CARD = {
    "bio": {
        0x01: "PEREZ", 0x02: "GOMEZ", 0x03: "JUAN", 0x04: "URY",
        0x05: "01011970", 0x06: "MONTEVIDEO", 0x07: "12345678", 0x09: "01012099",
    },
    "doc_num": "00000TXXXX",
    "mrz": ["I<URY00000", "7001010<99", "PEREZ<GOMEZ"],
}

_SENSITIVE = ["PEREZ", "GOMEZ", "JUAN", "MONTEVIDEO", "12345678", "01011970",
              "01/01/1970", "00000TXXXX", "I<URY00000", "URY"]


# --- parsers ----------------------------------------------------------------

def test_parse_bio_reads_1f_tlv():
    data = _tlv(0x01, b"PEREZ") + _tlv(0x03, b"JUAN PABLO")
    assert parse_bio(data) == {0x01: "PEREZ", 0x03: "JUAN PABLO"}


def test_parse_bio_stops_at_non_1f():
    data = _tlv(0x01, b"PEREZ") + [0x00, 0x00]
    assert parse_bio(data) == {0x01: "PEREZ"}


def test_parse_doc_number():
    data = [0x5F, 0x01, 0x05] + list(b"12345")
    assert parse_doc_number(data) == "12345"
    assert parse_doc_number([0x00, 0x00]) is None
    assert parse_doc_number([0x5F, 0x01, 0x00]) is None   # empty value: absent, not ""


def test_parse_bio_drops_field_whose_length_runs_past_buffer():
    # A TLV declaring more bytes than remain must be dropped, not emitted as a truncated value.
    good = _tlv(0x01, b"PEREZ")
    truncated = [0x1F, 0x03, 0x20] + list(b"JUAN")   # claims 0x20 bytes, only 4 present
    assert parse_bio(good + truncated) == {0x01: "PEREZ"}   # 0x03 omitted, not "JUAN"


def test_parse_doc_number_none_when_length_runs_past_buffer():
    assert parse_doc_number([0x5F, 0x01, 0x20] + list(b"123")) is None   # claims 0x20, only 3


def test_parse_mrz_td1_three_lines():
    raw = ("A" * 30 + "B" * 30 + "C" * 30).encode("ascii")
    assert parse_mrz(list(raw)) == ["A" * 30, "B" * 30, "C" * 30]


def test_parse_mrz_wrapped_7f01():
    raw = ("A" * 30 + "B" * 30 + "C" * 30).encode("ascii")
    data = [0x7F, 0x01, len(raw)] + list(raw)
    assert parse_mrz(data) == ["A" * 30, "B" * 30, "C" * 30]


def test_fmt_date():
    assert _fmt_date("01011970") == "01/01/1970"


def test_fmt_date_malformed_length_returned_as_is():
    assert _fmt_date("5") == "5"                    # not "5//"
    assert _fmt_date("010119701") == "010119701"    # 9 chars: left untouched


# --- redaction (the regression guard) ---------------------------------------

def test_json_obj_full_then_redacted():
    full = card_to_json_obj(_CARD, redact=False)
    assert full["first_lastname"] == "PEREZ"
    assert full["birth_date"] == "01/01/1970"      # date formatted
    assert full["birthplace"] == "MONTEVIDEO"
    assert full["document_number"] == "00000TXXXX"
    assert full["mrz"] == _CARD["mrz"]

    red = card_to_json_obj(_CARD, redact=True)
    # Every biographical field, the document number and the MRZ are hidden.
    for key in ("first_lastname", "second_lastname", "given_names", "nationality",
                "birth_date", "birthplace", "id_number", "expiry_date", "document_number"):
        assert red[key] == "[REDACTED]", key
    assert red["mrz"] == "[REDACTED]"
    # No sensitive value survives anywhere in the serialised output.
    blob = json.dumps(red, ensure_ascii=False)
    for needle in _SENSITIVE:
        assert needle not in blob, needle


def test_human_output_redacted_leaks_nothing():
    full = format_card_human(_CARD, redact=False)
    assert "PEREZ" in full and "MONTEVIDEO" in full        # shows data without --redact
    assert "CÉDULA DE IDENTIDAD - URUGUAY" in full         # header, no em dash

    red = format_card_human(_CARD, redact=True)
    for needle in _SENSITIVE:
        assert needle not in red, needle
    assert "[REDACTED]" in red


def test_absent_fields_are_omitted():
    card = {"bio": {0x01: "PEREZ"}, "doc_num": None, "mrz": None}
    out = card_to_json_obj(card, redact=False)
    assert out == {"first_lastname": "PEREZ"}   # missing fields/doc/mrz omitted


# --- photo (file 7004) parsing ----------------------------------------------

def _ber_tlv(tag: bytes, value: bytes) -> list:
    """Wrap value in BER-TLV with `tag`, using long-form length above 127 bytes (as the card does)."""
    n = len(value)
    if n < 0x80:
        length = bytes([n])
    elif n <= 0xFFFF:
        length = bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    else:
        length = bytes([0x83, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])
    return list(tag + length + value)


# A synthetic JPEG: SOI ... EOI, >127 bytes so the wrapper uses a long-form length like the card.
_JPEG = b"\xff\xd8\xff" + b"\x00" * 200 + b"\xff\xd9"


def test_parse_photo_tlv_long_length():
    data = _ber_tlv(b"\x3f\x01", _JPEG)        # 3F 01 82 LL LL <jpeg>, exactly like file 7004
    assert data[2] == 0x82                     # long-form length, as on the real card
    assert parse_photo(data) == _JPEG


def test_parse_photo_tlv_short_length():
    small = b"\xff\xd8\xff\x00\xff\xd9"        # < 128 bytes -> short-form length
    data = _ber_tlv(b"\x3f\x01", small)
    assert data[2] < 0x80
    assert parse_photo(data) == small


def test_parse_photo_fallback_locates_soi():
    # An unexpected wrapper: the JPEG is still recovered via its SOI marker.
    data = list(b"\x99\x88\x77" + _JPEG)
    assert parse_photo(data) == _JPEG


def test_parse_photo_fallback_trims_ef_padding_at_eoi():
    # Unexpected wrapper AND trailing EF allocation padding: the returned bytes must stop at the
    # EOI marker, so fetch-photo's reported size and SHA-256 cover only the image itself.
    data = list(b"\x99\x88" + _JPEG + b"\x00" * 32)
    assert parse_photo(data) == _JPEG


def test_parse_photo_declared_length_past_buffer_falls_back_to_soi():
    # A 3F01 wrapper declaring far more bytes than present is not trusted: the SOI/EOI fallback
    # recovers exactly the image instead of returning a silently truncated slice.
    data = list(b"\x3f\x01\x81\xff" + _JPEG)   # claims 0xFF bytes, fewer present
    assert parse_photo(data) == _JPEG


def test_parse_photo_none_without_jpeg():
    assert parse_photo(list(b"\x3f\x01\x05hello")) is None


class _FakeCard:
    """Minimal PC/SC card serving one file via SELECT AID / SELECT FILE / READ BINARY, enough to
    exercise the APDU read path (select_applet -> select_file -> read_file)."""

    def __init__(self, file_bytes: bytes):
        self.file = file_bytes

    def transmit(self, apdu):
        if apdu[:4] == [0x00, 0xA4, 0x04, 0x00]:          # SELECT AID
            return [], 0x90, 0x00
        if apdu[:4] == [0x00, 0xA4, 0x00, 0x00]:          # SELECT FILE -> FCI with tag 81 (size)
            size = len(self.file)
            return [0x6F, 0x04, 0x81, 0x02, (size >> 8) & 0xFF, size & 0xFF], 0x90, 0x00
        if apdu[:2] == [0x00, 0xB0]:                       # READ BINARY
            offset = ((apdu[2] & 0x7F) << 8) | apdu[3]
            return list(self.file[offset:offset + apdu[4]]), 0x90, 0x00
        raise AssertionError(f"unexpected APDU: {apdu}")


def test_read_photo_end_to_end_with_fake_card():
    from firmauy.card_reader import read_photo

    card = _FakeCard(bytes(_ber_tlv(b"\x3f\x01", _JPEG)))   # file 7004 as on the card
    assert read_photo(card) == _JPEG                        # full path: applet -> file -> JPEG


def test_fci_size_ignores_81_02_inside_another_tlv_value():
    from firmauy.card_reader import _fci_file_size

    # 6F 08 | 83 02 81 02 (a sub-TLV whose VALUE bytes spell 81 02) | 81 02 00 40 (real size 0x40).
    # A raw byte scan would match inside the first sub-TLV and report 0x8102; the structural walk
    # must skip it and land on the real size tag.
    fci = [0x6F, 0x08, 0x83, 0x02, 0x81, 0x02, 0x81, 0x02, 0x00, 0x40]
    assert _fci_file_size(fci) == 0x40


class _ChunkedSelectCard(_FakeCard):
    """SELECT AID answers 61 xx (FCI available via GET RESPONSE), as a T=0 stack may."""

    def transmit(self, apdu):
        if apdu[:4] == [0x00, 0xA4, 0x04, 0x00]:          # SELECT AID -> more data available
            return [], 0x61, 0x02
        if apdu[:2] == [0x00, 0xC0]:                       # GET RESPONSE -> the FCI
            return [0x6F, 0x00], 0x90, 0x00
        return super().transmit(apdu)


def test_select_applet_chains_61xx_get_response():
    from firmauy.card_reader import select_applet

    select_applet(_ChunkedSelectCard(b""))   # must not raise "SELECT AID failed: 61 02"


class _NoOptionalFilesCard(_FakeCard):
    """Serves file 7002 but reports 6A 82 (file not found) for every other SELECT FILE."""

    def transmit(self, apdu):
        if apdu[:4] == [0x00, 0xA4, 0x00, 0x00] and apdu[5:7] != [0x70, 0x02]:
            return [], 0x6A, 0x82
        return super().transmit(apdu)


def test_read_card_degrades_only_on_genuinely_absent_files():
    from firmauy.card_reader import read_card

    card = read_card(_NoOptionalFilesCard(bytes(_tlv(0x01, b"PEREZ"))))
    assert card["bio"] == {0x01: "PEREZ"}
    assert card["doc_num"] is None and card["mrz"] is None


class _FailingOptionalCard(_FakeCard):
    """SELECT of file 7001 fails with 69 82 (security status): a real failure, not absence."""

    def transmit(self, apdu):
        if apdu[:4] == [0x00, 0xA4, 0x00, 0x00] and apdu[5:7] == [0x70, 0x01]:
            return [], 0x69, 0x82
        return super().transmit(apdu)


def test_read_card_propagates_non_absent_failures_on_optional_files():
    # A transport-level or security failure on an optional file must surface, not be silently
    # degraded to None as if the card simply lacked the file.
    from firmauy.card_reader import read_card

    with pytest.raises(RuntimeError, match="SELECT 7001"):
        read_card(_FailingOptionalCard(bytes(_tlv(0x01, b"PEREZ"))))


def test_read_file_rejects_offsets_past_15_bit_limit():
    from firmauy.card_reader import read_file

    # 33 KB declared size: plain READ BINARY cannot address past offset 7FFF, so the read must
    # fail loudly instead of wrapping the offset and returning corrupt data.
    with pytest.raises(RuntimeError, match="7FFF"):
        read_file(_FakeCard(bytes(0x8100)), 0x7004)


def test_list_readers_wraps_pcsc_daemon_failure(monkeypatch):
    smartcard_system = pytest.importorskip("smartcard.System")
    from firmauy.card_reader import list_readers

    def boom():
        raise Exception("Failure to establish context: 0x8010001D")

    monkeypatch.setattr(smartcard_system, "readers", boom)
    with pytest.raises(RuntimeError, match="pcscd"):
        list_readers()


class _StuckCard:
    """A reader that reports a non-empty file size but keeps returning 0 bytes with a 90 00 success
    status on READ BINARY. Without a no-progress guard this loops forever (offset never advances)."""

    def __init__(self):
        self.reads = 0

    def transmit(self, apdu):
        if apdu[:4] == [0x00, 0xA4, 0x00, 0x00]:          # SELECT FILE -> FCI with file size 16
            return [0x6F, 0x04, 0x81, 0x02, 0x00, 0x10], 0x90, 0x00
        if apdu[:2] == [0x00, 0xB0]:                       # READ BINARY -> success but no bytes
            self.reads += 1
            assert self.reads <= 2, "read_file looped on an empty successful READ BINARY"
            return [], 0x90, 0x00
        raise AssertionError(f"unexpected APDU: {apdu}")


def test_read_file_bails_out_on_zero_byte_success_instead_of_looping():
    from firmauy.card_reader import read_file

    with pytest.raises(RuntimeError, match="no data"):
        read_file(_StuckCard(), 0x7002)


# --- photo JSON record (dimensions, metadata, redaction) --------------------

def _jpeg_with_dims(width: int, height: int) -> bytes:
    """A minimal JPEG carrying a real SOF0 frame header, so dimensions are parseable."""
    soi = b"\xff\xd8"
    app0 = b"\xff\xe0\x00\x10" + b"JFIF\x00" + b"\x00" * 9          # APP0, length 0x10 (skipped)
    sof0 = (b"\xff\xc0\x00\x11\x08"                                 # SOF0, length 0x11, precision 8
            + bytes([height >> 8, height & 0xFF])
            + bytes([width >> 8, width & 0xFF])
            + b"\x03" + b"\x00" * 9)                                # 3 components
    return soi + app0 + sof0 + b"\xff\xd9"


def test_jpeg_dimensions_reads_sof_past_other_segments():
    assert _jpeg_dimensions(_jpeg_with_dims(240, 320)) == (240, 320)


def test_jpeg_dimensions_none_when_absent():
    assert _jpeg_dimensions(b"\xff\xd8\xff\xd9") is None     # SOI + EOI only, no frame
    assert _jpeg_dimensions(b"not a jpeg at all") is None


def test_photo_to_json_obj_full_round_trips_image():
    jpeg = _jpeg_with_dims(240, 320)
    obj = photo_to_json_obj(jpeg, redact=False)
    assert obj["format"] == "jpeg" and obj["mime"] == "image/jpeg"
    assert obj["width"] == 240 and obj["height"] == 320
    assert obj["bytes"] == len(jpeg)
    assert obj["sha256"] == hashlib.sha256(jpeg).hexdigest()
    assert base64.b64decode(obj["base64"]) == jpeg          # decodes back to the exact image
    assert "redacted" not in obj                            # the flag is added by the CLI, not here


def test_photo_to_json_obj_redacted_drops_image_and_correlators():
    jpeg = _jpeg_with_dims(240, 320)
    obj = photo_to_json_obj(jpeg, redact=True)
    # The image and every per-card fingerprint are dropped entirely (omitted, not stringified), so the
    # record stays well-typed. Only the non-identifying shape (format, mime, dimensions) survives.
    assert obj == {"format": "jpeg", "mime": "image/jpeg", "width": 240, "height": 320}
    blob = json.dumps(obj)
    assert base64.b64encode(jpeg).decode() not in blob      # the image never appears, in any form


# --- id_number check-digit integration in card_to_json_obj ------------------

def test_card_json_includes_id_number_check_digit_valid():
    card = {"bio": {0x07: "12345672"}, "doc_num": None, "mrz": None}   # valid check digit
    full = card_to_json_obj(card, redact=False)
    assert full["id_number"] == "12345672"
    assert full["id_number_check_digit_valid"] is True
    red = card_to_json_obj(card, redact=True)
    assert red["id_number"] == "[REDACTED]"
    assert red["id_number_check_digit_valid"] is True      # boolean kept under redact (non-identifying)


def test_card_json_id_number_check_digit_invalid():
    card = {"bio": {0x07: "12345678"}, "doc_num": None, "mrz": None}   # wrong check digit
    assert card_to_json_obj(card, redact=False)["id_number_check_digit_valid"] is False


def test_card_json_omits_check_digit_when_unparseable():
    card = {"bio": {0x07: "not a number"}, "doc_num": None, "mrz": None}
    out = card_to_json_obj(card, redact=False)
    assert "id_number_check_digit_valid" not in out        # unparseable number -> flag omitted
