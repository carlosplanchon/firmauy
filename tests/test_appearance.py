import re
from pathlib import Path

import pytest
from PIL import Image

from firmauy.signing import _box_in_corner, _page_media_box
from firmauy.appearance import (
    _sized_for_box,
    check_stamp_image,
    ensure_output_parent,
    make_appearance_pdf,
    split_signer_name,
    wrap_line,
)
from firmauy.constants import (ImageMode, STAMP_FONT_NAME, STAMP_FONT_SIZE,
                               STAMP_LEADING, STAMP_TEXT_Y, STAMP_IMAGE_DPI,
                               StampCorner, StampFields,
                               APPEARANCE_HEIGHT, APPEARANCE_WIDTH,
                               DEFAULT_X1, DEFAULT_X2, DEFAULT_Y1, DEFAULT_Y2)


class TestWrapLine:
    def test_short_text_single_line(self):
        lines = wrap_line("Hola", STAMP_FONT_NAME, STAMP_FONT_SIZE, max_width=200)
        assert lines == ["Hola"]

    def test_long_text_multiple_lines(self):
        text = " ".join(["Palabra"] * 20)
        lines = wrap_line(text, STAMP_FONT_NAME, STAMP_FONT_SIZE, max_width=100)
        assert len(lines) > 1

    def test_single_oversized_word_not_broken(self):
        # Una sola palabra que excede max_width no se rompe
        lines = wrap_line("Superlargapalabra", STAMP_FONT_NAME, STAMP_FONT_SIZE, max_width=1)
        assert lines == ["Superlargapalabra"]

    def test_empty_string_returns_empty(self):
        assert wrap_line("", STAMP_FONT_NAME, STAMP_FONT_SIZE, max_width=200) == []


class TestSplitSignerName:
    def test_short_name_single_line(self):
        lines = split_signer_name("Ana Gomez")
        assert len(lines) == 1
        assert lines[0].startswith("Firmado por: ")
        assert "Ana Gomez" in lines[0]

    def test_long_name_splits_into_two_lines(self):
        # Un nombre suficientemente largo para no entrar en una sola línea
        long_name = "Juan Domingo Perez Hernandez de los Santos Caballero"
        lines = split_signer_name(long_name)
        assert len(lines) >= 2
        assert lines[0].startswith("Firmado por: ")

    def test_prefix_only_on_first_line(self):
        long_name = "Juan Domingo Perez Hernandez de los Santos Caballero"
        lines = split_signer_name(long_name)
        for line in lines[1:]:
            assert not line.startswith("Firmado por:")

    def test_narrower_max_width_wraps_more(self):
        name = "Juan Domingo Perez Hernandez de los Santos"
        assert len(split_signer_name(name, max_width=60)) >= len(split_signer_name(name, max_width=400))


@pytest.fixture
def sample_png(tmp_path):
    p = tmp_path / "sig.png"
    Image.new("RGBA", (120, 48), (10, 30, 200, 160)).save(p)  # semi-transparent
    return p


class TestImageAppearance:
    @pytest.mark.parametrize("mode", [ImageMode.background, ImageMode.side, ImageMode.only])
    def test_each_mode_produces_valid_pdf(self, tmp_path, sample_png, mode):
        out = tmp_path / f"{mode.value}.pdf"
        make_appearance_pdf(
            str(out), signer="CARLOS ANDRÉS PLANCHÓN PRESTES", cert_serial="78191ABC",
            ts="29/06/2026 12:00", issuer="Autoridad Certificadora del Ministerio del Interior",
            image_path=str(sample_png), image_mode=mode,
        )
        assert out.read_bytes()[:4] == b"%PDF"

    def test_embedding_an_image_grows_the_file(self, tmp_path, sample_png):
        base = tmp_path / "base.pdf"
        make_appearance_pdf(str(base), signer="X", cert_serial="1", ts="t", issuer="i")
        withimg = tmp_path / "img.pdf"
        make_appearance_pdf(str(withimg), signer="X", cert_serial="1", ts="t", issuer="i",
                            image_path=str(sample_png), image_mode=ImageMode.background)
        assert withimg.stat().st_size > base.stat().st_size

    def test_invalid_image_raises_clear_error(self, tmp_path):
        bad = tmp_path / "bad.png"
        bad.write_bytes(b"not an image")
        with pytest.raises(RuntimeError, match="could not load image"):
            make_appearance_pdf(str(tmp_path / "x.pdf"), signer="X", cert_serial="1", ts="t",
                                issuer="i", image_path=str(bad), image_mode=ImageMode.only)

    def test_faded_image_is_a_pale_watermark(self, sample_png):
        from PIL import ImageStat

        from firmauy.appearance import _faded_image, _sized_for_box

        # It takes the opened image rather than a path now: the shrink to the box has to happen
        # before the fade, and doing both from a path would decode the file twice.
        faded = _faded_image(
            _sized_for_box(str(sample_png), APPEARANCE_WIDTH, APPEARANCE_HEIGHT), 0.2)
        mean = sum(ImageStat.Stat(faded).mean) / 3  # overall brightness across R/G/B
        assert mean > 200  # blended ~80% toward white -> a faint watermark (renderer-independent)


class TestEnsureOutputParent:
    def test_creates_missing_directory(self, tmp_path):
        target = tmp_path / "sub" / "dir" / "file.pdf"
        ensure_output_parent(target)
        assert target.parent.exists()

    def test_existing_directory_no_error(self, tmp_path):
        ensure_output_parent(tmp_path / "file.pdf")  # tmp_path ya existe
        assert tmp_path.exists()


class TestMakeAppearancePdf:
    def test_creates_file(self, tmp_path):
        out = str(tmp_path / "appearance.pdf")
        make_appearance_pdf(
            out,
            signer="Juan Test",
            cert_serial="ABCDEF1234",
            ts="20/03/2026 10:00",
            issuer="Ministerio del Interior",
        )
        assert Path(out).exists()
        assert Path(out).stat().st_size > 0

    def test_output_is_pdf(self, tmp_path):
        out = str(tmp_path / "appearance.pdf")
        make_appearance_pdf(
            out,
            signer="Juan Test",
            cert_serial="ABCDEF1234",
            ts="20/03/2026 10:00",
            issuer="Ministerio del Interior",
        )
        with open(out, "rb") as f:
            header = f.read(4)
        assert header == b"%PDF"


class TestStampFields:
    """Which of the five lines the stamp prints, and where the block sits when some are off.

    The bytes are searched directly because make_appearance_pdf sets setPageCompression(0), so
    the text and its positioning operators are literal in the file. That is what makes it possible
    to assert the default did not move by a single point, which is the thing that must not change:
    every stamp firmauy has ever drawn used these coordinates.
    """

    ARGS = dict(signer="PEREZ PEREZ, JUAN", cert_serial="0123ABCD",
                ts="06/08/2026 10:30", issuer="AC RAIZ NACIONAL")

    def _render(self, tmp_path, name, **kw) -> bytes:
        out = str(tmp_path / f"{name}.pdf")
        make_appearance_pdf(out, **self.ARGS, **kw)
        return Path(out).read_bytes()

    def _first_baseline(self, data: bytes) -> float:
        match = re.search(rb"1 0 0 1 [\d.]+ ([\d.]+) Tm", data)
        assert match, "no text was drawn at all"
        return float(match.group(1))

    def test_every_line_is_printed_by_default(self, tmp_path):
        data = self._render(tmp_path, "full")
        for needle in (b"Firma electr", b"Firmado por", b"Documento", b"Fecha:", b"AC RAIZ"):
            assert needle in data, f"{needle!r} is missing from the default stamp"

    @pytest.mark.parametrize("field,gone,kept", [
        ("title", b"Firma electr", b"Firmado por"),
        ("signer", b"Firmado por", b"Documento"),
        ("document", b"Documento", b"Fecha:"),
        ("date", b"Fecha:", b"AC RAIZ"),
        ("issuer", b"AC RAIZ", b"Firmado por"),
    ])
    def test_turning_one_line_off_removes_that_one_and_no_other(self, tmp_path, field, gone, kept):
        data = self._render(tmp_path, field, fields=StampFields(**{field: False}))
        assert gone not in data
        assert kept in data

    def test_turning_everything_off_draws_no_text_at_all(self, tmp_path):
        data = self._render(tmp_path, "none",
                            fields=StampFields(False, False, False, False, False))
        for needle in (b"Firma electr", b"Firmado por", b"Documento", b"Fecha:", b"AC RAIZ"):
            assert needle not in data

    def test_the_default_block_still_starts_exactly_where_it_always_did(self, tmp_path):
        """The regression this whole feature could have caused. Any change here silently moves
        the stamp on every document signed with defaults."""
        assert self._first_baseline(self._render(tmp_path, "default")) == STAMP_TEXT_Y

    def test_a_shorter_block_slides_down_by_half_of_what_was_removed(self, tmp_path):
        """Otherwise a one-line stamp hangs from the top of a 70pt box with all the air below it."""
        one_off = self._render(tmp_path, "one_off", fields=StampFields(date=False))
        assert self._first_baseline(one_off) == STAMP_TEXT_Y - STAMP_LEADING / 2

        only_signer = self._render(tmp_path, "only_signer",
                                   fields=StampFields(True, True, False, False, False))
        assert self._first_baseline(only_signer) == STAMP_TEXT_Y - 3 * STAMP_LEADING / 2

    def test_a_block_longer_than_five_lines_is_never_pushed_up(self, tmp_path):
        """A name or issuer long enough to wrap already produces more than five lines. Moving
        those up to "center" them would push the first line out through the top of the box."""
        out = str(tmp_path / "long.pdf")
        make_appearance_pdf(out, signer=" ".join(["APELLIDO"] * 8), cert_serial="0123ABCD",
                            ts="06/08/2026 10:30", issuer=" ".join(["AUTORIDAD"] * 6))
        assert self._first_baseline(Path(out).read_bytes()) == STAMP_TEXT_Y


class TestStampCorner:
    """Placing the box against a corner of the page, resolved from that page's real size.

    The reason this lives in the core and not in a caller: a corner cannot be turned into
    coordinates without the page size, and only the code holding the open PDF knows it. A box
    computed for A4 and applied to an A5 lands 156 points off the paper, which the last test here
    states as a number rather than as a worry.
    """

    A4 = (0.0, 0.0, 595.28, 841.89)
    A5 = (0.0, 0.0, 419.53, 595.28)
    BOX = (APPEARANCE_WIDTH, APPEARANCE_HEIGHT)     # 205 x 70, the default stamp

    @pytest.mark.parametrize("page", [A4, A5])
    @pytest.mark.parametrize("corner", list(StampCorner))
    def test_every_corner_of_every_page_size_lands_on_the_page(self, page, corner):
        left, bottom, right, top = page
        x1, y1, x2, y2 = _box_in_corner(page, corner, 20.0, *self.BOX)

        assert left <= x1 and bottom <= y1
        assert x2 <= right and y2 <= top
        assert (round(x2 - x1), round(y2 - y1)) == self.BOX      # the size is never changed

    def test_the_default_corner_reproduces_the_coordinates_it_replaces(self):
        """bottom-left with the default margin has to be the box firmauy has always drawn, or
        asking for the corner it already used would move every existing stamp."""
        assert _box_in_corner(self.A4, StampCorner.bottom_left, 20.0, *self.BOX) == (
            DEFAULT_X1, DEFAULT_Y1, DEFAULT_X2, DEFAULT_Y2)

    def test_each_corner_is_the_corner_it_says(self):
        left, bottom, right, top = self.A4
        width, height = self.BOX

        assert _box_in_corner(self.A4, StampCorner.bottom_right, 20.0, *self.BOX)[2] == right - 20
        assert _box_in_corner(self.A4, StampCorner.top_left, 20.0, *self.BOX)[3] == top - 20
        far = _box_in_corner(self.A4, StampCorner.top_right, 20.0, *self.BOX)
        assert (far[2], far[3]) == (right - 20, top - 20)
        near = _box_in_corner(self.A4, StampCorner.bottom_left, 20.0, *self.BOX)
        assert (near[0], near[1]) == (left + 20, bottom + 20)

    def test_a_box_that_cannot_fit_says_so_instead_of_drawing_off_the_paper(self):
        with pytest.raises(ValueError, match="does not fit on it at all"):
            _box_in_corner(self.A5, StampCorner.top_left, 20.0, 900, 70)

    def test_a_margin_wider_than_the_leftover_space_is_clamped_onto_the_page(self):
        """A 205 point box on a 420 point page leaves 215 points to share. A 300 point margin
        cannot be honoured, and sliding off the paper is the wrong way to say so."""
        left, bottom, right, top = self.A5
        x1, y1, x2, y2 = _box_in_corner(self.A5, StampCorner.bottom_right, 300.0, *self.BOX)

        assert left <= x1 and x2 <= right
        assert bottom <= y1 and y2 <= top

    def test_the_page_size_is_read_from_the_page_and_not_assumed(self, tmp_path):
        """The whole feature. A file whose pages differ has to give a different box per page."""
        import io

        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
        from reportlab.lib.pagesizes import A4, A5
        from reportlab.pdfgen import canvas as rl_canvas

        buf = io.BytesIO()
        c = rl_canvas.Canvas(buf, pagesize=A4)
        c.showPage()
        c.setPageSize(A5)
        c.showPage()
        c.save()
        buf.seek(0)
        writer = IncrementalPdfFileWriter(buf)

        first = _page_media_box(writer, 0)
        last = _page_media_box(writer, -1)
        assert round(first[2]) == round(A4[0])
        assert round(last[2]) == round(A5[0])      # -1 is the last page, and it is the A5 one

        # And the failure this replaces, as a number: the A4 answer used on the A5 page.
        wrong = _box_in_corner(first, StampCorner.bottom_right, 20.0, *self.BOX)
        assert wrong[2] - last[2] > 150, "the A4 box would have hung off the A5 page"


class TestImageIsNotEmbeddedWholesale:
    """An image goes into the stamp, and the stamp goes into every PDF signed with it.

    Measured before this existed: a 3000x2000 photo produced a 15 MB appearance, and even a
    1200x750 logo produced 2.3 MB, for a box 205 by 70 points across. Other Uruguayan signing
    software answers this by refusing anything over 500 kb and 400x250 px. Shrinking to what the
    box can show is the better answer: the person's own image is used, and nothing is refused.
    """

    ARGS = dict(signer="PEREZ, JUAN", cert_serial="0123", ts="07/08/2026 10:30",
                issuer="AC RAIZ")

    def _photo(self, tmp_path, size) -> str:
        """Noise, because a flat colour compresses to nothing and would prove nothing."""
        import random

        random.seed(1)
        image = Image.new("RGB", size)
        image.putdata([(random.randrange(256), random.randrange(256), random.randrange(256))
                       for _ in range(size[0] * size[1])])
        path = tmp_path / "photo.jpg"
        image.save(path, quality=85)
        return str(path)

    @pytest.mark.parametrize("mode", list(ImageMode))
    def test_a_photo_does_not_become_a_multi_megabyte_stamp(self, tmp_path, mode):
        out = tmp_path / f"{mode.value}.pdf"
        make_appearance_pdf(str(out), **self.ARGS, image_path=self._photo(tmp_path, (3000, 2000)),
                            image_mode=mode)

        # 15 MB is what this produced before. Half a megabyte is generous for a 205x70 box and
        # still two orders of magnitude away from the failure.
        assert out.stat().st_size < 512 * 1024, f"{mode.value} embedded the photo whole"

    def test_it_shrinks_to_the_box_and_keeps_the_aspect_ratio(self, tmp_path):
        wide = _sized_for_box(self._photo(tmp_path, (3000, 2000)), APPEARANCE_WIDTH,
                              APPEARANCE_HEIGHT)

        assert wide.height <= round(APPEARANCE_HEIGHT / 72 * STAMP_IMAGE_DPI)
        assert wide.width <= round(APPEARANCE_WIDTH / 72 * STAMP_IMAGE_DPI)
        assert abs(wide.width / wide.height - 3000 / 2000) < 0.01, "the aspect ratio moved"

    def test_a_small_logo_keeps_its_own_pixels(self, tmp_path):
        """Only ever shrunk. Enlarging would invent detail and make the file bigger for it."""
        path = tmp_path / "small.png"
        Image.new("RGBA", (120, 40), (10, 60, 120, 255)).save(path)

        assert _sized_for_box(str(path), APPEARANCE_WIDTH, APPEARANCE_HEIGHT).size == (120, 40)

    def test_a_transparent_background_survives_the_shrink(self, tmp_path):
        """The resize runs before the image reaches reportlab, so it must not flatten alpha:
        mask="auto" is what cuts a logo out of its box, and an opaque rectangle instead of a
        transparent one is the most visible way this could go wrong."""
        path = tmp_path / "logo.png"
        image = Image.new("RGBA", (800, 600), (0, 0, 0, 0))
        image.paste((220, 40, 40, 255), (200, 150, 600, 450))
        image.save(path)

        shrunk = _sized_for_box(str(path), APPEARANCE_WIDTH, APPEARANCE_HEIGHT)
        assert shrunk.mode == "RGBA"
        assert shrunk.getpixel((0, 0))[3] == 0, "the transparent corner became opaque"

    def test_a_large_jpeg_is_decoded_at_a_fraction_of_its_size(self, tmp_path, monkeypatch):
        """Decoding a photo whole only to throw most of it away cost 560 MB on a 48 MP phone
        photo. What the decoder was asked for is visible on the opened file: its size."""
        path = tmp_path / "photo.jpg"
        Image.new("RGB", (3600, 1400), (200, 190, 180)).save(path, quality=85)
        opened = []
        real_open = Image.open

        def spy(*args, **kwargs):
            opened.append(real_open(*args, **kwargs))
            return opened[-1]

        monkeypatch.setattr(Image, "open", spy)
        shrunk = _sized_for_box(str(path), APPEARANCE_WIDTH, APPEARANCE_HEIGHT)

        assert opened[0].size[0] < 3600, "the JPEG was decoded at full size"
        assert shrunk.width <= round(APPEARANCE_WIDTH / 72 * STAMP_IMAGE_DPI)
        assert shrunk.height <= round(APPEARANCE_HEIGHT / 72 * STAMP_IMAGE_DPI)


class TestCheckStampImage:
    """Everything the stamp would refuse after the PIN, refused before it."""

    def test_a_real_image_passes(self, sample_png):
        check_stamp_image(str(sample_png))

    def test_a_corrupt_file_is_a_value_error(self, tmp_path):
        bad = tmp_path / "bad.png"
        bad.write_bytes(b"not an image")
        with pytest.raises(ValueError, match="cannot identify image file"):
            check_stamp_image(str(bad))

    def test_a_decompression_bomb_is_refused_on_its_header(self, tmp_path, monkeypatch):
        """Pillow's own limit, applied to the declared size, so nothing is decoded to find out."""
        path = tmp_path / "bomb.png"
        Image.new("RGB", (64, 64)).save(path)
        monkeypatch.setattr(Image, "MAX_IMAGE_PIXELS", 1000)     # 4096 pixels is over twice that
        with pytest.raises(ValueError, match="decompression bomb"):
            check_stamp_image(str(path))
