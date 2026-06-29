import os
from pathlib import Path

import pytest
from PIL import Image

from cedula_uy_pdf_sign.appearance import (
    ensure_output_parent,
    make_appearance_pdf,
    split_signer_name,
    wrap_line,
)
from cedula_uy_pdf_sign.constants import ImageMode, STAMP_FONT_NAME, STAMP_FONT_SIZE


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
