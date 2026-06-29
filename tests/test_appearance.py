import os
from pathlib import Path

from cedula_uy_pdf_sign.appearance import (
    ensure_output_parent,
    make_appearance_pdf,
    split_signer_name,
    wrap_line,
)
from cedula_uy_pdf_sign.constants import STAMP_FONT_NAME, STAMP_FONT_SIZE


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
