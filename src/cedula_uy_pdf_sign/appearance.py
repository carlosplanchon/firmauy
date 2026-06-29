# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

from pathlib import Path

from reportlab.lib.utils import ImageReader
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen import canvas

from cedula_uy_pdf_sign.constants import (
    APPEARANCE_WIDTH,
    APPEARANCE_HEIGHT,
    DEFAULT_IMAGE_OPACITY,
    ImageMode,
    STAMP_FONT_NAME,
    STAMP_FONT_SIZE,
    STAMP_LEADING,
    STAMP_TEXT_X,
    STAMP_TEXT_Y,
)


def wrap_line(
    text: str,
    font_name: str,
    font_size: float,
    max_width: float,
) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""

    for word in words:
        candidate = word if not current else f"{current} {word}"
        if stringWidth(candidate, font_name, font_size) <= max_width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word

    if current:
        lines.append(current)

    return lines


def split_signer_name(signer: str, max_width: float | None = None) -> list[str]:
    prefix = "Firmado por: "
    if max_width is None:
        max_width = APPEARANCE_WIDTH - STAMP_TEXT_X - 2

    full = f"{prefix}{signer}"
    if stringWidth(full, STAMP_FONT_NAME, STAMP_FONT_SIZE) <= max_width:
        return [full]

    words = signer.split()
    current = prefix
    used_words = 0

    for i, word in enumerate(words):
        candidate = current + word if current.endswith(": ") else f"{current} {word}"
        if stringWidth(candidate, STAMP_FONT_NAME, STAMP_FONT_SIZE) <= max_width:
            current = candidate
            used_words = i + 1
        else:
            break

    remaining = " ".join(words[used_words:]).strip()

    lines = [current]
    if remaining:
        lines.append(remaining)

    return lines


def _draw_image_fit(c, image_path, x, y, w, h, opacity: float = 1.0) -> None:
    """Draw an image inside the (x, y, w, h) box, preserving aspect ratio and centered.
    `opacity` < 1 fades it (for the background watermark). Raises a clear error on a bad image."""
    try:
        img = ImageReader(image_path)
    except Exception as exc:
        raise RuntimeError(f"could not load image '{image_path}': {exc}") from exc
    c.saveState()
    if opacity < 1.0:
        c.setFillAlpha(opacity)
        c.setStrokeAlpha(opacity)
    try:
        c.drawImage(img, x, y, width=w, height=h,
                    preserveAspectRatio=True, anchor="c", mask="auto")
    except Exception as exc:
        raise RuntimeError(f"could not draw image '{image_path}': {exc}") from exc
    finally:
        c.restoreState()


def make_appearance_pdf(
    path: str,
    signer: str,
    cert_serial: str,
    ts: str,
    issuer: str,
    *,
    image_path: str | None = None,
    image_mode: ImageMode = ImageMode.background,
    image_opacity: float = DEFAULT_IMAGE_OPACITY,
) -> None:
    """Render the signature appearance as a ReportLab PDF file.

    Without `image_path` it is the text block only (the original behavior). With an image,
    `image_mode` decides the layout: `background` (image behind the text, faded by
    `image_opacity`), `side` (image to the left, text reflowed into the narrower right column),
    or `only` (image, no text)."""
    width, height = APPEARANCE_WIDTH, APPEARANCE_HEIGHT

    c = canvas.Canvas(path, pagesize=(width, height))
    c.setPageCompression(0)

    text_x = STAMP_TEXT_X
    text_max_width = APPEARANCE_WIDTH - STAMP_TEXT_X - 2
    draw_text = True

    if image_path:
        if image_mode == ImageMode.only:
            _draw_image_fit(c, image_path, 2, 2, width - 4, height - 4)
            draw_text = False
        elif image_mode == ImageMode.side:
            side_w = width * 0.35
            _draw_image_fit(c, image_path, 2, 2, side_w - 4, height - 4)
            text_x = side_w + 4
            text_max_width = width - text_x - 2
        else:  # background
            _draw_image_fit(c, image_path, 2, 2, width - 4, height - 4, opacity=image_opacity)

    if draw_text:
        c.setFont(STAMP_FONT_NAME, STAMP_FONT_SIZE)
        signer_lines = split_signer_name(signer, text_max_width)
        issuer_lines = wrap_line(issuer, STAMP_FONT_NAME, STAMP_FONT_SIZE, text_max_width)

        lines = [
            "Firma electrónica avanzada, UY",
            *signer_lines,
            f"Documento: {cert_serial}",
            f"Fecha: {ts}",
            *issuer_lines,
        ]

        text = c.beginText(text_x, STAMP_TEXT_Y)
        text.setFont(STAMP_FONT_NAME, STAMP_FONT_SIZE)
        text.setLeading(STAMP_LEADING)
        for line in lines:
            text.textLine(line)
        c.drawText(text)

    c.showPage()
    c.save()


def ensure_output_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
