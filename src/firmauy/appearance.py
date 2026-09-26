# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

from pathlib import Path

from reportlab.lib.utils import ImageReader
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen import canvas

from firmauy.constants import (
    APPEARANCE_WIDTH,
    APPEARANCE_HEIGHT,
    DEFAULT_IMAGE_OPACITY,
    ImageMode,
    STAMP_FONT_NAME,
    STAMP_IMAGE_DPI,
    STAMP_FONT_SIZE,
    STAMP_LEADING,
    STAMP_TEXT_X,
    STAMP_TEXT_Y,
    StampFields,
)

_ALL_FIELDS = StampFields()

# What STAMP_TEXT_Y was measured against: title, signer, document, date, issuer.
_FULL_TEXT_LINES = 5


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


def check_stamp_image(image_path) -> None:
    """Fail on an image the stamp cannot use, before any card is touched.

    Opening reads the header only, so a file past Pillow's decompression-bomb limit is refused on
    its declared size without being decoded, and ``verify`` catches a truncated or corrupt one.
    Whatever the decoder refuses comes back as a ValueError carrying its message, for the caller
    to put in context.
    """
    from PIL import Image

    try:
        with Image.open(image_path) as im:
            im.verify()
    except Exception as exc:
        raise ValueError(str(exc) or type(exc).__name__) from exc


def _sized_for_box(image_path, w: float, h: float):
    """Open the image and shrink it to the pixels the box can actually show.

    An image is embedded at whatever resolution it arrives with, and the stamp box is 205x70
    points. Measured: a 3000x2000 photo produced a 15 MB appearance, which then sits inside every
    PDF signed with it, and even a 1200x750 logo produced 2.3 MB. Capped at 300 DPI over the box
    the same photo produces 141 KB, 109 times smaller, and no viewer or printer can tell: at that
    size the box is already beyond what either resolves.

    Never enlarged, only shrunk, so a small logo keeps its own pixels. RGBA throughout, so a
    transparent background stays transparent and `mask="auto"` still cuts it out.
    """
    from PIL import Image

    cap = (max(1, round(w / 72 * STAMP_IMAGE_DPI)), max(1, round(h / 72 * STAMP_IMAGE_DPI)))
    with Image.open(image_path) as src:   # context manager: don't leak the file handle
        # A JPEG can be decoded at 1/2, 1/4 or 1/8 of its size for almost nothing, and the box
        # never shows more than `cap`. Measured on a 48 MP phone photo: 560 MB decoded whole,
        # 38 MB this way, and the same 29 KB stamp. The 2x margin is the one Image.thumbnail
        # keeps when it does the same. Every other format ignores the call and is decoded whole,
        # as before.
        src.draft(None, (2 * cap[0], 2 * cap[1]))
        img = src.convert("RGBA")
    if img.width > cap[0] or img.height > cap[1]:
        img.thumbnail(cap, Image.LANCZOS)
    return img


def _faded_image(img, opacity: float):
    """Return a PIL image blended toward white by `opacity` (a deterministic watermark, baked
    into the pixels, so it does not rely on the PDF renderer honouring image alpha)."""
    from PIL import Image

    white = Image.new("RGBA", img.size, (255, 255, 255, 255))
    on_white = Image.alpha_composite(white, img)          # resolve transparency over white
    return Image.blend(white, on_white, opacity).convert("RGB")


def _draw_image_fit(c, image_path, x, y, w, h, opacity: float = 1.0) -> None:
    """Draw an image inside the (x, y, w, h) box, preserving aspect ratio and centered.
    `opacity` < 1 fades it (for the background watermark). Raises a clear error on a bad image."""
    try:
        source = _sized_for_box(image_path, w, h)
        img = ImageReader(_faded_image(source, opacity) if opacity < 1.0 else source)
    except Exception as exc:
        raise RuntimeError(f"could not load image '{image_path}': {exc}") from exc
    try:
        c.drawImage(img, x, y, width=w, height=h,
                    preserveAspectRatio=True, anchor="c", mask="auto")
    except Exception as exc:
        raise RuntimeError(f"could not draw image '{image_path}': {exc}") from exc


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
    fields: StampFields = _ALL_FIELDS,
) -> None:
    """Render the signature appearance as a ReportLab PDF file.

    Without `image_path` it is the text block only (the original behavior). With an image,
    `image_mode` decides the layout: `background` (image behind the text, faded by
    `image_opacity`), `side` (image to the left, text reflowed into the narrower right column),
    or `only` (image, no text).

    `fields` selects which of the five lines are printed. With every line off the text block is
    skipped entirely, which is the same result as `only` reached from the other direction, and
    with an image and no text that is a perfectly sensible stamp."""
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

    if draw_text and fields.any:
        c.setFont(STAMP_FONT_NAME, STAMP_FONT_SIZE)
        # Wrap every line to text_max_width so nothing clips in the narrower `side` column
        # (in the default full-width layout these stay on a single line, unchanged).
        lines: list[str] = []
        if fields.title:
            lines += wrap_line("Firma electrónica avanzada, UY", STAMP_FONT_NAME,
                               STAMP_FONT_SIZE, text_max_width)
        if fields.signer:
            lines += split_signer_name(signer, text_max_width)
        if fields.document:
            lines.append(f"Documento: {cert_serial}")
        if fields.date:
            lines.append(f"Fecha: {ts}")
        if fields.issuer:
            lines += wrap_line(issuer, STAMP_FONT_NAME, STAMP_FONT_SIZE, text_max_width)

        # With all five on, the block starts at STAMP_TEXT_Y, which is what these constants were
        # chosen for, so that case renders byte for byte as before. Turning lines off would
        # otherwise hang a short block from the top with every bit of air underneath, so it slides
        # down by half of what was removed and keeps sitting in the middle of the box. Never
        # upward: a long name or issuer already wraps past five lines, and raising that would push
        # the first line out through the top.
        missing = max(0, _FULL_TEXT_LINES - len(lines))
        text = c.beginText(text_x, STAMP_TEXT_Y - missing * STAMP_LEADING / 2)
        text.setFont(STAMP_FONT_NAME, STAMP_FONT_SIZE)
        text.setLeading(STAMP_LEADING)
        for line in lines:
            text.textLine(line)
        c.drawText(text)

    c.showPage()
    c.save()


def ensure_output_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
