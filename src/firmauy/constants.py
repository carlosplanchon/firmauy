# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

from enum import Enum


class ImageMode(str, Enum):
    """Where an --image goes inside the signature appearance box."""
    background = "background"   # behind the text (subtle watermark)
    side = "side"               # to the left of the text
    only = "only"               # image only, no text


class SignAs(str, Enum):
    """The signature type for the unified `sign` / `sign-batch` commands."""
    auto = "auto"     # detect by file content: PDF -> pdf, XML -> xml, else -> cades
    pdf = "pdf"       # force PAdES (embedded PDF signature)
    xml = "xml"       # force XAdES (enveloped XML signature)
    cades = "cades"   # force detached CAdES (.p7s), for any input including PDF/XML


# Default opacity for an image in --image-mode background (subtle watermark, keeps text legible).
DEFAULT_IMAGE_OPACITY = 0.2

DEFAULT_PKCS11_LIB = "/usr/lib/pkcs11/libgclib.so"
DEFAULT_TIMEZONE = "America/Montevideo"

# Reference dimensions for the signature field:
# Rect [20 20 225 90] => 205 x 70
APPEARANCE_WIDTH = 205
APPEARANCE_HEIGHT = 70

DEFAULT_X1 = 20
DEFAULT_Y1 = 20
DEFAULT_X2 = DEFAULT_X1 + APPEARANCE_WIDTH   # 225
DEFAULT_Y2 = DEFAULT_Y1 + APPEARANCE_HEIGHT  # 90

# Signature field font values
STAMP_FONT_NAME = "Helvetica"
STAMP_FONT_SIZE = 8.0
STAMP_LEADING = 9.6
STAMP_TEXT_X = 4.0
STAMP_TEXT_Y = 58.0

