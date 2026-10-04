# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

import os
import sys
from dataclasses import dataclass
from enum import Enum


@dataclass(frozen=True)
class StampFields:
    """Which of the five lines the visible stamp prints.

    One object rather than five booleans threaded through every signing function, which is the
    only reason it exists: the public shape is :class:`firmauy.api.PdfAppearance`, which spells
    them out flat because that is what a checkbox binds to.

    Every line can be turned off, including the signer's name. The stamp is decoration drawn on
    a page, not the signature: whoever verifies the file reads the signer, the issuer and the
    time out of the signature itself, where they are covered by the cryptography and cannot be
    edited away. Turning off ``document`` is worth knowing about for a different reason: it is
    the certificate's serial rather than the cédula number, so it identifies the certificate
    without printing somebody's national ID on every copy of the file.
    """

    title: bool = True       # "Firma electrónica avanzada, UY"
    signer: bool = True      # "Firmado por: ..."
    document: bool = True    # "Documento: ..." (the certificate serial)
    date: bool = True        # "Fecha: ..."
    issuer: bool = True      # the issuing authority's name

    @property
    def any(self) -> bool:
        """False when every line is off, which draws no text block at all."""
        return any((self.title, self.signer, self.document, self.date, self.issuer))


class StampCorner(str, Enum):
    """Which corner of the page the visible stamp is placed against.

    A corner is resolved against the page's own MediaBox while the PDF is open, which is the only
    place the page size is known. Absolute coordinates cannot express "bottom right" without it:
    a box computed for A4 falls off an A5.
    """
    bottom_left = "bottom-left"     # where the stamp has always gone
    bottom_right = "bottom-right"
    top_left = "top-left"
    top_right = "top-right"


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


# The stamp box is 205x70 points, so an image beyond this over it is pixels nobody can see, in a
# file that then travels inside every PDF signed with it. 300 DPI is past what a screen or a
# printer resolves at that size. Measured: a 3000x2000 photo went from a 15 MB appearance to
# 141 KB, with no visible difference.
STAMP_IMAGE_DPI = 300

# Default opacity for an image in --image-mode background (subtle watermark, keeps text legible).
DEFAULT_IMAGE_OPACITY = 0.2

# The cédula's PKCS#11 module, as its middleware installs it. On Windows that is Thales Classic
# Client. Its installer also puts a 32-bit copy under "Program Files (x86)", which a 64-bit Python
# cannot load. %ProgramFiles% names the folder matching this interpreter, so a 64-bit Python gets
# the 64-bit module.
if sys.platform == "win32":
    DEFAULT_PKCS11_LIB = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"),
                                      "Thales", "Classic Client", "BIN", "gclib.dll")
else:
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

