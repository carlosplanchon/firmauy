# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Uruguayan cédula de identidad (CI) check-digit validation.

This is a purely **arithmetic consistency check** of a CI number using the standard weighted
check-digit algorithm (weights 2 9 8 7 6 3 4 over the 7-digit body, left-padded with zeros). It
catches typos and obviously malformed numbers.

It does **not** validate identity, the existence or current validity of a person, the validity of a
document, or the authenticity of a card. It only verifies that the number's check digit is internally
consistent.
"""

import re

_WEIGHTS = (2, 9, 8, 7, 6, 3, 4)
_SEPARATORS = re.compile(r"[.\-\s]")


def normalize_ci(text: str) -> str:
    """Strip the usual separators (dots, dashes, spaces) and return the digits of a CI string.

    Raises ValueError if the input is empty, contains non-digit characters, or is longer than 8
    digits (a 7-digit body plus one check digit)."""
    digits = _SEPARATORS.sub("", text)
    if not digits:
        raise ValueError("empty cédula number")
    if not digits.isdigit():
        raise ValueError(f"cédula number has non-digit characters: {text!r}")
    if len(digits) > 8:
        raise ValueError(f"cédula number too long ({len(digits)} digits, max 8): {text!r}")
    return digits


def ci_check_digit(body: str) -> int:
    """Return the check digit (0-9) for a CI body of up to 7 digits (left-padded with zeros)."""
    body = body.zfill(7)
    if len(body) != 7 or not body.isdigit():
        raise ValueError(f"cédula body must be up to 7 digits: {body!r}")
    total = sum(int(d) * w for d, w in zip(body, _WEIGHTS))
    return (10 - total % 10) % 10


def complete_ci(body_text: str) -> str:
    """Given a CI body (no check digit), return the full CI with its check digit appended.

    Raises ValueError if the body is malformed or longer than 7 digits."""
    body = normalize_ci(body_text)
    if len(body) > 7:
        raise ValueError(f"cédula body too long ({len(body)} digits, max 7): {body_text!r}")
    return body.zfill(7) + str(ci_check_digit(body))


def validate_ci(text: str) -> dict:
    """Validate a complete CI (its last digit is the check digit).

    Returns ``{"valid", "normalized", "body", "check_digit", "expected_check_digit"}``. Raises
    ValueError if the input is not a usable CI string (non-digits, empty, too long, or too short to
    contain both a body and a check digit)."""
    normalized = normalize_ci(text)
    if len(normalized) < 2:
        raise ValueError(f"cédula number too short ({len(normalized)} digit): {text!r}")
    body, check = normalized[:-1], normalized[-1]
    expected = str(ci_check_digit(body))
    return {
        "valid": expected == check,
        "normalized": normalized,
        "body": body,
        "check_digit": check,
        "expected_check_digit": expected,
    }
