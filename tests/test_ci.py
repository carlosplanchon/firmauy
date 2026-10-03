"""Unit tests for the Uruguayan cédula check-digit logic (pure, no card).

The algorithm is anchored to the public ground-truth vector documented by multiple sources: the body
``1234567`` has check digit ``2`` (weights 2 9 8 7 6 3 4). No real cédula number appears here."""

import pytest

from firmauy.ci import (
    ci_check_digit,
    complete_ci,
    normalize_ci,
    validate_ci,
)


# --- the algorithm, anchored to ground truth --------------------------------

def test_check_digit_ground_truth():
    assert ci_check_digit("1234567") == 2          # authoritative public example


def test_check_digit_zero_case():
    # When the weighted sum is a multiple of 10 the check digit is 0, not 10.
    assert ci_check_digit("0000000") == 0


def test_check_digit_pads_short_body():
    assert ci_check_digit("234567") == ci_check_digit("0234567")


@pytest.mark.parametrize("body", ["1234567", "0000000", "7654321", "0010203", "4200000", "0000001"])
def test_complete_then_validate_round_trips(body):
    full = complete_ci(body)
    assert len(full) == 8                           # canonical zero-padded form
    assert full[:7] == body.zfill(7)
    assert validate_ci(full)["valid"] is True       # the completed number validates


# --- validate_ci ------------------------------------------------------------

def test_validate_known_valid():
    r = validate_ci("12345672")
    assert r["valid"] is True
    assert r == {"valid": True, "normalized": "12345672", "body": "1234567",
                 "check_digit": "2", "expected_check_digit": "2"}


def test_validate_known_invalid_reports_expected():
    r = validate_ci("12345678")                     # check digit should be 2, not 8
    assert r["valid"] is False
    assert r["check_digit"] == "8" and r["expected_check_digit"] == "2"


def test_validate_strips_separators():
    assert validate_ci("1.234.567-2")["normalized"] == "12345672"
    assert validate_ci("1.234.567-2")["valid"] is True


# --- normalization / malformed input ----------------------------------------

def test_normalize_strips_dots_dash_spaces():
    assert normalize_ci("  1.234.567-2 ") == "12345672"


@pytest.mark.parametrize("bad", ["", "   ", "ABC", "12a45", "12345678-9", "123456789"])
def test_normalize_rejects_malformed(bad):
    with pytest.raises(ValueError):
        normalize_ci(bad)


def test_validate_rejects_too_short():
    with pytest.raises(ValueError):
        validate_ci("7")                            # a single digit has no body


def test_complete_rejects_body_too_long():
    with pytest.raises(ValueError):
        complete_ci("12345678")                     # 8 digits is a full CI, not a body


# --- digits other than 0-9 --------------------------------------------------
#
# str.isdigit() is true for far more than 0-9, and every one of these used to get past it.

@pytest.mark.parametrize("text", ["١٢٣٤٥٦٧٢", "１２３４５６７２", "1234567٢"],
                         ids=["arabic-indic", "fullwidth", "only-the-check-digit"])
def test_a_correct_number_in_another_digit_set_is_malformed_not_invalid(text):
    """Each is 1234567-2, which is correct. They came back ``valid: False``: int() reads these
    digits, so the expected check digit came out right, and it was then compared as text with
    one that is a different character. A verdict that a correct number is wrong is worse than
    refusing to read it."""
    with pytest.raises(ValueError, match="non-digit"):
        validate_ci(text)


def test_a_superscript_digit_is_refused_by_the_check_and_not_by_int():
    """isdigit() accepts '²' and int() does not, so this raised from int(), in its own words."""
    with pytest.raises(ValueError, match="non-digit"):
        validate_ci("12345²72")


@pytest.mark.parametrize("body", ["١٢٣٤٥٦٧", "12345²7"], ids=["arabic-indic", "superscript"])
def test_a_body_in_another_digit_set_is_not_completed(body):
    """The first one came back as '١٢٣٤٥٦٧2', a number in two scripts at once."""
    with pytest.raises(ValueError, match="non-digit"):
        complete_ci(body)


def test_the_check_digit_refuses_them_on_its_own():
    """It is public too, and was the one place the arithmetic ran on whatever isdigit() let in."""
    with pytest.raises(ValueError):
        ci_check_digit("١٢٣٤٥٦٧")
