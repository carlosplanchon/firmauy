"""Unit tests for the pure (no card, no HSM) parts of the public API firmauy.api.

The card- and PKCS#11-touching API functions are covered by the SoftHSM integration tests
(test_integration_*.py); this file covers the utilities that need no hardware.
"""

from __future__ import annotations

import pytest

from firmauy.api import (
    CaBundle,
    CiReport,
    complete_ci,
    fetch_cas,
    sign,
    sign_files,
    sign_xml,
    validate_ci,
)


def test_validate_ci_accepts_a_consistent_number():
    full = complete_ci("1234567")  # a body turned into a full number with its check digit
    report = validate_ci(full)
    assert isinstance(report, CiReport)
    assert report.valid is True
    assert report.normalized == full
    assert report.body == full[:-1]
    assert report.check_digit == full[-1]
    assert report.expected_check_digit == full[-1]


def test_validate_ci_flags_a_wrong_check_digit():
    full = complete_ci("1234567")
    wrong = full[:-1] + str((int(full[-1]) + 1) % 10)
    report = validate_ci(wrong)
    assert report.valid is False
    assert report.check_digit == wrong[-1]
    assert report.expected_check_digit == full[-1]


def test_validate_ci_rejects_non_digits():
    with pytest.raises(ValueError):
        validate_ci("not-a-number")


def test_complete_ci_appends_a_valid_check_digit():
    full = complete_ci("1111111")
    assert len(full) == 8
    assert validate_ci(full).valid is True


def test_sign_functions_reject_empty_pin(tmp_path):
    """Every signing entry point refuses an empty PIN before touching the card (would spend a retry)."""
    f = tmp_path / "x.txt"
    f.write_text("hola")
    for call in (
        lambda: sign(f, "", native=False),
        lambda: sign_xml(f, "", native=False),
        lambda: sign_files([f], "", native=False),
    ):
        with pytest.raises(ValueError, match="non-empty PIN"):
            call()


def test_fetch_cas_wraps_the_paths_and_cache_dir(monkeypatch, tmp_path):
    import firmauy.national_ca as nca

    root = tmp_path / "acrn.pem"
    intermediate = tmp_path / "mica.pem"
    monkeypatch.setattr(nca, "fetch_cas", lambda progress=None, source_files=None: (root, intermediate))
    monkeypatch.setattr(nca, "cache_dir", lambda: tmp_path)

    bundle = fetch_cas()

    assert isinstance(bundle, CaBundle)
    assert bundle.root_path == root
    assert bundle.intermediate_path == intermediate
    assert bundle.cache_dir == tmp_path


def test_doctor_marks_only_the_token_check_as_sensitive(monkeypatch):
    """The diagnostic contract: every check says whether its detail can carry the cardholder's
    data, so a consumer never has to infer it from the check's name."""
    import firmauy._shared as shared
    from firmauy.api import run_doctor

    raw = [
        {"status": "PASS", "name": "firmauy", "detail": "1.9.0", "fix": None, "sensitive": False},
        {"status": "PASS", "name": "cédula token detected", "detail": "PEREZ PEREZ JUAN",
         "fix": None, "sensitive": True},
    ]
    monkeypatch.setattr(shared, "_collect_doctor_checks", lambda *a, **k: raw)

    checks = run_doctor().checks
    assert [c.sensitive for c in checks] == [False, True]
    # The flag travels on the dataclass, so an API consumer sees the same contract as --json.
    assert checks[1].detail == "PEREZ PEREZ JUAN"


def test_every_collected_check_carries_the_sensitive_flag(monkeypatch):
    """No check may omit the key: a consumer that fails closed on a missing one must never be
    tripped by our own output."""
    import firmauy._shared as shared

    monkeypatch.setattr(shared, "_doctor_pkcs11", lambda add, lib: add(
        "PASS", "cédula token detected", "SOME LABEL", sensitive=True))
    checks = shared._collect_doctor_checks(False, None, "/nonexistent.so")

    assert checks, "expected at least the version and pcscd checks"
    assert all("sensitive" in c for c in checks)
    assert sum(c["sensitive"] for c in checks) == 1     # only the token label


# --- output_path_for (no card, no HSM) --------------------------------------

def test_output_path_for_matches_each_signer_default(tmp_path):
    """The point of the helper is that a caller can warn about an existing output before asking
    for the PIN. If it drifted from where the file actually lands it would be worse than useless.
    """
    from firmauy.api import output_path_for

    pdf = tmp_path / "contrato.pdf"
    pdf.write_bytes(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    xml = tmp_path / "factura.xml"
    xml.write_bytes(b'<?xml version="1.0"?><F/>')
    blob = tmp_path / "datos.bin"
    blob.write_bytes(b"cualquier cosa")

    # Auto-detection, by content: embedded signatures keep the extension, detached ones append.
    assert output_path_for(pdf) == tmp_path / "contrato_firmado.pdf"
    assert output_path_for(xml) == tmp_path / "factura_firmado.xml"
    assert output_path_for(blob) == tmp_path / "datos.bin.p7s"


def test_output_path_for_honours_a_forced_type(tmp_path):
    pdf = tmp_path / "contrato.pdf"
    pdf.write_bytes(b"%PDF-1.7\n")

    from firmauy.api import output_path_for

    # Signing a PDF as a detached .p7s leaves the original bytes untouched, which some
    # counterparties ask for.
    assert output_path_for(pdf, sign_as="cades") == tmp_path / "contrato.pdf.p7s"
    assert output_path_for(pdf, sign_as="pdf") == tmp_path / "contrato_firmado.pdf"


def test_output_path_for_places_a_batch_flat_in_the_output_dir(tmp_path):
    from firmauy.api import output_path_for

    src = tmp_path / "sub"
    src.mkdir()
    blob = src / "datos.bin"
    blob.write_bytes(b"x")
    out = tmp_path / "firmados"

    assert output_path_for(blob, output_dir=out) == out / "datos.bin.p7s"


def test_output_path_for_can_answer_about_a_file_that_is_not_there(tmp_path):
    """With an explicit type nothing is read, so a caller can ask before the file exists."""
    from firmauy.api import output_path_for

    assert output_path_for(tmp_path / "todavia_no.xml",
                           sign_as="xml") == tmp_path / "todavia_no_firmado.xml"


def test_output_path_for_rejects_an_unknown_type(tmp_path):
    from firmauy.api import output_path_for

    with pytest.raises(ValueError):
        output_path_for(tmp_path / "x.pdf", sign_as="pkcs7")


def test_the_access_control_error_is_reachable_from_the_public_api():
    """The module promises the precise exceptions are importable from here, and a caller cannot
    catch what it cannot name."""
    from firmauy import api
    from firmauy.errors import OutputAccessControlError

    assert api.OutputAccessControlError is OutputAccessControlError


def test_the_committed_output_error_is_reachable_from_the_public_api():
    """Same promise as every other precise exception: a caller cannot catch what it cannot name,
    and this is the one that means the file exists and must not be signed again."""
    from firmauy import api
    from firmauy.errors import OutputCommittedError

    assert api.OutputCommittedError is OutputCommittedError


def test_the_post_sign_verification_error_is_reachable_from_the_public_api():
    """It carries the difference between "delete this and sign again" and "do not sign again,
    look at it", which a caller cannot act on without being able to name the class."""
    from firmauy import api
    from firmauy.errors import PostSignVerificationError

    assert api.PostSignVerificationError is PostSignVerificationError


def test_the_sign_as_type_is_reachable_from_the_public_api():
    """`sign_as` is an argument of three public functions, so its type belongs here too. A caller
    that wants to reject a bad value before touching the card had to import firmauy.constants,
    which is the one place firmauy-desktop reached past this module. The alternative, a hand-copied
    tuple of the valid strings, forks the enum the day a fourth type is added.
    """
    from firmauy import api
    from firmauy.constants import SignAs

    assert api.SignAs is SignAs
    # The values the three signatures document, so a consumer can build a menu from the enum
    # instead of hardcoding them.
    assert {member.value for member in api.SignAs} == {"auto", "pdf", "xml", "cades"}


def test_the_image_mode_type_is_reachable_from_the_public_api():
    """Same promise as SignAs: it is the type of PdfAppearance.image_mode, so a caller building a
    menu of the layouts should not have to import firmauy.constants to enumerate them."""
    from firmauy import api
    from firmauy.constants import ImageMode

    assert api.ImageMode is ImageMode
    assert {member.value for member in api.ImageMode} == {"background", "side", "only"}


def test_the_default_appearance_is_exactly_what_was_hardcoded_before_it_existed():
    """PdfAppearance replaced literals that sat inside sign_pdf and sign_files. If its defaults
    drift from those, every document signed without asking for an appearance gets a stamp
    somewhere else, and nothing else in the suite would notice."""
    from firmauy.api import PdfAppearance
    from firmauy.constants import (DEFAULT_IMAGE_OPACITY, DEFAULT_TIMEZONE, DEFAULT_X1,
                                   DEFAULT_X2, DEFAULT_Y1, DEFAULT_Y2, ImageMode, StampFields)

    kwargs = PdfAppearance()._pdf_kwargs()

    assert kwargs["page"] == -1                     # the last page
    assert (kwargs["x1"], kwargs["y1"]) == (DEFAULT_X1, DEFAULT_Y1)
    assert (kwargs["x2"], kwargs["y2"]) == (DEFAULT_X2, DEFAULT_Y2)
    assert kwargs["timezone"] == DEFAULT_TIMEZONE
    assert kwargs["image_path"] is None
    assert kwargs["image_mode"] == ImageMode.background
    assert kwargs["image_opacity"] == DEFAULT_IMAGE_OPACITY
    assert kwargs["stamp_fields"] == StampFields()  # all five lines on


def test_the_appearance_rejects_a_bad_value_before_the_card_is_touched():
    """The whole point of validating in __post_init__. Reaching the card first means the person
    typed their PIN, the card spent one of its tries, and then a coordinate turned out to be
    wrong. Every one of these is knowable without any of that.
    """
    from firmauy.api import PdfAppearance

    with pytest.raises(ValueError, match="not a valid ImageMode"):
        PdfAppearance(image_mode="watermark")
    with pytest.raises(ValueError, match="between 0 and 1"):
        PdfAppearance(image_opacity=1.5)
    with pytest.raises(ValueError, match="empty or inverted"):
        PdfAppearance(x2=10)                        # x2 below the default x1 of 20
    with pytest.raises(ValueError, match="empty or inverted"):
        PdfAppearance(y1=90, y2=90)                 # zero height, which draws nothing
    # zoneinfo answers an unknown zone with a KeyError, which a caller checking arguments has no
    # reason to expect. Translated, and raised here rather than where the stamp is drawn, which
    # is after the PIN.
    with pytest.raises(ValueError, match="not a valid IANA time zone"):
        PdfAppearance(timezone="Nope/Nowhere")
    with pytest.raises(FileNotFoundError, match="stamp image not found"):
        PdfAppearance(image="/nowhere/logo.png")


def test_an_unusable_stamp_image_is_refused_when_the_appearance_is_built(tmp_path):
    """Existing is not enough: a file that is not an image used to pass here and fail only when
    the stamp was drawn, which is after the PIN."""
    from PIL import Image

    from firmauy.api import PdfAppearance

    bad = tmp_path / "logo.png"
    bad.write_bytes(b"not an image")
    with pytest.raises(ValueError, match="not a usable image"):
        PdfAppearance(image=bad)

    good = tmp_path / "ok.png"
    Image.new("RGB", (8, 8), (1, 2, 3)).save(good)
    PdfAppearance(image=good)


def test_the_appearance_travels_from_sign_to_the_pdf_signer(monkeypatch, tmp_path):
    """sign() routes by content, and the appearance only means something on the PDF branch. This
    holds that it arrives there rather than being dropped on the way, which a default that
    silently works would hide."""
    from firmauy import api

    pdf = tmp_path / "d.pdf"
    pdf.write_bytes(b"%PDF-1.7\n%%EOF\n")
    seen = {}

    def fake(path, pin=None, **kw):
        seen.update(kw)
        return api.SignReport(output_path=path, signer="X", issuer="Y")

    monkeypatch.setattr(api, "sign_pdf", fake)
    wanted = api.PdfAppearance(page=1, show_signer=False)
    api.sign(pdf, "1234", appearance=wanted)

    assert seen["appearance"] is wanted


def test_verify_on_a_pdf_past_the_verify_limit_is_refused_before_the_card(monkeypatch, tmp_path):
    """The API has no channel for the warning the CLI prints, but the refusal reaches it, and
    before the PIN."""
    from firmauy import signing
    from firmauy.api import sign_pdf

    def no_session(**kwargs):
        raise AssertionError("the card was reached")

    monkeypatch.setattr(signing, "_signing_session", no_session)
    monkeypatch.setattr(signing, "MAX_PDF_BYTES", 2000)
    monkeypatch.setattr(signing, "_SIGNED_PDF_HEADROOM", 100)
    big = tmp_path / "big.pdf"
    big.write_bytes(b"%PDF-1.7\n" + b"0" * 1950)

    with pytest.raises(ValueError, match="Sign it without --verify"):
        sign_pdf(big, pin="1234", verify=True)


def test_the_api_forwards_allow_private_network(monkeypatch, tmp_path):
    """verify() hands it to the verifier, sign() to the per-format function, and sign_files() to
    the timestamper, each before any card is touched."""
    import firmauy.api as api
    from firmauy import signing

    seen = {}

    def _spy(*args, **kwargs):
        seen.update(kwargs)
        raise RuntimeError("stop here")

    pdf = tmp_path / "a.pdf"
    pdf.write_bytes(b"%PDF-1.7\n")
    doc = tmp_path / "doc.bin"
    doc.write_bytes(b"contenido")

    monkeypatch.setattr(api, "verify_pdf", _spy)
    with pytest.raises(RuntimeError, match="stop here"):
        api.verify(pdf, no_trust=True, allow_private_network=True)
    assert seen.pop("allow_private_network") is True

    monkeypatch.setattr(api, "sign_file", _spy)
    with pytest.raises(RuntimeError, match="stop here"):
        api.sign(doc, pin="1234", allow_private_network=True)
    assert seen.pop("allow_private_network") is True

    monkeypatch.setattr(signing, "_build_timestamper", _spy)
    with pytest.raises(RuntimeError, match="stop here"):
        api.sign_files([doc], pin="1234", tsa_url="https://tsa.example/tsr",
                       allow_private_network=True)
    assert seen.pop("allow_private_network") is True
