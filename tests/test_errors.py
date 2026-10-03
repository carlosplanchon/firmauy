"""Unit tests for the domain exception hierarchy (firmauy.errors).

The contract under test: every domain error is catchable precisely (for a GUI) and as a family
through ``FirmaUYError``, and none of them is a built-in error type, so catching an unexpected
failure never silently catches an expected domain condition too.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from firmauy.errors import (
    CardNotFoundError,
    CertificateError,
    CertificateNotFoundError,
    CertificateNotValidError,
    FirmaUYError,
    IncorrectPinError,
    OutputAccessControlError,
    OutputCommittedError,
    OutputExistsError,
    PostSignVerificationError,
    PinError,
    PinFormatError,
    PinLastTryError,
    PinLockedError,
    ReaderNotFoundError,
    SigningKeyNotFoundError,
    TokenNotFoundError,
)


def test_every_domain_error_is_a_firmauy_error_and_not_a_builtin_one():
    for cls in (
        ReaderNotFoundError, CardNotFoundError, PinError, IncorrectPinError, PinLockedError,
        PinFormatError, PinLastTryError, TokenNotFoundError, CertificateError, CertificateNotFoundError, CertificateNotValidError,
        SigningKeyNotFoundError, OutputExistsError, OutputAccessControlError,
        OutputCommittedError, PostSignVerificationError,
    ):
        exc = cls("boom")
        assert isinstance(exc, FirmaUYError)
        assert str(exc) == "boom"
        # Domain conditions are expected outcomes, so they must not be catchable as the built-in
        # types used for unexpected failures.
        assert not isinstance(exc, (RuntimeError, ValueError, OSError))


def test_pin_hierarchy():
    for cls in (IncorrectPinError, PinLockedError, PinFormatError, PinLastTryError):
        assert issubclass(cls, PinError)
    assert IncorrectPinError("x").attempts_remaining is None
    assert IncorrectPinError("x", attempts_remaining=2).attempts_remaining == 2


def test_the_two_refusals_are_not_one_another():
    """A typo is fixed by typing again and a card on its last try only by unblocking it. One class
    for both is what had a GUI telling them apart by when its prompt had run."""
    assert not issubclass(PinFormatError, PinLastTryError)
    assert not issubclass(PinLastTryError, PinFormatError)


def test_firmauy_never_raises_a_bare_pin_error():
    """PinError's docstring promises a subclass every time, so a caller can tell the four apart
    without reading the message. A bare one added later would break that quietly, because every
    existing ``except PinError`` would still catch it."""
    src = Path(__file__).resolve().parent.parent / "src" / "firmauy"
    bare = [f"{path.name}:{number}" for path in sorted(src.glob("*.py"))
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
            if re.search(r"\braise PinError\b", line)]
    assert bare == []


def test_certificate_hierarchy():
    for cls in (CertificateNotFoundError, CertificateNotValidError, SigningKeyNotFoundError):
        assert issubclass(cls, CertificateError)


def test_output_exists_carries_the_path(tmp_path):
    exc = OutputExistsError("exists", path=tmp_path / "out.p7s")
    assert exc.path == tmp_path / "out.p7s"


# ---------------------------------------------------------------------------
# Cheap end-to-end mappings (no card, no HSM)
# ---------------------------------------------------------------------------


def test_open_reader_without_readers_raises_reader_not_found(monkeypatch):
    import firmauy.card_reader as card_reader

    monkeypatch.setattr(card_reader, "list_readers", lambda: [])
    with pytest.raises(ReaderNotFoundError, match="No PC/SC readers found"):
        card_reader.open_reader()


def test_open_reader_missing_named_reader_raises_reader_not_found(monkeypatch):
    import firmauy.card_reader as card_reader

    monkeypatch.setattr(card_reader, "list_readers", lambda: ["ACS ACR 38U"])
    with pytest.raises(ReaderNotFoundError, match="not found"):
        card_reader.open_reader("otro lector")


def test_sign_one_cms_existing_output_raises_output_exists(tmp_path):
    from firmauy.signing import _sign_one_cms

    src = tmp_path / "doc.bin"
    src.write_bytes(b"data")
    out = tmp_path / "doc.bin.p7s"
    out.write_bytes(b"old")   # pre-existing output, no overwrite

    # The exists-check fires before the signer is ever used, so a dummy signer suffices.
    with pytest.raises(OutputExistsError, match="already exists") as ei:
        _sign_one_cms(input_file=src, output_p7s=out, pkcs11_signer=object(),
                      timestamper=None, overwrite=False)
    assert ei.value.path == out


# --- a detached .p7s with no original ---------------------------------------

def test_verify_detached_without_an_original_raises_a_typed_error(tmp_path):
    """The two files routinely travel separately by email, so this is a recoverable situation a
    caller has to be able to branch on. It used to be a bare ValueError, which left callers
    matching on the message text."""
    from asn1crypto import cms as asn1cms

    from firmauy.api import DetachedOriginalRequiredError, verify

    # A structurally valid, empty SignedData: enough for the format detection to say "cms" and
    # reach the missing-original check, without needing a real signature.
    p7s = tmp_path / "contrato.pdf.p7s"
    p7s.write_bytes(asn1cms.ContentInfo({
        "content_type": "signed_data",
        "content": asn1cms.SignedData({
            "version": "v1",
            "digest_algorithms": [],
            "encap_content_info": {"content_type": "data"},
            "signer_infos": [],
        }),
    }).dump())

    with pytest.raises(DetachedOriginalRequiredError) as ei:
        verify(p7s)

    assert ei.value.p7s_path == p7s
    assert ei.value.expected == tmp_path / "contrato.pdf"   # where the sibling was looked for


def test_the_detached_error_is_a_firmauy_error_not_a_value_error(tmp_path):
    """It moved out of ValueError deliberately: catching a bad argument should not also catch an
    expected domain condition."""
    from firmauy.api import DetachedOriginalRequiredError, FirmaUYError

    assert issubclass(DetachedOriginalRequiredError, FirmaUYError)
    assert not issubclass(DetachedOriginalRequiredError, ValueError)


# --- a batch that stops halfway ---------------------------------------------

def test_batch_sign_error_carries_what_was_already_signed():
    from firmauy.api import BatchSignError, FirmaUYError

    exc = BatchSignError("stopped", completed=["a", "b"], failed_index=2,
                         failed_path=Path("/tmp/c.pdf"))

    assert isinstance(exc, FirmaUYError)
    assert exc.completed == ["a", "b"]
    assert exc.failed_index == 2
    assert exc.failed_path == Path("/tmp/c.pdf")


def test_batch_sign_error_defaults_to_nothing_completed():
    from firmauy.api import BatchSignError

    exc = BatchSignError("stopped")
    assert exc.completed == []
    assert exc.failed_index == -1
    assert exc.failed_path is None


# --- a batch the caller stopped ---------------------------------------------

def test_cancelling_a_batch_is_not_a_failure():
    """Somebody pressing cancel is not the batch breaking, and a caller reporting "it broke"
    must not catch it by accident."""
    from firmauy.api import BatchSignCancelled, BatchSignError, FirmaUYError

    assert issubclass(BatchSignCancelled, FirmaUYError)
    assert not issubclass(BatchSignCancelled, BatchSignError)
    assert not issubclass(BatchSignError, BatchSignCancelled)


def test_batch_sign_cancelled_carries_what_was_already_signed():
    from firmauy.api import BatchSignCancelled

    exc = BatchSignCancelled("stopped", completed=["a", "b"], stopped_before=2)
    assert exc.completed == ["a", "b"]
    assert exc.stopped_before == 2


def test_batch_sign_cancelled_defaults_to_nothing_done():
    from firmauy.api import BatchSignCancelled

    exc = BatchSignCancelled("stopped")
    assert exc.completed == []
    assert exc.stopped_before == -1


@pytest.mark.parametrize("kwargs,why", [
    ({"outcome": "typo"}, "an outcome nobody named"),
    ({"outcome": "Failed"}, "the right word spelled differently"),
    ({"outcome": "detached-mismatch"}, "a detached mismatch with no second file"),
    ({"outcome": "failed", "covers": "doc.bin"}, "a second file where there is only one"),
    ({"outcome": "inconclusive", "covers": "doc.bin"}, "the same, from the other outcome"),
])
def test_an_impossible_post_sign_state_cannot_be_built(kwargs, why):
    """The field exists so a program can branch without reading prose, which only works if every
    value it can hold is one the contract names. A scan of the literals in the signing module
    cannot see a construction built dynamically, a typo in another module, or a caller raising it
    directly."""
    from firmauy.errors import PostSignVerificationError

    with pytest.raises(ValueError):
        PostSignVerificationError("x", **kwargs)


def test_the_states_the_contract_does_name_all_build():
    from firmauy.errors import PostSignVerificationError

    assert PostSignVerificationError("x", outcome="failed").covers is None
    assert PostSignVerificationError("x", outcome="inconclusive").outcome == "inconclusive"
    detached = PostSignVerificationError("x", outcome="detached-mismatch", covers="doc.bin")
    assert detached.covers == "doc.bin"
    assert set(PostSignVerificationError.OUTCOMES) == {"failed", "detached-mismatch",
                                                       "inconclusive"}
