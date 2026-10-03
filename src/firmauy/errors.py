# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Domain exceptions for firmauy.

They all derive from :class:`FirmaUYError`, so a caller can catch the whole family or a precise
condition::

    from firmauy.api import sign, IncorrectPinError, PinLockedError

    try:
        report = sign(path, pin_provider=ask_pin)
    except IncorrectPinError as exc:
        retry_dialog(attempts=exc.attempts_remaining)   # None when the backend cannot know
    except PinLockedError:
        show_unblock_help()

The hierarchy is intentionally small: only conditions a caller can meaningfully branch on get a
class. Environment problems (pcscd down, PKCS#11 module missing) stay plain ``RuntimeError`` with
actionable messages, and ``run_doctor`` is the structured way to diagnose those. That split is the
point of keeping ``FirmaUYError`` off the built-in error types: an expected domain condition and an
unexpected failure should not be caught by the same ``except``.
"""

from typing import Optional


class FirmaUYError(Exception):
    """Base class for all firmauy domain errors."""


# ---------------------------------------------------------------------------
# Reader / card presence (PC/SC)
# ---------------------------------------------------------------------------


class ReaderNotFoundError(FirmaUYError):
    """No PC/SC reader is available (none connected, or the named reader does not exist)."""


class CardNotFoundError(FirmaUYError):
    """A reader is present but no card answered (not inserted, or not readable)."""


# ---------------------------------------------------------------------------
# PIN
# ---------------------------------------------------------------------------


class PinError(FirmaUYError):
    """Base class for PIN problems (bad format, empty, or the low-retries safety guard)."""


class IncorrectPinError(PinError):
    """The PIN was wrong. ``attempts_remaining`` is the card's remaining tries when the backend
    can know it (the native PC/SC path), or None (the PKCS#11 middleware does not report it)."""

    def __init__(self, message: str, *, attempts_remaining: Optional[int] = None):
        super().__init__(message)
        self.attempts_remaining = attempts_remaining


class PinLockedError(PinError):
    """The PIN is blocked after too many incorrect attempts; the cédula must be unblocked."""


# ---------------------------------------------------------------------------
# Tokens / certificates
# ---------------------------------------------------------------------------


class TokenNotFoundError(FirmaUYError):
    """No PKCS#11 token is available to the module."""


class CertificateError(FirmaUYError):
    """Base class for signing-certificate problems on the card/token."""


class CertificateNotFoundError(CertificateError):
    """No (matching) certificate exists on the token."""


class CertificateNotValidError(CertificateError):
    """The signing certificate is outside its validity window (expired, or not yet valid)."""


class SigningKeyNotFoundError(CertificateError):
    """A certificate exists but has no matching private key to sign with."""


# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------


class OutputExistsError(FirmaUYError):
    """The output file already exists and overwrite was not requested. ``path`` is the output."""

    def __init__(self, message: str, *, path=None):
        super().__init__(message)
        self.path = path


class OutputCommittedError(FirmaUYError):
    """The signature was written and is in place, and something failed afterwards.

    What it says, exactly: the signing routine finished and the final bytes were committed
    atomically, and then one step after that did not. Setting the final permissions is the last
    step and happens *after* the atomic commit, on purpose, so that the document is never readable
    by anyone else until it is in place under its own name. If that step fails the file is complete
    and its bytes are final, and it stayed at ``0600``.

    What it does **not** say is that the signature was checked. The self-check ``verify=True``
    asks for runs after the signing call returns, so this is raised before it, and when it is
    raised that check never happens. See :class:`PostSignVerificationError` for the failures that
    do come from it, which mean something different: one of them says the produced signature is
    not intact, and answering it by repairing a permission bit would be exactly wrong.

    ``path`` is the output, ``final_mode`` the mode it should have been given, and ``errno`` the
    operating system's code for why it could not be. Repair the mode. Signing again would work,
    but it would sign a second time to fix a permission bit.

    A distinct class because "no output was produced" and "the output exists and needs one
    chmod" are opposite instructions to whoever is handling the failure, and telling them apart
    by matching on the text of a message is exactly the thing this module exists to avoid. Not an
    ``OSError`` subclass, following the split described at the top of this file: the cause is
    environmental, but the condition is a domain one that a caller must branch on.

    .. versionadded:: 1.14.0
    """

    def __init__(self, message: str, *, path=None, final_mode: Optional[int] = None,
                 errno: Optional[int] = None):
        super().__init__(message)
        self.path = path
        self.final_mode = final_mode
        self.errno = errno


class PostSignVerificationError(FirmaUYError):
    """The signature was written, and the check that should have confirmed it did not confirm it.

    Signing with ``verify=True`` reads the file back and checks the signature it just made. That
    check runs after the output is in place, so getting this means a file exists at ``path``.
    ``outcome`` says which of three things happened, and they call for different responses:

    - ``"failed"``: the check ran on a self-contained signature, a PDF or a XAdES XML, and
      reported that the produced signature is not intact. There is nothing else it could be. That
      file is not a signature: delete it and sign again.
    - ``"detached-mismatch"``: a detached ``.p7s`` did not verify against the file it covers,
      which is in ``covers``. Two explanations fit and the check cannot tell them apart, because
      it reopened that file by name after signing streamed it: the signature may not be intact, or
      the file may have changed since. **Do not delete and re-sign on this alone.** Re-signing
      would sign whatever that file holds now, which may not be what anybody meant to sign. Find
      out which file was supposed to be covered first.
    - ``"inconclusive"``: the check could not run at all, because the verifier raised or the file
      could not be read back. Nothing is known about the signature, and it may be perfectly good.
      Do not use it, and retry the verification rather than the signing: signing again would put
      a second signature on a document whose first one was never examined.

    Telling those apart matters enough to be a field rather than a sentence. Two of the three say
    do not sign again, for different reasons, and a program should not have to read prose to find
    that out. None of the three puts the file in :attr:`BatchSignError.completed`, which is what
    is finished and can be handed to somebody: all three leave something that cannot.

    .. versionchanged:: 1.14.0
       Was a bare ``RuntimeError`` for the failing case, and whatever the verifier happened to
       raise for the other, which left callers matching on message text to find out that a file
       had been written at all.
    """

    OUTCOMES = ("failed", "detached-mismatch", "inconclusive")

    def __init__(self, message: str, *, path=None, outcome: str = "failed", covers=None):
        # Checked here rather than trusted, because the entire point of the field is that a
        # program branches on it without reading the message. A value nobody named falls through
        # every caller's branches into whatever their else does, and a "detached-mismatch" with
        # no `covers` names no second file for the one outcome whose whole meaning is that a
        # second file is involved. Both are programming errors, and the place to find a
        # programming error is where it is made.
        if outcome not in self.OUTCOMES:
            raise ValueError(
                f"unknown post-sign outcome {outcome!r}; expected one of {self.OUTCOMES}")
        if outcome == "detached-mismatch" and covers is None:
            raise ValueError("a detached-mismatch has to name the file it was checked against")
        if outcome != "detached-mismatch" and covers is not None:
            raise ValueError(f"covers has no meaning for a {outcome!r} outcome")

        super().__init__(message)
        self.path = path
        self.outcome = outcome
        self.covers = covers


class OutputAccessControlError(FirmaUYError):
    """Replacing the output would have changed who can read it. ``path`` is the output.

    Raised before anything is written into place, so the existing file is untouched. A signature
    is written by replacing an inode, and the replacement carries the owner, group and ACL of
    whoever created it rather than of the file it replaces. When those cannot be restored, the
    published document would allow a different set of people than the one it replaced while its
    mode digits read exactly the same. Refusing is the only answer that does not decide that
    silently on the user's behalf.
    """

    def __init__(self, message: str, *, path=None):
        super().__init__(message)
        self.path = path


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------


class DetachedOriginalRequiredError(FirmaUYError):
    """A detached ``.p7s`` was given with no original file to check it against.

    The default follows the ``<x>.p7s -> <x>`` convention; this is raised when that sibling is
    missing and no ``original`` was passed. ``p7s_path`` is the signature and ``expected`` is
    where the original was looked for, so a caller can name the file it needs.

    A recoverable situation rather than a programming error: the two files routinely travel
    separately by email, and the fix is to ask which file the signature covers.

    .. versionadded:: 1.10.0
       Previously a bare ``ValueError``, which left callers matching on the message text.
    """

    def __init__(self, message: str, *, p7s_path=None, expected=None):
        super().__init__(message)
        self.p7s_path = p7s_path
        self.expected = expected


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------


class TimestampError(FirmaUYError):
    """The signature timestamp could not be obtained, and the signature was not written.

    The TSA could not be reached, refused the request, answered with something that is not a
    timestamp, or sent back a token for a different request. The message says which, and the
    exception underneath, when there is one, is ``__cause__``.

    .. versionadded:: 1.19.0
       Previously pyHanko's ``TimestampRequestError``, an ``OSError``, which put a condition a
       caller can act on (fix the TSA URL, try again later) in the same ``except`` as an
       environment failure.
    """


class TimestampDestinationRefusedError(TimestampError):
    """The TSA URL leads to an address the outbound policy refuses, so nothing was sent to it.

    ``host`` is the name in the URL and ``addresses`` what it resolved to. With ``link_local``
    false the address is loopback or private, and ``allow_private_network=True`` reaches it on
    purpose. With ``link_local`` true it is refused even then: that range is where cloud metadata
    services answer, so a caller offering the opt-in for it would offer a dead end.

    .. versionadded:: 1.19.0
    """

    def __init__(self, message: str, *, host: Optional[str] = None, addresses=(),
                 link_local: bool = False):
        super().__init__(message)
        self.host = host
        self.addresses = tuple(addresses)
        self.link_local = link_local


# ---------------------------------------------------------------------------
# Batches
# ---------------------------------------------------------------------------


class BatchSignCancelled(FirmaUYError):
    """The caller asked a batch to stop, and it did, between files.

    ``completed`` holds one :class:`~firmauy.api.SignReport` per file written before the stop, and
    ``stopped_before`` is the index of the first file that was never attempted. Everything in
    ``completed`` is a complete signed output on disk. Whether each was checked is its own
    ``verified`` field, not something this class asserts.

    Deliberately **not** a :class:`BatchSignError`: somebody pressing cancel is not a failure, and
    a caller reporting "it broke" should not catch it by accident. Both carry ``completed``
    because both leave real signatures behind.

    The stop is only ever honoured between files. A signature is written whole or not at all, so
    there is no point at which a half-written output could be left behind.

    .. versionadded:: 1.11.0
    """

    def __init__(self, message: str, *, completed=None, stopped_before: int = -1):
        super().__init__(message)
        self.completed = list(completed or [])
        self.stopped_before = stopped_before


class BatchSignError(FirmaUYError):
    """A batch stopped at one file, carrying what had already been signed.

    ``completed`` holds one :class:`~firmauy.api.SignReport` per finished output,
    ``failed_index`` is the position of the file that broke (0-based, into the input sequence)
    and ``failed_path`` is that file. The underlying failure is chained as ``__cause__``.

    The signatures already written stay on disk on purpose: they are real. Being able to tell the
    user "2 of 7 were signed" instead of only "it failed" is the reason this class exists.

    **The file at ``failed_index`` can itself appear in ``completed``**, whenever the failure came
    after its output was finished: :class:`OutputCommittedError`, where only the final permissions
    could not be set, and a callback raising after the signature was written. So ``len(completed)``
    is not always ``failed_index``.

    ``completed`` is what is finished and can be handed to somebody. That is narrower than every
    file on disk: an output whose self-check failed, or whose self-check could not be completed,
    has been written and is deliberately **not** here, because neither can be used yet.

    It is also narrower than "everything you do not have to redo", so **the work left over is not
    ``paths`` minus ``completed``**. A batch stops at one file, and what that file needs is in
    ``__cause__``, per file and already structured: a
    :class:`PostSignVerificationError` with ``outcome="inconclusive"`` in particular says the
    output exists and must **not** be signed again, only checked. Computing a retry list by
    subtraction would sign it a second time, which is the one thing that error asks you not to do.

    A report being present says the output is finished rather than that it was checked. Read
    ``verified`` per report, and ``__cause__`` for what stopped it.

    ``callback_error`` is what the caller's own ``progress`` or ``should_continue`` callback
    raised, when one did, and None otherwise. Those callbacks are the caller's code and can have
    bugs in them, and whatever they raise used to surface in place of everything else: the reports
    for files already on disk, and the :class:`OutputCommittedError` saying an output exists and
    must not be signed again. A broken progress bar is not a reason to lose that, so the callback's
    failure is carried here instead of replacing the batch's own account. When nothing else went
    wrong it is also ``__cause__``.

    .. versionchanged:: 1.14.0
       ``completed`` can include the failed item, the reports carry a meaningful ``verified``, and
       ``callback_error`` is new. A callback that raises now surfaces as this exception rather
       than on its own.

    .. versionadded:: 1.10.0
    """

    def __init__(self, message: str, *, completed=None, failed_index: int = -1,
                 failed_path=None, callback_error: Optional[BaseException] = None):
        super().__init__(message)
        self.completed = list(completed or [])
        self.failed_index = failed_index
        self.failed_path = failed_path
        self.callback_error = callback_error
