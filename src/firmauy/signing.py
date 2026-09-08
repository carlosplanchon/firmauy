# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Card-signing engine shared by the CLI and the public API.

This module holds the signing machinery (session management, per-format signers,
timestamping and post-sign verification) so both firmauy.cli and firmauy.api build on it,
instead of the public API reaching into the CLI module. It is presentation-free: it never
prints or exits. Warnings and notes are reported through an optional ``notify`` callback
(the CLI passes a stderr printer, the API passes nothing), the identity display fields
travel on the yielded ``_SigningContext`` for the caller to print, and the PIN arrives
directly (``pin``) or lazily (``pin_provider``), never via a prompt of its own."""

import errno
import os
import secrets
import stat
import tempfile
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Callable, List, NamedTuple, Optional
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo
import pkcs11
import pkcs11.exceptions
from cryptography import x509
from pyhanko import stamp
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.layout import (
    AxisAlignment,
    InnerScaling,
    Margins,
    SimpleBoxLayoutRule,
)
from pyhanko.sign import fields, signers
from pyhanko.sign.pkcs11 import PKCS11Signer
from pyhanko.sign.timestamps import HTTPTimeStamper
from firmauy.appearance import ensure_output_parent, make_appearance_pdf
from firmauy.card_reader import (
    open_reader,
    select_applet,
)
from firmauy.cert_utils import (
    cert_not_after,
    cert_not_before,
    get_common_name,
    normalize_issuer_name,
)
from firmauy.errors import (
    CertificateNotValidError,
    IncorrectPinError,
    OutputAccessControlError,
    OutputCommittedError,
    OutputExistsError,
    PostSignVerificationError,
    PinError,
    PinLockedError,
)
from firmauy.constants import (
    DEFAULT_IMAGE_OPACITY,
    DEFAULT_PKCS11_LIB,
    ImageMode,
    SignAs,
    StampCorner,
    StampFields,
)
from firmauy.pkcs11_utils import (
    cert_is_expired,
    cert_not_yet_valid,
    find_token,
    get_private_key,
    load_pkcs11_lib,
    normalize_cert_id_hex,
    select_certificate,
)
from firmauy.pdf_verify import verify_pdf
from firmauy.xml_sign import sign_xml
from firmauy.xml_verify import verify_xml
from firmauy.cms_sign import sign_cms_detached
from firmauy.cms_verify import verify_cms


class _SigningContext:
    """Backend-agnostic context yielded by ``_signing_session``.

    Carries the selected certificate and its display fields, plus lazy factories for the two signer
    shapes the sign-* commands need: a pyHanko ``Signer`` (PDF/CMS) via ``pyhanko_signer()`` and a raw
    bytes->bytes callable (XML) via ``raw_signer()``. The factories are backend-specific (PKCS#11 vs
    native card); each is built at most once, so a PDF-only sign never constructs the XML signer and
    vice-versa, and a batch reuses the one instance across all files.

    ``source_caption`` ("Token" / "Reader"), ``source_display`` (token label / resolved reader name)
    and ``key_id`` (the PKCS#11 object ID, None in native mode) let the caller print the identity
    block; the session itself prints nothing."""

    def __init__(self, *, cert, signer_name, issuer_name, cert_serial,
                 source_caption, source_display, key_id,
                 pyhanko_signer_factory, raw_signer_factory):
        self.cert = cert
        self.signer_name = signer_name
        self.issuer_name = issuer_name
        self.cert_serial = cert_serial
        self.source_caption = source_caption
        self.source_display = source_display
        self.key_id = key_id
        self._pyhanko_signer_factory = pyhanko_signer_factory
        self._raw_signer_factory = raw_signer_factory
        self._pyhanko_signer = None
        self._raw_signer = None

    def pyhanko_signer(self):
        if self._pyhanko_signer is None:
            self._pyhanko_signer = self._pyhanko_signer_factory()
        return self._pyhanko_signer

    def raw_signer(self):
        if self._raw_signer is None:
            self._raw_signer = self._raw_signer_factory()
        return self._raw_signer


def _cert_display_fields(cert) -> tuple:
    """The (signer_name, issuer_name, cert_serial) shown in the identity block, derived the same
    way by both signing backends."""
    return (
        get_common_name(cert.subject),
        normalize_issuer_name(get_common_name(cert.issuer)),
        format(cert.serial_number, "X"),
    )


@contextmanager
def _card_connection(reader_name=None):
    """Open a PC/SC card connection and always disconnect on exit (best-effort), shared by the
    native signing session and fetch-identity / fetch-photo."""
    conn = open_reader(reader_name)
    try:
        yield conn
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass


def _resolve_final_pin(pin, pin_provider) -> str:
    """Resolve the PIN at the point of use (after the PIN-free certificate read, so the card's
    retry-limit guard is preserved): a directly-supplied ``pin``, else the lazy ``pin_provider()``
    callback (the CLI wraps its --pin-source handling in one).

    Rejects anything the cédula cannot accept, before it can reach the card. A wrong PIN is not
    free: it spends one of a handful of tries and enough of them block the card, so a typo that
    puts a letter in the string is worth catching here rather than at the price of an attempt.

    Both backends come through this function, which is why the check lives here and not in either
    one. The native path checked the length and the encoding and let letters through, while
    telling the user in the same breath that a PIN must be digits.
    """
    if pin is None and pin_provider is None:
        raise RuntimeError("no PIN was supplied: pass pin= or pin_provider=")
    final = pin if pin is not None else pin_provider()
    if not final:
        raise PinError(
            "Empty PIN received; aborting before contacting the card "
            "(an empty PIN would still count toward its retry limit)."
        )
    # isascii() as well as isdigit(): the latter is true for '٤' and '④', which the card would
    # never accept and which encoding to ASCII would reject one layer down, after the guard.
    if not (final.isascii() and final.isdigit()):
        raise PinError(
            "The cédula's PIN is digits only; aborting before contacting the card "
            "(a wrong PIN would still count toward its retry limit)."
        )
    if not 4 <= len(final) <= 8:
        raise PinError(
            f"The cédula's PIN is 4 to 8 digits, got {len(final)}; aborting before contacting "
            "the card (a wrong PIN would still count toward its retry limit)."
        )
    return final


@contextmanager
def _signing_session(*, native, reader, pkcs11_lib, token_label, cert_id, pin=None,
                     pin_provider=None, notify: Optional[Callable[[str], None]] = None):
    """Open a signing session with the selected backend and yield a ``_SigningContext``.

    Dispatches to the native PC/SC backend (``--native``) or the PKCS#11 backend. Both select the
    signing certificate and expose the same signer factories plus the identity display fields, so
    every sign-* command (single and batch) stays backend-agnostic; printing the identity block is
    the caller's job. Callers keep their own (fail-fast, pre-PIN) validation and timestamper build.

    The PIN arrives as ``pin`` (direct) or ``pin_provider`` (a zero-arg callable invoked only after
    the PIN-free certificate read, preserving the card's retry-limit guard). ``notify``, when given,
    receives the informational lines as they occur (backend-option notes pre-flight, then the
    certificate-selection warnings); without it they are dropped. The --cert-id/--native hard error
    is always raised."""
    _check_backend_options(
        native=native, reader=reader, pkcs11_lib=pkcs11_lib, token_label=token_label,
        cert_id=cert_id, notify=notify,
    )
    if native:
        with _native_signing_session(reader=reader, pin=pin, pin_provider=pin_provider) as ctx:
            yield ctx
    else:
        with _pkcs11_signing_session(
            pkcs11_lib=pkcs11_lib, token_label=token_label, cert_id=cert_id, pin=pin,
            pin_provider=pin_provider, notify=notify,
        ) as ctx:
            yield ctx


@contextmanager
def _pkcs11_signing_session(*, pkcs11_lib, token_label, cert_id, pin=None, pin_provider=None,
                            notify: Optional[Callable[[str], None]] = None):
    """PKCS#11 backend: load the module, open a PIN session, select the signing certificate and
    yield the context (display fields included, nothing printed). The session is closed on exit.
    ``notify`` receives the certificate-selection warnings (skipped candidates)."""
    # Validate the hex cert ID up front: a malformed --cert-id must fail before the PIN is obtained
    # (an incorrect PIN counts toward the card's retry limit), not later inside select_certificate.
    if cert_id is not None:
        normalize_cert_id_hex(cert_id)
    lib = load_pkcs11_lib(pkcs11_lib)
    token = find_token(lib, token_label)
    final_pin = _resolve_final_pin(pin, pin_provider)
    # Translate the middleware's PIN exceptions into the domain ones (same messages the CLI's
    # _format_error historically produced), so API consumers can catch IncorrectPinError /
    # PinLockedError regardless of backend. The middleware does not report remaining attempts.
    try:
        with token.open(user_pin=final_pin) as session:
            key_id, cert = select_certificate(session, cert_id, notify=notify)
            signer_name, issuer_name, cert_serial = _cert_display_fields(cert)
            yield _SigningContext(
                cert=cert, signer_name=signer_name, issuer_name=issuer_name,
                cert_serial=cert_serial,
                source_caption="Token",
                source_display=(getattr(token, "label", "") or "").strip() or "<no label>",
                key_id=key_id,
                pyhanko_signer_factory=lambda: PKCS11Signer(
                    pkcs11_session=session, cert_id=key_id, key_id=key_id),
                raw_signer_factory=lambda: _make_raw_signer(session, key_id),
            )
    except pkcs11.exceptions.PinIncorrect as exc:
        raise IncorrectPinError("Incorrect PIN.") from exc
    except pkcs11.exceptions.PinLocked as exc:
        raise PinLockedError("The PIN is locked (too many incorrect attempts).") from exc


@contextmanager
def _native_signing_session(*, reader, pin=None, pin_provider=None):
    """Native PC/SC backend: open the reader, select the applet, read the public signing certificate,
    verify the PIN and yield the context (display fields included, nothing printed). No PKCS#11
    module is loaded. The connection is closed on exit. Do not run while a PKCS#11 sign session is
    open on the same card: both go through pcscd and will conflict.

    The PIN (direct ``pin`` or lazy ``pin_provider``) is obtained only after the PIN-free
    certificate read, preserving the retry-limit guard."""
    from firmauy import native_card
    with _card_connection(reader) as conn:
        select_applet(conn)
        cert = native_card.read_signing_certificate(conn)
        # Same validity guard the PKCS#11 path gets from select_certificate: never sign with an
        # expired / not-yet-valid certificate, and fail before the PIN is obtained.
        if cert_is_expired(cert) or cert_not_yet_valid(cert):
            if cert_is_expired(cert):
                reason = f"expired (valid until {cert_not_after(cert)})"
            else:
                reason = f"not yet valid (valid from {cert_not_before(cert)})"
            raise CertificateNotValidError(
                f"The card's signing certificate is {reason}: {get_common_name(cert.subject)}"
            )
        signer_name, issuer_name, cert_serial = _cert_display_fields(cert)
        # Obtain the PIN only after the (PIN-free) cert read succeeds, so a reader/card problem
        # surfaces before the PIN is requested. verify_pin refuses to spend the card's last retry.
        final_pin = _resolve_final_pin(pin, pin_provider)
        native_card.verify_pin(conn, final_pin)
        # The pyHanko signer is built lazily through the factory (honoring _SigningContext's
        # contract: an XML-only sign never constructs it, nor loads the bundled trust anchors).
        sig_len = (cert.public_key().key_size + 7) // 8   # expected RSA signature size (256)
        yield _SigningContext(
            cert=cert, signer_name=signer_name, issuer_name=issuer_name, cert_serial=cert_serial,
            # The reader name pyscard resolved, so the identity block records the actual device
            # even when it was auto-detected rather than passed via ``reader``.
            source_caption="Reader", source_display=conn.getReader(), key_id=None,
            pyhanko_signer_factory=lambda: native_card.make_native_signer(conn, cert),
            raw_signer_factory=lambda: (
                lambda data: native_card.sign_message(conn, data, expected_len=sig_len)),
        )


# Retries on a name collision. With 64 random bits a collision is not a real event; the loop
# is here so an exhausted namespace fails loudly instead of spinning.
_STAGING_ATTEMPTS = 8

_SENSITIVE_HEADERS = frozenset({
    "authorization", "proxy-authorization", "x-api-key", "api-key", "x-auth-token", "x-auth",
})


class _NoRedirectTimeStamper(HTTPTimeStamper):
    """A timestamper that refuses to follow redirects.

    pyHanko's ``HTTPTimeStamper`` posts with requests' default, which follows them. requests drops
    ``Authorization`` when a redirect downgrades https to http, and keeps every other header, so a
    TSA answering 302 could walk an ``X-Api-Key`` from --tsa-header-env straight into plaintext.
    Checking the scheme of the URL the user gave does not help: by the time the final URL is
    known, the secret has already been sent to it.

    Refused for every request, not only credentialed ones. RFC 3161 is a POST to a fixed endpoint,
    a TSA that redirects is doing something unusual, and following a POST redirect is precisely
    how a request ends up somewhere nobody named. A real relocation is worth a config change, not
    a silent hop.

    Overriding this means restating the parent's body, which is a maintenance cost taken
    deliberately: the alternative is leaving the guarantee to a default we do not control.
    """

    _MAX_RESPONSE_BYTES = 4 * 1024 * 1024

    async def async_request_tsa_response(self, req):
        from asyncio import to_thread

        import requests
        from asn1crypto import tsp
        from pyhanko.sign.timestamps.common_utils import TimestampRequestError

        def task():
            try:
                raw_res = requests.post(
                    self.url,
                    req.dump(),
                    headers=self.request_headers(),
                    auth=self.auth,
                    timeout=self.timeout,
                    allow_redirects=False,
                    stream=True,
                )
            except OSError as exc:
                raise TimestampRequestError(
                    "Error in communication with timestamp server",
                ) from exc
            if raw_res.is_redirect or raw_res.is_permanent_redirect:
                raise TimestampRequestError(
                    f"The timestamp server answered {raw_res.status_code} (a redirect) instead of "
                    "a timestamp. Refusing to follow it: a redirect can carry request headers, "
                    "credentials among them, to a destination nobody asked for, and can downgrade "
                    "to plain HTTP on the way. Point --tsa-url at the endpoint directly."
                )
            if raw_res.headers.get("Content-Type") != "application/timestamp-reply":
                raise TimestampRequestError(
                    "Timestamp server response is malformed.", raw_res
                )
            content_length = raw_res.headers.get("Content-Length")
            if content_length is not None:
                try:
                    declared_length = int(content_length)
                except ValueError:
                    raise TimestampRequestError(
                        "Timestamp server response has an invalid Content-Length."
                    ) from None
                if declared_length > self._MAX_RESPONSE_BYTES:
                    raise TimestampRequestError(
                        f"Timestamp server response exceeds the {self._MAX_RESPONSE_BYTES} byte "
                        "limit; refusing to parse it."
                    )
            body = bytearray()
            for chunk in raw_res.iter_content(chunk_size=64 * 1024):
                body.extend(chunk)
                if len(body) > self._MAX_RESPONSE_BYTES:
                    raise TimestampRequestError(
                        f"Timestamp server response exceeds the {self._MAX_RESPONSE_BYTES} byte "
                        "limit; refusing to parse it."
                    )
            return tsp.TimeStampResp.load(bytes(body))

        return await to_thread(task)


def _build_timestamper(
    *,
    tsa_url: Optional[str],
    tsa_user: Optional[str],
    tsa_pass_env: Optional[str],
    tsa_header: Optional[List[str]],
    tsa_header_env: Optional[List[str]],
    notify: Optional[Callable[[str], None]] = None,
):
    """Build an HTTPTimeStamper from the TSA options, or None when no --tsa-url is given.

    Supports HTTP Basic auth (``--tsa-user`` + ``--tsa-pass-env``) and arbitrary extra headers for
    credentialed RFC 3161 TSAs. A header value may be literal (``--tsa-header 'Name: Value'``) or,
    for a secret, read from an environment variable (``--tsa-header-env 'Name: ENV_VAR'``) so it
    never appears in argv. Passwords/secrets are never taken on the command line. Raises
    ``ValueError`` on inconsistent options. ``notify``, when given, receives the argv-visibility
    warning for a literal header whose name looks like a credential (a CLI-only concern)."""
    if tsa_url is None:
        if tsa_user or tsa_pass_env or tsa_header or tsa_header_env:
            raise ValueError(
                "--tsa-user / --tsa-pass-env / --tsa-header / --tsa-header-env require --tsa-url."
            )
        return None

    auth = None
    if tsa_user or tsa_pass_env:
        if not (tsa_user and tsa_pass_env):
            raise ValueError(
                "HTTP Basic auth for the TSA needs both --tsa-user and --tsa-pass-env."
            )
        password = os.environ.get(tsa_pass_env)
        if password is None:
            raise ValueError(
                f"Environment variable '{tsa_pass_env}' (from --tsa-pass-env) is not set."
            )
        auth = (tsa_user, password)

    headers: dict = {}
    # Literal headers: the value is on the command line. Warn if one looks like a credential.
    for item in (tsa_header or []):
        name, sep, value = item.partition(":")
        if not sep or not name.strip():
            raise ValueError(
                f"--tsa-header '{item}' must be in 'Name: Value' format."
            )
        nm = name.strip()
        if nm.lower() in _SENSITIVE_HEADERS and notify:
            notify(
                f"Warning: the value of --tsa-header '{nm}' is visible in the process list (argv). "
                "Use --tsa-header-env to read it from an environment variable instead."
            )
        headers[nm] = value.strip()
    # Env-backed headers: the value is read from an environment variable, kept off argv.
    for item in (tsa_header_env or []):
        name, sep, env_var = item.partition(":")
        if not sep or not name.strip() or not env_var.strip():
            raise ValueError(
                f"--tsa-header-env '{item}' must be in 'Name: ENV_VAR' format."
            )
        val = os.environ.get(env_var.strip())
        if val is None:
            raise ValueError(
                f"Environment variable '{env_var.strip()}' "
                f"(from --tsa-header-env '{name.strip()}') is not set."
            )
        headers[name.strip()] = val

    # Credentials require TLS. An anonymous timestamp over http is a defensible choice: the token
    # is signed, so a passive observer learns a hash and can change nothing. A subscriber password
    # or an API key over http is a different matter, because it travels in the clear to whoever is
    # on the path and is reusable once taken. Refused rather than warned about, since a warning
    # scrolls past and the credential is already spent by then.
    #
    # The URL is parsed rather than searched for a flag, because credentials do not only arrive
    # through the flags: `http://user:pass@tsa/` carries them in the authority and reaches
    # requests exactly the same way, so a check that only looked at `auth` and `headers` waved it
    # through. A secret hidden in a query parameter cannot be told apart from any other parameter
    # and is not covered; that limit is documented beside --tsa-url.
    split = urlsplit(tsa_url)

    # Rejected here rather than several layers down inside requests, where the same mistake comes
    # back as a connection error that names neither the option nor the fix.
    if split.scheme.lower() not in ("http", "https"):
        raise ValueError(
            f"--tsa-url must be an http:// or https:// URL, got {tsa_url!r}. An RFC 3161 TSA "
            "speaks HTTP."
        )
    if not split.hostname:
        raise ValueError(f"--tsa-url has no host: {tsa_url!r}.")

    # Credentials in the URL are refused outright, https or not. TLS would protect them in
    # transit and nothing protects them at rest: a URL passed on the command line is in argv, in
    # /proc, in the shell history and in whatever logs the shell or CI keeps. That is the exact
    # exposure --tsa-pass-env and --tsa-header-env exist to avoid, and this module already
    # promises above that passwords are never taken on the command line. Half-keeping a promise
    # is worse than not making it.
    #
    # ``is not None`` and not a truth test: `https://:@host/` parses to empty strings rather than
    # None, which is userinfo all the same and which a truth test waves through.
    if split.username is not None or split.password is not None:
        raise ValueError(
            "Refusing a TSA URL with credentials in it: a URL on the command line lands in argv, "
            "/proc and the shell history, where TLS does not reach. Use --tsa-user with "
            "--tsa-pass-env, or --tsa-header-env, which read the secret from the environment."
        )

    if (auth or headers) and split.scheme.lower() != "https":
        raise ValueError(
            "Refusing to send TSA credentials over an unencrypted connection. Use an https:// "
            "TSA URL, or drop --tsa-user / --tsa-pass-env / --tsa-header / --tsa-header-env to "
            "request an anonymous timestamp."
        )

    return _NoRedirectTimeStamper(tsa_url, auth=auth, headers=headers or None)


def _check_backend_options(*, native, reader, pkcs11_lib, token_label, cert_id,
                           notify: Optional[Callable[[str], None]] = None) -> None:
    """Pre-flight (before any reader or PIN access): reject or warn about options that don't apply
    to the chosen backend.

    --cert-id is an identity-pinning guarantee ("sign only with this certificate") that the native
    backend cannot honor -- the card exposes a single signing certificate (EF B001) and there are no
    PKCS#11 object IDs to match -- so combining it with --native is a hard error, not a silently
    weakened warning. --pkcs11-lib/--token-label are harmless in native mode and only warn, and the
    pcscd single-card caveat applies (same wording as fetch-identity). --reader only applies to the
    native backend, so it is a no-op with PKCS#11.

    The informational notes go to ``notify`` (the CLI passes a stderr printer; the public API passes
    nothing and they are dropped); the --cert-id/--native hard error is always raised."""
    if native:
        if cert_id is not None:
            raise RuntimeError(
                "--cert-id cannot be used with --native: it pins the signing identity by PKCS#11 "
                "object ID, and the native backend always signs with the card's single signing "
                "certificate (EF B001). Drop --cert-id, or use the PKCS#11 backend to select a "
                "certificate by ID."
            )
        if notify is None:
            return
        ignored = [
            name for name, changed in (
                ("--pkcs11-lib", pkcs11_lib != DEFAULT_PKCS11_LIB),
                ("--token-label", token_label is not None),
            ) if changed
        ]
        if ignored:
            notify(
                f"Note: {', '.join(ignored)} {'is' if len(ignored) == 1 else 'are'} ignored with "
                "--native (no PKCS#11 module is used)."
            )
        notify(
            "Note: --native talks to the card over PC/SC; do not run while a PKCS#11 session (other "
            "sign-* invocations) is active on the same card -- both go through pcscd and may conflict."
        )
    elif reader is not None and notify is not None:
        notify(
            "Note: --reader only applies to --native; it is ignored with the PKCS#11 backend."
        )


def _open_staging(path: Path):
    """Create a private, unpredictably named staging file beside ``path``: ``(fd, Path)``.

    Not ``tempfile.mkstemp``, and the difference is the mode. mkstemp creates at 0600, which
    ``os.replace`` would then impose on every signed document, so restoring the ordinary
    permissions meant reading the umask, and reading it means setting it: ``os.umask(0)`` followed
    by putting it back. That mutates process-global state for an instant, and any other thread
    creating a file in that instant gets it wide open. firmauy starts no threads, but it is a
    library and can be called from a program that does.

    Passing the mode to ``os.open`` instead lets the kernel apply the umask atomically, which is
    what an ordinary create does and what the plain ``write_bytes`` this replaced produced. No
    global state is touched and there is no window to lose.

    ``O_EXCL`` is the other half: it refuses to open anything that already exists, symlink
    included. The predictable ``<name>.part`` this replaces was a target, since ``os.replace``
    guards the destination and the staging path had no guard at all.

    The name does not embed the output's, which would be friendlier to read in a stray leftover
    and costs too much: it added 23 bytes to a basename that may already be near the filesystem's
    limit, so a perfectly legal 233-byte output name failed with ENAMETOOLONG on a path that could
    hold 255. A fixed-length name signs anything the filesystem can name.
    """
    for _ in range(_STAGING_ATTEMPTS):
        tmp = path.with_name(f".firmauy-{secrets.token_hex(8)}.part")
        try:
            return os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666), tmp
        except FileExistsError:
            continue
    raise OSError(f"could not create a staging file next to {path}")


# The POSIX access ACL, as the kernel exposes it to getxattr/setxattr.
_ACL_XATTR = "system.posix_acl_access"

# Three outcomes, kept apart. Collapsing them into None left "the file had no ACL", "this
# filesystem has no ACLs" and "reading the ACL failed" indistinguishable, and only the first two
# say anything about what should be restored.
_ACL_ABSENT = "absent"
_ACL_UNSUPPORTED = "unsupported"

# errno for "no such attribute". Linux says ENODATA, the BSDs ENOATTR, and Python only defines the
# second where the platform has it.
_NO_SUCH_ATTR = {errno.ENODATA, getattr(errno, "ENOATTR", errno.ENODATA)}
_NO_ACL_SUPPORT = {errno.ENOTSUP, errno.EOPNOTSUPP}


class _Replaced(NamedTuple):
    """What a regular file being replaced should hand to the file replacing it."""

    mode: int
    uid: int
    gid: int
    acl: object                 # bytes, _ACL_ABSENT or _ACL_UNSUPPORTED


# Something is at the path, but not a file whose access control could be adopted: a symlink
# (ELOOP, and EMLINK where a BSD reports O_NOFOLLOW that way) or a device with nothing behind it.
# The same answer a directory or a FIFO gets from the S_ISREG check below, reached earlier.
_NOT_ADOPTABLE = {errno.ELOOP, getattr(errno, "EMLINK", errno.ELOOP), errno.ENXIO, errno.ENODEV}


class _Moved(Exception):
    """Internal. The file's own access control was rewritten while it was being read, or the path
    stopped pointing at it. Nothing read is usable, and :func:`_adopt_replaced` starts over."""


def _unreadable(path: Path, exc: OSError) -> OutputAccessControlError:
    """The one sentence every failure to read the replaced file's access control ends in."""
    return OutputAccessControlError(
        f"Could not read the access control of {path.name} ({exc.strerror}), so replacing it "
        "could publish a document readable by a different set of people. Nothing was changed.",
        path=path,
    )


def _capture_replaced(path: Path) -> Optional[_Replaced]:
    """The access control of the file about to be replaced, or None when there is no such file.

    **Read through a descriptor, not a pathname.** A pathname is a lookup, not a handle: ask twice
    and the answers can describe two different files, and mode from one with an ACL from another
    published a document at 0644 over a file that was 0600 (measured). Two lookups cannot be made
    safe by comparing them either, because an entry taken away and put back leaves the comparison
    equal. That was the previous design, and it leaned on ``rename`` rewriting the inode's ctime,
    which POSIX explicitly declines to require: "Some implementations mark for update the last
    file status change timestamp of renamed files and some do not." Opening once and reading
    everything from that descriptor makes the question moot rather than unlikely.

    Opened ``O_NOFOLLOW`` because a symlink planted at the output is not the file being replaced
    and has nothing to say about what the result should allow, and ``O_NONBLOCK`` because opening
    a FIFO for reading otherwise waits for a writer that never comes, hanging the signature at the
    commit. Anything not a regular file is nothing to preserve.

    The price is read permission, which replacing a file never needed, so a file whose own owner
    has made it unreadable now fails instead of being overwritten. That is the trade taken
    knowingly: refusing is recoverable with one ``chmod`` and says what happened, while the
    alternative publishes access control assembled from two files and says nothing.

    An unreadable ACL is an error rather than an assumption. Guessing "absent" there would restore
    absence onto a file that may have had one, which is a decision about who may read a document
    and not a detail to paper over.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno in _NOT_ADOPTABLE:
            return None
        failure = _unreadable(path, exc)
        if exc.errno in (errno.EACCES, errno.EPERM):
            failure.args = (f"{failure.args[0]} If the file is yours and simply unreadable, "
                            "`chmod u+r` it and sign again.",)
        raise failure from exc

    try:
        return _read_replaced(fd, path)
    finally:
        os.close(fd)


def _read_replaced(fd: int, path: Path) -> Optional[_Replaced]:
    """Everything :class:`_Replaced` holds, off one open descriptor, or None for nothing to adopt.

    Bracketed by two ``fstat`` calls on that same descriptor. They cannot land on different files,
    so the only thing they can disagree about is this file's own access control being rewritten
    mid-read, and ctime is what shows that. Unlike the ``rename`` case this design used to lean
    on, POSIX does require ``chmod`` and ``chown`` to mark it for update, but a timestamp is still
    only as sharp as the filesystem storing it: what this catches is an ordinary concurrent change,
    subject to that resolution.

    So the limit worth stating plainly. The descriptor guarantees that owner, group, mode and ACL
    describe one inode. It is not an atomic snapshot of that inode against somebody already
    entitled to rewrite its access control: change the ACL, let it be read, change it back, and
    where the clock cannot separate the two the read stands. Reading the ACL a second time would
    catch more accidents and still not close that, because it is the same shape of race one syscall
    further along. POSIX offers no atomic read of stat and ACL together, so this is where the line
    is, and it is drawn rather than papered over.

    Then, still holding the descriptor, the path must lead back to this inode. Otherwise what was
    read is a perfectly coherent description of a file that is no longer the one being replaced.

    Every syscall here is wrapped, because a caller catching :class:`OutputAccessControlError` is
    entitled to the same answer whether the access control could not be read or could not be
    trusted. Failing closed while escaping as a bare ``OSError`` is still a broken contract.
    """
    try:
        current = os.fstat(fd)
    except OSError as exc:
        raise _unreadable(path, exc) from exc
    if not stat.S_ISREG(current.st_mode):
        return None

    try:
        acl = os.getxattr(fd, _ACL_XATTR)
    except AttributeError:
        acl = _ACL_UNSUPPORTED          # no xattr API on this platform at all
    except OSError as exc:
        if exc.errno in _NO_SUCH_ATTR:
            acl = _ACL_ABSENT
        elif exc.errno in _NO_ACL_SUPPORT:
            acl = _ACL_UNSUPPORTED
        else:
            raise _unreadable(path, exc) from exc

    try:
        again = os.fstat(fd)
    except OSError as exc:
        raise _unreadable(path, exc) from exc
    if (again.st_ctime_ns, again.st_mode, again.st_uid, again.st_gid) != (
            current.st_ctime_ns, current.st_mode, current.st_uid, current.st_gid):
        raise _Moved

    try:
        entry = path.lstat()
    except FileNotFoundError:
        raise _Moved from None
    except OSError as exc:
        raise _unreadable(path, exc) from exc
    if (entry.st_dev, entry.st_ino) != (current.st_dev, current.st_ino):
        raise _Moved

    return _Replaced(mode=stat.S_IMODE(current.st_mode) & 0o777,
                     uid=current.st_uid, gid=current.st_gid, acl=acl)


def _restore_replaced(fd: int, replaced: _Replaced, path: Path) -> None:
    """Carry the replaced file's access control onto the descriptor that will replace it.

    An atomic replace swaps an *inode*, not the bytes inside one, so everything the old inode
    carried is gone unless it is put back. Mode alone is not that: a file can read 0640 before and
    after and still be readable by different people, because the owner or group changed, or
    because the new inode inherited a default ACL from the directory that the old one never had.
    All three were measured, all three widened access silently, and all three look identical to
    ``stat``.

    **Every failure here aborts.** This runs before the commit, so raising unlinks the staging
    file and leaves the existing one exactly as it was: nothing is published with access controls
    that do not match what it replaced. Swallowing them and carrying on was worse than not trying,
    because it produced a document whose mode digits looked preserved while the people they
    applied to had changed.

    What is deliberately not carried: ``user.*`` attributes, capabilities and ``security.*``. A
    blanket ``copystat`` would move all of them, and quietly transplanting a capability or a
    security label onto a document this program just produced is not something anybody asked for.
    Preserving nothing there is a decision, and this is where it is written down.
    """
    try:
        os.fchown(fd, replaced.uid, replaced.gid)
    except AttributeError:
        pass                            # a platform without POSIX ownership
    except OSError as exc:
        raise OutputAccessControlError(
            f"{path.name} belongs to uid {replaced.uid} / gid {replaced.gid} and this process "
            f"cannot give the replacement the same ({exc.strerror}). Its mode would have been "
            "restored onto a different owner or group, which changes who can read it. Nothing "
            "was changed. Write to a path you own, or adjust the ownership first.",
            path=path,
        ) from exc

    if replaced.acl is _ACL_UNSUPPORTED:
        return                          # nothing to restore, nothing could have been inherited

    try:
        if replaced.acl is _ACL_ABSENT:
            os.removexattr(fd, _ACL_XATTR)
        else:
            os.setxattr(fd, _ACL_XATTR, replaced.acl)
    except AttributeError:
        pass
    except OSError as exc:
        if replaced.acl is _ACL_ABSENT and exc.errno in _NO_SUCH_ATTR:
            return                      # the ordinary case: nothing was inherited to remove
        raise OutputAccessControlError(
            f"Could not give the replacement for {path.name} the same ACL it had "
            f"({exc.strerror}), so publishing it could allow a different set of people. Nothing "
            "was changed.",
            path=path,
        ) from exc


# How many times to start over when the file moves mid-read. Each attempt is a handful of
# syscalls, so this is not a spin loop: it is there so an ordinary concurrent write does not cost
# a signature, and it gives up rather than chasing something that keeps rewriting the path.
_ADOPT_ATTEMPTS = 4


def _adopt_replaced(fd: int, path: Path) -> Optional[_Replaced]:
    """Carry the access control at *path* onto *fd*, or return None when there is nothing to carry.

    Two responsibilities, and keeping them apart is the point. :func:`_capture_replaced` decides
    what should be adopted and refuses to answer at all if it could not read it coherently. This
    decides what to do when it refuses, which is to start over, a bounded number of times, and
    then give up rather than publish.

    **A discarded attempt leaves the staging file untouched.** Nothing is applied until a capture
    has been accepted. Restoring inside the loop was measured leaking across attempts: the first
    attempt copied an ACL granting a third party read access, the file then vanished, the second
    attempt found nothing to preserve and so restored nothing, and the ACL from the discarded
    attempt was published on a file that never had one. Restoring overwrites owner, group and ACL,
    so any accepted attempt covers what an earlier one did, but the attempt that captures nothing
    has nothing to overwrite it with, which was the whole bug.

    A refused capture now raises rather than returning something to inspect, so the ordering here
    is no longer what prevents that. Kept anyway: an invariant worth having is worth not resting
    on one exception type staying an exception.

    What stays open is the gap between the accepted capture and the commit, a few syscalls wide.
    Closing that needs cooperative locking, which a program writing to a path the user chose is in
    no position to demand of whoever else writes there.
    """
    for _ in range(_ADOPT_ATTEMPTS):
        try:
            replaced = _capture_replaced(path)
        except _Moved:
            continue
        break
    else:
        raise OutputAccessControlError(
            f"{path.name} kept changing while its access control was being read, so the signature "
            "would have carried permissions belonging to a file that is no longer there. Nothing "
            "was changed.",
            path=path,
        )

    if replaced is not None:
        _restore_replaced(fd, replaced, path)
    return replaced


# What the kernel answers when a filesystem cannot make a hard link. Linux says EPERM for FAT32
# and exFAT, which keep no link count at all, and a network or FUSE mount may say ENOTSUP or
# EOPNOTSUPP (one value on Linux, two names) instead.
_NO_HARD_LINKS = {errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP}


def _no_clobber_refusal(path: Path) -> OutputExistsError:
    return OutputExistsError(
        f"{path.name} appeared while the signature was being made. Not overwriting it. Use "
        "--overwrite if that is what you want.",
        path=path,
    )


def _commit_without_clobber(tmp: Path, path: Path) -> None:
    """Put the staging file at ``path`` without replacing anything already there.

    ``os.link`` is the commit that needs no second step: the name is taken in one syscall or not
    at all, so nothing can appear at ``path`` between a check and the write. It is also the
    commit a FAT32 or exFAT stick cannot make. Those filesystems have no hard links, the kernel
    answers EPERM, and a pendrive is an ordinary place to sign a document to. That answer used to
    reach the user as a bare "Operation not permitted", after the PIN had been typed and the card
    had signed, and nothing but ``--overwrite`` got past it.

    On that errno, and on nothing else, the name is reserved with an exclusive create and the
    staging file is renamed over the reservation. The reservation keeps the property that
    matters, which is that a file already at ``path`` is never destroyed: the exclusive create
    refuses anything present, a dangling symlink included, exactly as the link did. What it
    cannot keep is the single syscall. Between the reservation and the rename, an entry swapped
    into ``path`` would be renamed over. That window is one syscall wide, open only to somebody
    who can already write to the directory, and on FAT there is no symlink to plant in it. The
    same limit the replacing commit states: on a shared directory, want the sticky bit.

    Anything else ``os.link`` raises is a different problem and propagates as it is. EPERM is not
    only "no hard links here", it is also an immutable directory, and there the fallback fails on
    the same directory with the same errno, which is the right answer either way.
    """
    try:
        os.link(tmp, path)
    except FileExistsError:
        raise _no_clobber_refusal(path) from None
    except OSError as exc:
        if exc.errno not in _NO_HARD_LINKS:
            raise
    else:
        tmp.unlink(missing_ok=True)
        return

    try:
        reservation = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    except FileExistsError:
        raise _no_clobber_refusal(path) from None
    try:
        os.replace(tmp, path)
    except BaseException:
        # An empty file under the output's name would make the next attempt refuse to sign over
        # it, and could pass for the document. It goes, but only while it is still the file that
        # was reserved: anything else at that name is not this function's to remove.
        try:
            if os.path.samestat(os.fstat(reservation), os.stat(path)):
                os.unlink(path)
        except OSError:
            pass
        raise
    finally:
        os.close(reservation)


@contextmanager
def _staged_output(path: Path, *, overwrite: bool = True):
    """Yield an open file beside ``path``, then atomically move it into place.

    Four properties, each against a different failure.

    **Private while it holds data.** The staging file is created 0666 so the kernel applies the
    umask, that mode is read straight back off the descriptor, and the file is then narrowed to
    0600 before a single byte is written. Only at commit does it get the mode the result should
    carry. Without that narrowing the staging file sat at 0644 for the whole signing operation
    while holding, for a PDF, essentially the entire document: unpredictable names stop somebody
    planting a file there, and do nothing about somebody watching the directory and reading one.
    On a filesystem with no permission bits of its own, FAT32 and exFAT among them, the kernel
    accepts the chmod and changes nothing, so there the staging file is exactly as private as
    the directory it sits in, which is what everything else on that medium is too.

    **Atomic, and not through a symlink.** Both commits put a fully written file in place in one
    step and neither writes through a link pre-created at ``path``: ``os.replace`` puts the file
    where the symlink was, and ``os.link`` refuses outright because the name is taken. A crash or
    an exception part-way never leaves a truncated file at ``path``. The staging file is fsynced
    before the commit, so the bytes are on the medium before the name points at them, though
    durability of the directory entry itself would need the directory fsynced too and is not
    promised here. Same directory on purpose: neither call is atomic across filesystems, and a
    temp directory elsewhere would silently become a copy.

    **No clobber unless asked.** With ``overwrite=False`` the commit is ``os.link``, which fails
    with ``FileExistsError`` if anything is already there. The callers' early ``path.exists()``
    check is for a clear message before the card is touched; it cannot be the guarantee, because
    reading a certificate, entering a PIN and reaching a TSA all happen between it and the write,
    and anything appearing in that window used to be destroyed silently. ``os.link`` also refuses
    a dangling symlink, which ``exists()`` reports as absent. Where the filesystem cannot make a
    hard link at all, the commit reserves the name instead: :func:`_commit_without_clobber` says
    what that keeps and what it gives up.

    **Deliberate access control.** Overwriting preserves the replaced file's POSIX discretionary
    access control, meaning owner, group, mode and access ACL: four things, not merely the mode
    digits, because a file can read 0640 before and after and still be readable by different
    people. Everything outside that is deliberately not carried, including ``security.*``, SELinux
    labels, capabilities and non-POSIX ACLs, and :func:`_restore_replaced` says why. It is applied
    through the open descriptor rather than by name, so it lands on the file that was written and
    not on whatever answers to that path by then, and all four are read the same way, off one
    descriptor held open on the file being replaced, so they cannot describe two different files.

    What none of this can survive is an adversary who can freely replace entries in the output
    directory. That is a property of the directory, not of this function: on a shared one, want
    the sticky bit.

    Yields the open file rather than a raw descriptor, and owns closing it. Handing back a
    descriptor made every caller responsible for a close they could skip by raising first, which
    leaked it onto a file already unlinked.
    """
    fd, tmp = _open_staging(path)
    try:
        # What an ordinary create would have produced, captured before narrowing, so a new file
        # still ends up with the umask's answer without the umask ever being read or set.
        fresh = stat.S_IMODE(os.fstat(fd).st_mode) & 0o777
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as out:
            yield out
            out.flush()
            os.fsync(fd)

        # Read here and not before the signature, because "the file being replaced" is whatever
        # is there at the commit, and signing takes seconds: a card, a PIN, sometimes a TSA. A
        # capture taken up front described a file that may since have been replaced by a more
        # private one, and reapplying the old mode published the document wider than the thing it
        # overwrote. Only for a replacing commit: os.link refuses a name that is taken, so the
        # other path has nothing to preserve by definition.
        replaced = _adopt_replaced(fd, path) if overwrite else None
        # Narrow again: applying an ACL rewrites the mode bits it encodes, and the file must
        # still be private when it becomes reachable by the final name.
        os.fchmod(fd, 0o600)

        if overwrite:
            os.replace(tmp, path)
        else:
            _commit_without_clobber(tmp, path)

        # Only now, when the bytes are already in place under the right name, does anyone other
        # than the owner get to read them. A failure here fails in the safe direction, leaving a
        # complete document at 0600, but it is the one failure in this function that raises after
        # the output exists, so it says so rather than looking like every other failure, which
        # leaves nothing behind.
        final = replaced.mode if replaced is not None else fresh
        try:
            os.fchmod(fd, final)
        except OSError as exc:
            raise OutputCommittedError(
                f"{path.name} was signed and is in place, but its permissions could not be set to "
                f"{oct(final)} ({exc.strerror}), so it stayed readable only by its owner. The "
                "signing operation itself completed and the output was committed. Repair the mode "
                "rather than signing again.",
                path=path, final_mode=final, errno=exc.errno,
            ) from exc
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    finally:
        os.close(fd)


def _atomic_write_bytes(path: Path, data: bytes, *, overwrite: bool = True) -> None:
    """Write ``data`` to ``path`` atomically. See :func:`_staged_output` for the guarantees."""
    with _staged_output(path, overwrite=overwrite) as out:
        out.write(data)


# A page tree is a tree, and /MediaBox is inheritable, so a page may not carry one itself. Deep
# enough for any real document and finite so a file with a /Parent cycle stops instead of hanging.
_MAX_PAGE_TREE_DEPTH = 64


def _page_media_box(writer, page: int) -> tuple[float, float, float, float]:
    """The page's MediaBox, walking up the page tree for the inherited case.

    Read from the writer rather than measured beforehand: the caller names a page, the page can be
    any size, and pages in one file can differ. Measured against a two-page file whose pages are A4
    and A5, and page=-1 correctly gives the A5 one.
    """
    ref, _ = writer.find_page_for_modification(page)
    node = ref.get_object()
    for _ in range(_MAX_PAGE_TREE_DEPTH):
        box = node.get("/MediaBox")
        if box is not None:
            return tuple(float(value) for value in box)
        parent = node.get("/Parent")
        if parent is None:
            break
        node = parent.get_object()
    raise RuntimeError(
        "the PDF does not state a page size: no /MediaBox on the page or any of its parents, "
        "which the PDF specification requires. Pass explicit coordinates instead of a corner.")


def _box_in_corner(media_box, corner: StampCorner, margin: float,
                   width: float, height: float) -> tuple[float, float, float, float]:
    """Place a width x height box `margin` points from the two edges that meet at `corner`.

    The MediaBox is not always anchored at the origin, so the page's own left and bottom are used
    rather than zero. The result is clamped to stay on the page, which only matters when the margin
    is larger than the space left over.
    """
    left, bottom, right, top = media_box
    if width > right - left or height > top - bottom:
        raise ValueError(
            f"the stamp box is {width:.0f}x{height:.0f} points and the page is "
            f"{right - left:.0f}x{top - bottom:.0f}, so it does not fit on it at all.")

    at_right = corner in (StampCorner.bottom_right, StampCorner.top_right)
    at_top = corner in (StampCorner.top_left, StampCorner.top_right)
    x1 = right - margin - width if at_right else left + margin
    y1 = top - margin - height if at_top else bottom + margin
    x1 = min(max(x1, left), right - width)
    y1 = min(max(y1, bottom), top - height)
    return x1, y1, x1 + width, y1 + height


def _sign_one_pdf(
    *,
    input_pdf: Path,
    output_pdf: Path,
    pkcs11_signer: "PKCS11Signer",
    signer_name: str,
    issuer_name: str,
    cert_serial: str,
    timestamper,
    meta: "signers.PdfSignatureMetadata",
    page: int,
    x1: int,
    y1: int,
    x2: int,
    y2: int,
    timezone: str,
    field_name: str,
    force: bool,
    overwrite: bool,
    image_path: Optional[Path] = None,
    image_mode: ImageMode = ImageMode.background,
    image_opacity: float = DEFAULT_IMAGE_OPACITY,
    stamp_fields: StampFields = StampFields(),
    corner: Optional[StampCorner] = None,
    margin: float = 20.0,
    allow_hybrid_xref: bool = False,
    notify: Optional[Callable[[str], None]] = None,
) -> None:
    """Sign a single PDF. Raises on any error. ``notify``, when given, receives the warning lines
    (hybrid-xref opt-in, signature-field reuse); without it they are dropped."""
    if input_pdf.resolve() == output_pdf.resolve():
        raise RuntimeError(
            f"Input and output are the same file: {output_pdf}. "
            "Choose a different output path (in batch mode, adjust --output-dir or --suffix)."
        )
    if output_pdf.exists() and not overwrite:
        raise OutputExistsError(
            f"Output file already exists: {output_pdf}\n"
            "Use --overwrite to overwrite it.",
            path=output_pdf,
        )

    ensure_output_parent(output_pdf)

    with input_pdf.open("rb") as inf:
        # Hybrid cross-reference PDFs (a classic xref table + an xref stream, common in files
        # exported by design tools) can't be incrementally signed in strict mode: pyHanko refuses
        # because the two xref structures could desync and the signature would not be equivalent
        # for all readers. --allow-hybrid-xref opens the PDF non-strict to sign it anyway.
        writer = IncrementalPdfFileWriter(inf, strict=not allow_hybrid_xref)
        if writer.prev.xrefs.hybrid_xrefs_present:
            if not allow_hybrid_xref:
                raise RuntimeError(
                    f"{input_pdf.name} uses hybrid cross-reference sections, which cannot be "
                    "signed in strict mode (the incremental signature may not be equivalent for "
                    "all PDF readers). Normalize it first with `qpdf in.pdf out.pdf` and sign the "
                    "result, or pass --allow-hybrid-xref to sign it as-is (at your own risk)."
                )
            if notify:
                notify(
                    f"Warning: {input_pdf.name} has hybrid cross-reference sections. Signing due to "
                    "--allow-hybrid-xref. The signature may not be equivalent for older PDF readers."
                )

        # Here and not before: the page size is only knowable with the file open, which is the
        # whole reason a corner cannot be resolved by the caller. The box keeps the size it was
        # given and only its place changes, so a default box in its default corner is unmoved.
        if corner is not None:
            x1, y1, x2, y2 = _box_in_corner(
                _page_media_box(writer, page), corner, margin, x2 - x1, y2 - y1)

        existing_fields = list(fields.enumerate_sig_fields(writer))
        matching = [(name, val) for name, val, _ in existing_fields if name == field_name]
        if matching:
            _, field_value = matching[0]
            if field_value is not None:
                if not force:
                    raise RuntimeError(
                        f"Field '{field_name}' already contains a signature. "
                        "Use --force to continue anyway (the PDF may become invalid)."
                    )
                if notify:
                    notify(
                        f"Warning: field '{field_name}' already contains a signature. "
                        "Continuing due to --force (the PDF may become invalid)."
                    )
            elif notify:
                notify(
                    f"Warning: field '{field_name}' already exists but is unsigned, "
                    "it will be reused."
                )
        else:
            fields.append_signature_field(
                writer,
                sig_field_spec=fields.SigFieldSpec(
                    field_name,
                    on_page=page,
                    box=(x1, y1, x2, y2),
                ),
            )

        ts = datetime.now(ZoneInfo(timezone)).strftime("%d/%m/%Y %H:%M")

        appearance_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
                appearance_path = tmp.name

            make_appearance_pdf(
                appearance_path,
                signer=signer_name,
                cert_serial=cert_serial,
                ts=ts,
                issuer=issuer_name,
                image_path=str(image_path) if image_path else None,
                image_mode=image_mode,
                image_opacity=image_opacity,
                fields=stamp_fields,
            )

            pdf_signer = signers.PdfSigner(
                meta,
                signer=pkcs11_signer,
                timestamper=timestamper,
                stamp_style=stamp.StaticStampStyle.from_pdf_file(
                    appearance_path,
                    border_width=0,
                    background_layout=SimpleBoxLayoutRule(
                        x_align=AxisAlignment.ALIGN_MIN,
                        y_align=AxisAlignment.ALIGN_MIN,
                        margins=Margins(0, 0, 0, 0),
                        inner_content_scaling=InnerScaling.NO_SCALING,
                    ),
                ),
            )

            # Sign into a private sibling temp file, then atomically move it into place. A failure
            # mid-signing (e.g. the card is pulled) then never leaves a partial/corrupt file at
            # output_pdf, and with --overwrite it never destroys the previous good output either.
            # The XML/CMS paths get the same guarantees through the same helper.
            with _staged_output(output_pdf, overwrite=overwrite) as outf:
                pdf_signer.sign_pdf(writer, output=outf)

        finally:
            if appearance_path:
                try:
                    Path(appearance_path).unlink(missing_ok=True)
                except Exception:
                    pass


def _make_raw_signer(session, key_id: bytes):
    """Return a callable that signs bytes on the token with RSA-SHA256."""
    priv = get_private_key(session, key_id)

    def raw_signer(data: bytes) -> bytes:
        return bytes(priv.sign(data, mechanism=pkcs11.Mechanism.SHA256_RSA_PKCS))

    return raw_signer


def _sign_one_xml(
    *,
    input_xml: Path,
    output_xml: Path,
    cert: "x509.Certificate",
    signer,
    signing_time: datetime,
    overwrite: bool,
    timestamper=None,
) -> None:
    """Sign a single XML (XAdES-BES, or XAdES-T with a timestamper). Raises on any error."""
    if input_xml.resolve() == output_xml.resolve():
        raise RuntimeError(
            f"Input and output are the same file: {output_xml}. "
            "Choose a different output path (in batch mode, adjust --output-dir or --suffix)."
        )
    if output_xml.exists() and not overwrite:
        raise OutputExistsError(
            f"Output file already exists: {output_xml}\n"
            "Use --overwrite to overwrite it.",
            path=output_xml,
        )
    ensure_output_parent(output_xml)
    signed = sign_xml(
        input_xml.read_bytes(),
        cert=cert,
        signer=signer,
        signing_time=signing_time,
        timestamper=timestamper,
    )
    _atomic_write_bytes(output_xml, signed, overwrite=overwrite)


def _sign_one_cms(
    *,
    input_file: Path,
    output_p7s: Path,
    pkcs11_signer: "PKCS11Signer",
    timestamper,
    overwrite: bool,
) -> None:
    """Sign a single file as a detached CAdES-BES ``.p7s``. Raises on any error."""
    if input_file.resolve() == output_p7s.resolve():
        raise RuntimeError(
            f"Input and output are the same file: {output_p7s}. "
            "Choose a different output path (in batch mode, adjust --output-dir or --suffix)."
        )
    if output_p7s.exists() and not overwrite:
        raise OutputExistsError(
            f"Output file already exists: {output_p7s}\n"
            "Use --overwrite to overwrite it.",
            path=output_p7s,
        )
    ensure_output_parent(output_p7s)
    with input_file.open("rb") as f:
        p7s = sign_cms_detached(f, signer=pkcs11_signer, timestamper=timestamper)
    _atomic_write_bytes(output_p7s, p7s, overwrite=overwrite)


def _check_post_sign(result, output: Path, *, covers: Optional[Path] = None) -> None:
    """Raise if a post-sign verification result has any failed check.

    Names the output, because by the time this runs the file has been written and the caller is
    about to be told only that something failed. Unlike every other failure on this path it is
    not a signature worth keeping, so saying it exists is what lets somebody delete it instead of
    finding it later and trusting it.

    ``covers`` is the separate file a detached signature is over, when there is one. It changes
    what a failure is allowed to claim: with the bytes inside the output there is one explanation,
    and with the bytes in somebody else's file there are two, since that file may simply not be
    the one that was signed any more. Saying "not intact" there would name the wrong culprit and
    send somebody to sign whatever the file now contains.
    """
    failed = [c for c in result.checks if not c.ok]
    if failed:
        detail = "; ".join(c.name + (f" ({c.detail})" if c.detail else "") for c in failed)
        if covers is None:
            raise PostSignVerificationError(
                "post-sign verification failed (the produced signature is not intact): "
                f"{detail}. {output.name} is on disk and should not be used: delete it and "
                "sign again.",
                path=output, outcome="failed",
            )
        # A different outcome, and not a nicety: "failed" is documented as delete and sign again,
        # and doing that here would sign whatever the covered file holds now. The message already
        # said this cannot tell the two explanations apart, so the field has to say it too, or a
        # program reading the field does the thing the prose warns against.
        raise PostSignVerificationError(
            f"post-sign verification failed: {output.name} does not verify against "
            f"{covers.name} as it is now ({detail}). Either the signature is not intact "
            f"or {covers.name} changed after it was signed, and this cannot tell which. "
            f"{output.name} is on disk and should not be used. Check whether "
            f"{covers.name} is still the file you meant to sign before signing it again.",
            path=output, outcome="detached-mismatch", covers=covers,
        )


@contextmanager
def _post_sign(output: Path):
    """Everything the self-check does, with the two ways of not confirming a signature kept apart.

    ``_check_post_sign`` only speaks when the verifier produced a result and something in it was
    false. Getting that far is not guaranteed: the verifier can raise, the file can fail to read
    back, the result list can come back empty. All of those used to escape as whatever the
    underlying library felt like raising, which said nothing about the fact that a file had been
    written and left the caller with a document of unknown standing and no way to tell that from
    an ordinary failure.

    That is one of three outcomes, and the one this wrapper is responsible for. The other two
    come from the check itself having produced a result: a self-contained signature found not
    intact, and a detached pair that no longer matches. See
    :class:`~firmauy.errors.PostSignVerificationError` for what each one asks of a caller.
    """
    try:
        yield
    except PostSignVerificationError:
        raise
    except Exception as exc:
        raise PostSignVerificationError(
            f"the post-sign verification could not be completed ({exc}). {output.name} is on "
            "disk and nothing is known about the signature in it: do not use it, and check it "
            "before signing again, which would only add a second signature to it.",
            path=output, outcome="inconclusive",
        ) from exc


def _verify_after_pdf(output_pdf: Path) -> None:
    # Only the signature we just appended (the last one); integrity + coverage, no trust.
    with _post_sign(output_pdf):
        _check_post_sign(verify_pdf(output_pdf, trust_roots=None)[-1], output_pdf)


def _verify_after_xml(output_xml: Path) -> None:
    # Only the signature we just appended (the last one); integrity, no trust.
    with _post_sign(output_xml):
        _check_post_sign(verify_xml(output_xml.read_bytes(), trust_roots=None)[-1], output_xml)


def _verify_after_cms(input_file: Path, output_p7s: Path) -> None:
    """The CAdES self-check, which is the one that cannot say what the other two can.

    A detached signature covers bytes that live in another file, and this re-opens that file by
    pathname to compare against it. Signing streamed the original through one descriptor and this
    opens a second one, so what is checked is the original *as it is now*. If it changed in
    between, the ``.p7s`` can be a perfectly good signature over what was actually signed and this
    still reports a mismatch, which is why the message says a mismatch rather than a corrupt
    signature. PDF and XAdES have nothing to compare against: their check reads the output alone.

    Closing that properly means verifying through the same descriptor the signature was made
    from, which means the check has to happen inside :func:`_sign_one_cms` while it is still open.
    That is a change to how every caller sequences signing and verifying, and it is not this
    release's.
    """
    with _post_sign(output_p7s):
        with input_file.open("rb") as data:
            from firmauy.cms_verify import MAX_CMS_BYTES
            from firmauy._shared import read_bounded
            _check_post_sign(verify_cms(data, read_bounded(output_p7s, MAX_CMS_BYTES, "CMS signature"),
                                        trust_roots=None),
                             output_p7s, covers=input_file)


def _detect_input_kind(path: Path) -> str:
    """Detect an UNSIGNED input file's kind for signing: "pdf", "xml" or "any" (arbitrary -> CAdES).

    Mirrors _detect_signature_kind's magic-byte logic, but the fallback is "any" (sign arbitrary
    bytes as a detached CAdES .p7s) instead of attempting a CMS parse. An empty file is "any"."""
    with path.open("rb") as f:
        start = f.read(1024).lstrip(b"\xef\xbb\xbf").lstrip()
    if start[:1] == b"<":
        return "xml"
    if start.startswith(b"%PDF-"):
        return "pdf"
    return "any"


def _resolve_sign_kind(path: Path, sign_as: SignAs) -> str:
    """Resolve the signature kind ("pdf" | "xml" | "any") for an input, honoring --as.

    With SignAs.auto the kind is detected by content; otherwise the requested type is forced
    (cades -> "any", the detached CAdES signer)."""
    if sign_as is SignAs.auto:
        return _detect_input_kind(path)
    return {SignAs.pdf: "pdf", SignAs.xml: "xml", SignAs.cades: "any"}[sign_as]


def _output_path_for(path: Path, kind: str, out_dir: Optional[Path] = None) -> Path:
    """Default output path for signing ``path`` as ``kind`` ("pdf" | "xml" | "any").

    An embedded signature keeps the input's extension and gets ``_firmado`` on the stem; a
    detached one appends ``.p7s`` to the whole name, so ``data.bin`` becomes ``data.bin.p7s``
    and the original name stays readable. With ``out_dir`` the result goes there, flat.

    One definition for the signers, the batch and the public :func:`firmauy.api.output_path_for`,
    so a caller checking for an existing output before asking for the PIN cannot drift from where
    the file actually lands."""
    if kind in ("pdf", "xml"):
        base = (out_dir / path.name) if out_dir else path
        return base.with_stem(path.stem + "_firmado")
    return (out_dir / (path.name + ".p7s")) if out_dir else path.with_name(path.name + ".p7s")
