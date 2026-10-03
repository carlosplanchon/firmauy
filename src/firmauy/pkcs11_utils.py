# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

import re
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Optional

import pkcs11
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from firmauy.cert_utils import cert_not_after, cert_not_before, get_common_name
from firmauy.errors import (
    CertificateNotFoundError,
    CertificateNotValidError,
    IncorrectPinError,
    PinLastTryError,
    PinLockedError,
    SigningKeyNotFoundError,
    TokenNotFoundError,
)

# One certificate as the token lists it: its PKCS#11 object ID and the parsed certificate.
CertEntry = tuple[bytes, x509.Certificate]


def load_pkcs11_lib(pkcs11_lib: str) -> pkcs11.lib:
    try:
        return pkcs11.lib(pkcs11_lib)
    except pkcs11.exceptions.GeneralError as exc:
        raise RuntimeError(
            f"Could not load PKCS#11 module '{pkcs11_lib}': {exc}"
        ) from exc
    except Exception as exc:
        if not Path(pkcs11_lib).exists():
            raise RuntimeError(
                f"PKCS#11 module not found: '{pkcs11_lib}'"
            ) from exc
        raise RuntimeError(
            f"Error loading PKCS#11 module '{pkcs11_lib}': {exc}"
        ) from exc


def find_token(lib: pkcs11.lib, token_label: Optional[str]) -> pkcs11.Token:
    """Return a PKCS#11 token by label, or auto-detect if exactly one is present."""
    if token_label:
        return lib.get_token(token_label=token_label)

    tokens = list(lib.get_tokens())
    if not tokens:
        raise TokenNotFoundError("No PKCS#11 tokens available.")

    if len(tokens) == 1:
        return tokens[0]

    labels = [
        (getattr(t, "label", "") or "").strip() or "<no label>"
        for t in tokens
    ]
    raise RuntimeError(
        "Multiple tokens found and --token-label was not specified. "
        f"Available tokens: {labels}"
    )


def iter_cert_objects(session: pkcs11.Session) -> Iterable[pkcs11.Object]:
    return session.get_objects(
        {pkcs11.Attribute.CLASS: pkcs11.ObjectClass.CERTIFICATE}
    )


def normalize_cert_id_hex(cert_id_hex: str) -> str:
    """Strip colons/spaces and validate that the result is valid, even-length hex.

    A PKCS#11 object ID is a byte string, so its hex form always has an even number of digits.
    Rejecting an odd length here (with a clear message) keeps the promise of "a valid hexadecimal
    value": otherwise it would pass this check and then blow up later in ``bytes.fromhex`` with a
    cryptic ``ValueError``."""
    normalized = cert_id_hex.replace(":", "").replace(" ", "").upper()
    if not re.fullmatch(r"[0-9A-F]+", normalized):
        raise ValueError(
            f"--cert-id '{cert_id_hex}' is not a valid hexadecimal value."
        )
    if len(normalized) % 2 != 0:
        raise ValueError(
            f"--cert-id '{cert_id_hex}' has an odd number of hex digits; "
            "a byte ID is an even-length hex string."
        )
    return normalized


def cert_is_expired(cert: x509.Certificate) -> bool:
    try:
        not_after = cert.not_valid_after_utc
    except AttributeError:
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)  # type: ignore[attr-defined]
    return datetime.now(timezone.utc) > not_after


def cert_not_yet_valid(cert: x509.Certificate) -> bool:
    try:
        not_before = cert.not_valid_before_utc
    except AttributeError:
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)  # type: ignore[attr-defined]
    return datetime.now(timezone.utc) < not_before


def get_private_key(session: pkcs11.Session, key_id: bytes) -> pkcs11.Object:
    """Return the private-key object on the token matching the given ID."""
    keys = list(session.get_objects({
        pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY,
        pkcs11.Attribute.ID: key_id,
    }))
    if not keys:
        raise SigningKeyNotFoundError(
            "No private key found on the token for the selected certificate."
        )
    return keys[0]


def has_private_key(session: pkcs11.Session, key_id: bytes) -> bool:
    """Return True if a private key with the given ID exists on the token.

    "No key" is simply an empty result, not an error. A genuine PKCS#11 error (e.g. the device is
    pulled mid-query) is allowed to propagate rather than being swallowed as "no key": hiding it
    could wrongly drop the only usable certificate and surface a misleading "no key" message."""
    keys = list(session.get_objects({
        pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY,
        pkcs11.Attribute.ID: key_id,
    }))
    return len(keys) > 0


def read_certificates(session: pkcs11.Session) -> tuple[list[CertEntry], int]:
    """Every certificate the session can see, and how many objects could not be read.

    An object whose ID or value cannot be read, or whose value does not parse, is skipped and
    counted. Skipping is what selection always did. The count is for the check before login, which
    must not mistake a certificate it failed to read for one that is not there.
    """
    certs: list[CertEntry] = []
    unreadable = 0
    for cert_obj in iter_cert_objects(session):
        try:
            obj_id = cert_obj[pkcs11.Attribute.ID]
            cert = x509.load_der_x509_certificate(cert_obj[pkcs11.Attribute.VALUE])
        except Exception:
            unreadable += 1
            continue
        certs.append((obj_id, cert))
    return certs, unreadable


def usable_certificates(
    certs: Iterable[CertEntry], cert_id_hex: Optional[str],
) -> tuple[list[CertEntry], list[CertEntry]]:
    """``(valid, unusable)``: the certificates valid now, and the ones expired or not yet valid,
    keeping only the ``cert_id_hex`` one when it is given.

    Raises CertificateNotFoundError when nothing is left and CertificateNotValidError when all that
    is left is outside its validity window. Neither check needs a private key, which is why they are
    apart from the rest of select_certificate: they can run before the PIN.
    """
    wanted_id = bytes.fromhex(normalize_cert_id_hex(cert_id_hex)) if cert_id_hex else None
    valid: list[CertEntry] = []
    unusable: list[CertEntry] = []
    for obj_id, cert in certs:
        if wanted_id is not None and obj_id != wanted_id:
            continue
        if cert_is_expired(cert) or cert_not_yet_valid(cert):
            unusable.append((obj_id, cert))
        else:
            valid.append((obj_id, cert))

    if not valid and not unusable:
        if cert_id_hex:
            raise CertificateNotFoundError(
                f"No certificate found with ID {cert_id_hex} in the token."
            )
        raise CertificateNotFoundError("No usable certificates found in the token.")

    if not valid:
        cert = unusable[0][1]
        cn = get_common_name(cert.subject)
        if cert_is_expired(cert):
            reason = f"expired (valid until {cert_not_after(cert)})"
        else:
            reason = f"not yet valid (valid from {cert_not_before(cert)})"
        raise CertificateNotValidError(
            f"Selected certificate is {reason}: {cn}\n"
            "No valid certificates found in the token."
        )
    return valid, unusable


def check_certificate_before_login(token: pkcs11.Token, cert_id_hex: Optional[str]) -> None:
    """Run the certificate checks that need no private key, before the PIN is asked for.

    select_certificate needs a logged-in session, because it pairs each certificate with its
    private key and private keys only appear after login. Whether the certificate exists and is
    valid needs no login: certificates are public objects on the cédula, with the official
    middleware and with OpenSC alike. Checking them here means an expired certificate or an unknown
    --cert-id fails before the PIN is typed, as on the native path. Checked after it, a mistyped PIN
    would spend one of the card's tries and be reported as the only problem.

    A token that shows no certificate without login, a certificate that cannot be read, or a module
    error proves nothing, so the checks then wait for the login, as they always did. Passing proves
    nothing either: login can only add private objects, and select_certificate still decides. The
    one setup this refuses early that login would have rescued is a token that shows some
    certificates and keeps the wanted one private, which no known cédula stack does.
    """
    try:
        with token.open() as session:
            certs, unreadable = read_certificates(session)
    except pkcs11.exceptions.PKCS11Error:
        return
    # Outside the try: closing the session can fail as well, and that failure must neither replace
    # a domain error raised here nor be taken for one.
    if certs and not unreadable:
        usable_certificates(certs, cert_id_hex)


def check_pin_status(token: pkcs11.Token) -> None:
    """Refuse before the PIN is asked for when the token reports the PIN as locked, or on its last
    try, as the native path's verify_pin does from the card's own counter.

    The flags are what the module reported when find_token got the token (C_GetTokenInfo), and
    reporting them is up to the module. OpenSC does for the cédula. A module that does not sets
    neither flag, which leaves the PIN path as it was. USER_PIN_COUNT_LOW only says a wrong PIN was
    entered since the last good one, which is no reason to refuse.
    """
    flags = token.flags
    if flags & pkcs11.TokenFlag.USER_PIN_LOCKED:
        raise PinLockedError("The PIN is locked (too many incorrect attempts).")
    if flags & pkcs11.TokenFlag.USER_PIN_FINAL_TRY:
        raise PinLastTryError(
            "Only 1 PIN try left: aborting for safety. Unblock the cédula before retrying."
        )


@contextmanager
def login_session(token: pkcs11.Token, pin: Optional[str]):
    """``token.open(user_pin=pin)``, with the module's PIN exceptions turned into firmauy's.

    Every PKCS#11 login goes through here, so a wrong or locked PIN reaches the caller as
    IncorrectPinError or PinLockedError whichever command logged in, as on the native path. The
    module does not report the remaining tries, so IncorrectPinError carries none. Without a PIN
    this opens a session with no login and translates nothing.
    """
    try:
        with token.open(user_pin=pin) as session:
            yield session
    except pkcs11.exceptions.PinIncorrect as exc:
        raise IncorrectPinError("Incorrect PIN.") from exc
    except pkcs11.exceptions.PinLocked as exc:
        raise PinLockedError("The PIN is locked (too many incorrect attempts).") from exc


def select_certificate(
    session: pkcs11.Session, cert_id_hex: Optional[str],
    notify: Optional[Callable[[str], None]] = None,
) -> tuple[bytes, x509.Certificate]:
    """Select the best signing certificate from the token.

    If cert_id_hex is given, filters to that specific certificate ID.
    Otherwise, scores all available certificates and returns the one most
    likely to be a cédula identity certificate. Expired certificates are
    excluded, and if all candidates are expired an error is raised.

    ``notify``, when given, receives the skipped-candidate warning lines (certificates without a
    private key, expired ones). Without it they are dropped.
    """
    certs, _ = read_certificates(session)
    cert_candidates, unusable_candidates = usable_certificates(certs, cert_id_hex)

    no_key_candidates: list[tuple[bytes, x509.Certificate]] = []
    valid_candidates: list[tuple[bytes, x509.Certificate]] = []
    for key_id, cert in cert_candidates:
        if has_private_key(session, key_id):
            valid_candidates.append((key_id, cert))
        else:
            no_key_candidates.append((key_id, cert))

    if no_key_candidates and notify:
        notify(
            f"Warning: {len(no_key_candidates)} certificate(s) skipped, no matching private key in token."
        )

    if not valid_candidates:
        cn_list = ", ".join(get_common_name(c.subject) or "?" for _, c in no_key_candidates)
        raise SigningKeyNotFoundError(
            "No valid certificate with available private key found. "
            f"Certificates without key: {cn_list}"
        )

    cert_candidates = valid_candidates

    if unusable_candidates and notify:
        notify(
            f"Warning: {len(unusable_candidates)} certificate(s) skipped (expired or not yet valid)."
        )

    def score(item: tuple[bytes, x509.Certificate]) -> int:
        _, cert = item
        subject = cert.subject.rfc4514_string().upper()
        issuer = cert.issuer.rfc4514_string().upper()

        points = 0
        if "SERIALNUMBER=" in subject or "DNI" in subject:
            points += 5
        if "MINISTERIO DEL INTERIOR" in issuer:
            points += 3
        if get_common_name(cert.subject):
            points += 1
        try:
            ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
            if ku.value.digital_signature:
                points += 4
            if ku.value.content_commitment:
                points += 3
        except x509.ExtensionNotFound:
            pass
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            signing_oids = {
                ExtendedKeyUsageOID.EMAIL_PROTECTION,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            }
            if any(oid in signing_oids for oid in eku.value):
                points += 2
        except x509.ExtensionNotFound:
            pass
        return points

    cert_candidates.sort(key=score, reverse=True)
    return cert_candidates[0]


def token_to_dict(token) -> dict:
    """Structured view of a PKCS#11 token: ``label``, ``manufacturer``, ``model`` and ``serial``.

    Each value is the trimmed attribute or ``None`` when empty (the display sentinels such as
    ``<no label>`` / ``-`` are a CLI concern, not part of the data). Shared by the ``list-tokens``
    command and :func:`firmauy.api.list_tokens`."""
    def _attr(name: str) -> Optional[str]:
        val = getattr(token, name, "")
        if isinstance(val, (bytes, bytearray)):
            # Some modules hand back the raw PKCS#11 attribute instead of a decoded string: the
            # Gemalto middleware does it for the serial. Without this, a value annotated as str
            # really is bytes, and a caller that formats it prints the Python repr,
            # b'66000034D0201077'. NUL padding is part of the attribute format, not the value.
            val = val.decode("utf-8", "replace").replace("\x00", "")
        val = (val or "").strip()
        return val or None

    return {
        "label": _attr("label"),
        "manufacturer": _attr("manufacturer"),
        "model": _attr("model"),
        "serial": _attr("serial"),
    }
