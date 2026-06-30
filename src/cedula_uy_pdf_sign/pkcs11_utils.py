# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

import pkcs11
import typer
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from cedula_uy_pdf_sign.cert_utils import cert_not_after, cert_not_before, get_common_name


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
        raise RuntimeError("No PKCS#11 tokens available.")

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
    """Strip colons/spaces and validate that the result is valid hex."""
    normalized = cert_id_hex.replace(":", "").replace(" ", "").upper()
    if not re.fullmatch(r"[0-9A-F]+", normalized):
        raise typer.BadParameter(
            f"--cert-id '{cert_id_hex}' is not a valid hexadecimal value."
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
        raise RuntimeError(
            "No private key found on the token for the selected certificate."
        )
    return keys[0]


def has_private_key(session: pkcs11.Session, key_id: bytes) -> bool:
    """Return True if a private key with the given ID exists on the token."""
    try:
        keys = list(session.get_objects({
            pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY,
            pkcs11.Attribute.ID: key_id,
        }))
        return len(keys) > 0
    except Exception:
        return False


def select_certificate(
    session: pkcs11.Session, cert_id_hex: Optional[str]
) -> tuple[bytes, x509.Certificate]:
    """Select the best signing certificate from the token.

    If cert_id_hex is given, filters to that specific certificate ID.
    Otherwise, scores all available certificates and returns the one most
    likely to be a cédula identity certificate. Expired certificates are
    excluded; if all candidates are expired an error is raised.
    """
    wanted_id = bytes.fromhex(normalize_cert_id_hex(cert_id_hex)) if cert_id_hex else None
    cert_candidates: list[tuple[bytes, x509.Certificate]] = []
    unusable_candidates: list[tuple[bytes, x509.Certificate]] = []   # expired or not yet valid

    for cert_obj in iter_cert_objects(session):
        try:
            obj_id = cert_obj[pkcs11.Attribute.ID]
            cert_der = cert_obj[pkcs11.Attribute.VALUE]
            cert = x509.load_der_x509_certificate(cert_der)
        except Exception:
            continue

        if wanted_id is not None and obj_id != wanted_id:
            continue

        if cert_is_expired(cert) or cert_not_yet_valid(cert):
            unusable_candidates.append((obj_id, cert))
        else:
            cert_candidates.append((obj_id, cert))

    if not cert_candidates and not unusable_candidates:
        if cert_id_hex:
            raise RuntimeError(
                f"No certificate found with ID {cert_id_hex} in the token."
            )
        raise RuntimeError("No usable certificates found in the token.")

    if not cert_candidates:
        cert = unusable_candidates[0][1]
        cn = get_common_name(cert.subject)
        if cert_is_expired(cert):
            reason = f"expired (valid until {cert_not_after(cert)})"
        else:
            reason = f"not yet valid (valid from {cert_not_before(cert)})"
        raise RuntimeError(
            f"Selected certificate is {reason}: {cn}\n"
            "No valid certificates found in the token."
        )

    no_key_candidates: list[tuple[bytes, x509.Certificate]] = []
    valid_candidates: list[tuple[bytes, x509.Certificate]] = []
    for key_id, cert in cert_candidates:
        if has_private_key(session, key_id):
            valid_candidates.append((key_id, cert))
        else:
            no_key_candidates.append((key_id, cert))

    if no_key_candidates:
        typer.secho(
            f"Warning: {len(no_key_candidates)} certificate(s) skipped, no matching private key in token.",
            fg=typer.colors.YELLOW,
            err=True,
        )

    if not valid_candidates:
        cn_list = ", ".join(get_common_name(c.subject) or "?" for _, c in no_key_candidates)
        raise RuntimeError(
            "No valid certificate with available private key found. "
            f"Certificates without key: {cn_list}"
        )

    cert_candidates = valid_candidates

    if unusable_candidates:
        typer.secho(
            f"Warning: {len(unusable_candidates)} certificate(s) skipped (expired or not yet valid).",
            fg=typer.colors.YELLOW,
            err=True,
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
