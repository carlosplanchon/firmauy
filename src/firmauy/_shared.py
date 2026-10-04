# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Backend-agnostic helpers shared by the CLI and the public API.

These are pure-logic helpers (signature-format detection, trust-anchor resolution and the
environment diagnostic checks) that both ``firmauy.cli`` and ``firmauy.api`` need. Keeping them
here, rather than in ``cli``, lets the public API reuse them without importing the Typer command
module. The CLI imports them back from here, so there is a single source of truth.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Callable, Optional

from cryptography import x509

from firmauy import _platform
from firmauy.national_ca import load_bundled_trust_anchors, load_cached_trust_anchors
from firmauy.pkcs11_utils import load_pkcs11_lib


# ---------------------------------------------------------------------------
# Error formatting
# ---------------------------------------------------------------------------

def _format_error(exc: Exception) -> str:
    """Human-readable message for an exception, with friendly text for common
    PKCS#11 PIN errors (whose own str() is empty)."""
    import pkcs11.exceptions as pe
    if isinstance(exc, pe.PinIncorrect):
        return "Incorrect PIN."
    if isinstance(exc, pe.PinLocked):
        return "The PIN is locked (too many incorrect attempts)."
    return str(exc) or type(exc).__name__


# ---------------------------------------------------------------------------
# Verify: format detection and trust-anchor resolution
# ---------------------------------------------------------------------------

_INDICATION_RANK = {"VALID": 0, "INDETERMINATE": 1, "INVALID": 2}

_CMS_DETECT_MAX_BYTES = 8 * 1024 * 1024


def read_bounded(path: Path, max_bytes: int, what: str) -> bytes:
    """Read a file up to ``max_bytes`` without allocating an unbounded input buffer."""
    with path.open("rb") as f:
        data = f.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"{what} exceeds the {max_bytes} byte limit; refusing to read it")
    return data


def _resolve_trust_anchors(ca_file: Optional[Path], no_trust: bool,
                           notify: Optional[Callable[[str], None]] = None):
    """Return (roots, intermediates): from --ca-file, else the cached national CAs, else the
    certificates bundled with the package, else (None, None) with a hint. Returns (None, None)
    when trust is skipped.

    ``notify``, when given, receives the fallback note when the bundled anchors cannot be loaded
    (a broken-install edge); without it the note is dropped."""
    if no_trust:
        return None, None
    if ca_file is not None:
        certs = x509.load_pem_x509_certificates(ca_file.read_bytes())
        roots = [c for c in certs if c.subject == c.issuer]
        intermediates = [c for c in certs if c.subject != c.issuer]
        if not roots:
            raise RuntimeError("--ca-file has no self-signed root certificate.")
        return roots, intermediates
    cached_roots, cached_intermediates = load_cached_trust_anchors()
    if cached_roots:
        return cached_roots, cached_intermediates
    bundled_roots, bundled_intermediates = load_bundled_trust_anchors()
    if bundled_roots:
        return bundled_roots, bundled_intermediates
    # Reached only if the bundled trust anchors could not be loaded (e.g. a broken install),
    # since they are otherwise always present.
    if notify:
        notify(
            "Note: the bundled trust anchors could not be loaded; checking signature integrity\n"
            "      only. Pass --ca-file with the national CAs, or run 'firmauy fetch-cas'."
        )
    return None, None


def _resolve_tsa_anchors(tsa_ca: Optional[Path]):
    """Return (roots, others) for validating an XAdES-T timestamp's TSA, loaded from --tsa-ca, or
    (None, None) if not given. Self-signed certs are anchors; the rest are path-building
    intermediates. With no self-signed cert, all are treated as anchors (the user chose to trust
    exactly this set)."""
    if tsa_ca is None:
        return None, None
    certs = x509.load_pem_x509_certificates(tsa_ca.read_bytes())
    if not certs:
        raise RuntimeError("--tsa-ca contains no certificates.")
    roots = [c for c in certs if c.subject == c.issuer]
    others = [c for c in certs if c.subject != c.issuer]
    if not roots:
        roots, others = certs, []
    return roots, others


def _detect_signature_kind(path: Path) -> str:
    """Detect a signed file's format by content: "pdf", "xml" (XAdES) or "cms" (detached
    .p7s in DER). Raises ValueError if none match.

    Only a 1 KB prefix is read to recognise PDF or XML; for the CMS (DER) case the read is bounded to
    _CMS_DETECT_MAX_BYTES -- a detached ``.p7s`` is small, so a larger file is not a detached
    signature and is not read whole into memory."""
    from asn1crypto import cms as asn1cms

    with path.open("rb") as f:
        head = f.read(1024)
        if not head:
            raise ValueError("file is empty")
        # Logical start: skip a UTF-8 BOM and any leading whitespace.
        start = head.lstrip(b"\xef\xbb\xbf").lstrip()
        if start[:1] == b"<":
            return "xml"
        # The PDF header must be at the (logical) start, not merely somewhere in the first KB, so
        # an XML or CMS that only *contains* the bytes "%PDF-" is not misdetected as a PDF.
        if start.startswith(b"%PDF-"):
            return "pdf"
        # Not PDF/XML: read the rest (bounded) and try to parse it as detached CMS (DER). The +1
        # lets an over-cap file produce len(raw) > cap so it is skipped rather than parsed truncated.
        raw = head + f.read(max(0, _CMS_DETECT_MAX_BYTES - len(head)) + 1)
    if len(raw) <= _CMS_DETECT_MAX_BYTES:
        try:
            ci = asn1cms.ContentInfo.load(raw)
            if ci["content_type"].native == "signed_data":
                return "cms"
        except Exception:
            pass
    raise ValueError("could not detect the signature type (not a PDF, XAdES XML or CMS/.p7s)")


def _detached_original(p7s_path: Path) -> Optional[Path]:
    """The original file a detached .p7s signs, by the '<x>.p7s -> <x>' convention."""
    return p7s_path.with_suffix("") if p7s_path.suffix == ".p7s" else None


# ---------------------------------------------------------------------------
# Doctor: environment diagnostic checks
# ---------------------------------------------------------------------------

_PCSCD_SOCKETS = ("/run/pcscd/pcscd.comm", "/var/run/pcscd/pcscd.comm")

# PE machine type of a 32-bit x86 image, from the COFF header.
_PE_MACHINE_I386 = 0x014C


def _pe_is_32bit(path: str) -> Optional[bool]:
    """Whether the Windows module at ``path`` is 32-bit x86, read off its PE header. None when the
    file cannot be read or is not a PE image, so the caller falls back to what the path says."""
    try:
        with open(path, "rb") as f:
            dos = f.read(0x40)
            if len(dos) < 0x40 or dos[:2] != b"MZ":
                return None
            f.seek(int.from_bytes(dos[0x3C:0x40], "little"))
            pe = f.read(6)
    except OSError:
        return None
    if len(pe) < 6 or pe[:4] != b"PE\0\0":
        return None
    return int.from_bytes(pe[4:6], "little") == _PE_MACHINE_I386


def _wrong_bitness_fix(pkcs11_lib: str) -> Optional[str]:
    """On a 64-bit Python, the fix for pointing at the 32-bit gclib.dll; None otherwise.

    Thales Classic Client installs both, and the 32-bit one fails to load with only "%1 is not a
    valid Win32 application", which says nothing about which file to use instead. The PE header
    decides when the file is there, and the "Program Files (x86)" folder when it is not.
    """
    if sys.maxsize <= 2**32:
        return None
    is_32bit = _pe_is_32bit(pkcs11_lib) if Path(pkcs11_lib).exists() else None
    if is_32bit is None:
        is_32bit = "program files (x86)" in pkcs11_lib.lower()
    if not is_32bit:
        return None
    from firmauy.constants import DEFAULT_PKCS11_LIB
    return (f"A 64-bit Python cannot load the 32-bit gclib.dll. Use the 64-bit one: "
            f"{DEFAULT_PKCS11_LIB}")


def _doctor_pkcs11(add, pkcs11_lib: str) -> None:
    """PKCS#11-backend checks: the middleware module and the token it exposes."""
    lib = None
    if Path(pkcs11_lib).exists():
        add("PASS", "PKCS#11 module present", pkcs11_lib)
        try:
            lib = load_pkcs11_lib(pkcs11_lib)
            add("PASS", "PKCS#11 module loads")
        except Exception as exc:
            fix = "The module is present but could not be initialised; check the middleware install."
            if _platform.WINDOWS:
                fix = _wrong_bitness_fix(pkcs11_lib) or fix
            add("FAIL", "PKCS#11 module loads", _format_error(exc), fix=fix)
    elif _platform.WINDOWS:
        add("FAIL", "PKCS#11 module present", f"not found: {pkcs11_lib}",
            fix=_wrong_bitness_fix(pkcs11_lib)
            or "Install Thales Classic Client (the cédula middleware), or pass --pkcs11-lib.")
    else:
        add("FAIL", "PKCS#11 module present", f"not found: {pkcs11_lib}",
            fix="Install the middleware (Arch: yay -S cedula-uruguay-pkcs11), or pass --pkcs11-lib.")

    if lib is None:
        return
    try:
        tokens = list(lib.get_tokens())
    except Exception:
        tokens = []
    if tokens:
        label = (getattr(tokens[0], "label", "") or "").strip() or "<no label>"
        extra = f" (+{len(tokens) - 1} more)" if len(tokens) > 1 else ""
        # The token label is the cardholder's name with some modules (OpenSC's cédula driver does
        # this), and a generic string with others. Marked sensitive either way: the consumer cannot
        # tell which module produced it, and must not have to guess.
        add("PASS", "cédula token detected", f"{label}{extra}", sensitive=True)
    else:
        add("WARN", "cédula token detected", "no card found",
            fix="Insert the cédula and check the reader connection / Smart Card service."
            if _platform.WINDOWS else "Insert the cédula and check the reader connection / pcscd.")


_SCARDSVR_FIX = ("Connect the reader; Windows starts the Smart Card service (SCardSvr) on its "
                 "own.")


def _doctor_smart_card_service(add) -> None:
    """The Windows counterpart of the pcscd check: can PC/SC be reached at all?

    Windows' PC/SC is the Smart Card service (SCardSvr), and it is trigger-started: stopped is its
    normal state until a reader is plugged in, so a stopped service is not a finding. Its state is
    therefore not what is asked. What is asked is whether listing readers works, through pyscard,
    which is what both backends then depend on. With no reader ever connected that fails with
    SCARD_E_NO_SERVICE, and the fix is the same one: connect the reader.
    """
    from firmauy.card_reader import list_readers

    try:
        list_readers()
    except Exception as exc:
        add("WARN", "Smart Card service available", _format_error(exc.__cause__ or exc),
            fix=_SCARDSVR_FIX)
    else:
        add("PASS", "Smart Card service available")


def _doctor_native(add, reader: Optional[str]) -> None:
    """Native (PC/SC) checks: a reader is present and the cédula answers, no PKCS#11 module."""
    from firmauy.card_reader import list_readers, open_reader, select_applet

    try:
        available = list_readers()
    except Exception as exc:
        if _platform.WINDOWS:
            add("WARN", "PC/SC reader detected", _format_error(exc.__cause__ or exc),
                fix=_SCARDSVR_FIX)
        else:
            add("WARN", "PC/SC reader detected", _format_error(exc),
                fix="Install the smart-card stack (sudo pacman -S pcsclite ccid) and start pcscd.")
        return
    if not available:
        add("WARN", "PC/SC reader detected", "none found",
            fix="Connect a reader and check that Windows lists it under \"Smart card readers\" "
                "in Device Manager." if _platform.WINDOWS
            else "Connect a reader and make sure pcscd is running.")
        return
    add("PASS", "PC/SC reader detected", ", ".join(str(r) for r in available))

    # Confirm the cédula answers over PC/SC: open the reader and select the IAS applet (no PIN).
    try:
        conn = open_reader(reader)
    except Exception as exc:
        add("WARN", "cédula detected", _format_error(exc),
            fix="Insert the cédula, or pass --reader if you have more than one reader.")
        return
    try:
        select_applet(conn)
        add("PASS", "cédula detected", "IAS applet selected")
    except Exception as exc:
        add("WARN", "cédula detected", _format_error(exc),
            fix="A card is present but did not answer as a cédula; check it is the right card.")
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass


def _collect_doctor_checks(native: bool, reader: Optional[str], pkcs11_lib: str) -> list:
    """Gather every diagnostic check as a list of ``{status, name, detail, fix, sensitive}`` dicts.

    Pure data gathering: it probes the environment but does no printing and never exits, so the
    ``doctor`` CLI command and the public API (:func:`firmauy.api.run_doctor`) share one source
    of truth. ``status`` is PASS / WARN / FAIL. With ``native`` the PC/SC reader and card are
    checked; otherwise the PKCS#11 middleware module at ``pkcs11_lib``.

    ``sensitive`` says whether ``detail`` can carry the cardholder's own data, so a consumer that
    must not leak it (an MCP server handing results to a model, a log shipper) can decide without
    parsing text. It is set per check rather than inferred: only the token label is marked, because
    some PKCS#11 modules use the holder's name for it. Every check carries the key, so a consumer
    can treat a missing one as sensitive and fail closed.
    """
    import platform
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _pkg_version

    checks: list = []

    def add(status: str, name: str, detail: str = "", fix: Optional[str] = None,
            sensitive: bool = False) -> None:
        checks.append({"status": status, "name": name, "detail": detail, "fix": fix,
                       "sensitive": sensitive})

    try:
        v = _pkg_version("firmauy")
    except PackageNotFoundError:
        v = "unknown"
    add("PASS", "firmauy", f"{v} (Python {platform.python_version()})")

    # PC/SC is needed by both backends (the PKCS#11 middleware and native both talk through it).
    # On Linux that is pcscd; on Windows the Smart Card service, a row of its own on purpose.
    if _platform.WINDOWS:
        _doctor_smart_card_service(add)
    elif any(Path(s).exists() for s in _PCSCD_SOCKETS):
        add("PASS", "pcscd running")
    elif shutil.which("pcscd"):
        add("WARN", "pcscd running", "installed but not running",
            fix="Start it: sudo systemctl enable --now pcscd")
    else:
        add("WARN", "pcscd running", "not found",
            fix="Install the smart-card stack: sudo pacman -S pcsclite ccid")

    if native:
        _doctor_native(add, reader)
    else:
        _doctor_pkcs11(add, pkcs11_lib)

    roots, intermediates = load_bundled_trust_anchors()
    if roots and intermediates:
        add("PASS", "bundled national CA certificates", "root + intermediate loaded")
    else:
        add("FAIL", "bundled national CA certificates", "not loadable",
            fix="The package install looks broken; reinstall firmauy.")

    return checks
