"""What doctor and the reader messages tell the user, per platform, and the platform defaults.

Runs on every OS: the platform seam is flipped, not the machine. firmauy-desktop translates these
strings by their exact text, so the Linux ones are pinned here verbatim and the Windows ones are
listed in CHANGELOG.md. A change to either is a change to a public surface.
"""

import sys
from pathlib import Path

import pytest

import firmauy.card_reader as card_reader
from firmauy import _platform, _shared

# Advice a Windows user cannot follow.
_LINUX_ONLY = ("sudo", "pacman", "yay ", "systemctl", "pcscd", "pcsclite", "Arch")


def _doctor(monkeypatch, *, windows, native=False, readers=(), pkcs11_lib="/nonexistent/module"):
    monkeypatch.setattr(_platform, "WINDOWS", windows)
    if isinstance(readers, Exception):
        def failing():
            raise readers
        monkeypatch.setattr(card_reader, "list_readers", failing)
    else:
        monkeypatch.setattr(card_reader, "list_readers", lambda: list(readers))
    return _shared._collect_doctor_checks(native, None, pkcs11_lib)


def _row(checks, name):
    (row,) = [c for c in checks if c["name"] == name]
    return row


def _scard_failure():
    """What list_readers raises on Windows when the Smart Card service cannot be reached."""
    try:
        raise Exception("Failure to establish context: Smart Card service not running. (0x8010001D)")
    except Exception as cause:
        try:
            raise RuntimeError("Could not reach the Smart Card service (...)") from cause
        except RuntimeError as exc:
            return exc


# --- Linux: unchanged, word for word ----------------------------------------------------------

def test_linux_keeps_the_pcscd_row(monkeypatch):
    monkeypatch.setattr(_shared.shutil, "which", lambda name: None)
    monkeypatch.setattr(_shared, "_PCSCD_SOCKETS", ())
    checks = _doctor(monkeypatch, windows=False)

    row = _row(checks, "pcscd running")
    assert (row["status"], row["detail"], row["fix"]) == (
        "WARN", "not found", "Install the smart-card stack: sudo pacman -S pcsclite ccid")
    assert not [c for c in checks if c["name"] == "Smart Card service available"]


def test_linux_keeps_its_fix_texts(monkeypatch):
    monkeypatch.setattr(_shared, "_PCSCD_SOCKETS", ())
    assert _row(_doctor(monkeypatch, windows=False), "PKCS#11 module present")["fix"] == (
        "Install the middleware (Arch: yay -S cedula-uruguay-pkcs11), or pass --pkcs11-lib.")
    assert _row(_doctor(monkeypatch, windows=False, native=True),
                "PC/SC reader detected")["fix"] == "Connect a reader and make sure pcscd is running."
    assert _row(_doctor(monkeypatch, windows=False, native=True, readers=RuntimeError("x")),
                "PC/SC reader detected")["fix"] == (
        "Install the smart-card stack (sudo pacman -S pcsclite ccid) and start pcscd.")


def test_linux_keeps_its_reader_messages(monkeypatch):
    monkeypatch.setattr(_platform, "WINDOWS", False)
    assert card_reader.no_readers_message() == (
        "No PC/SC readers found. Is pcscd running and a reader connected?")


# --- Windows: the Smart Card service, and nothing a Windows user cannot run -------------------

def test_windows_checks_the_smart_card_service_instead_of_pcscd(monkeypatch):
    checks = _doctor(monkeypatch, windows=True)

    row = _row(checks, "Smart Card service available")
    assert (row["status"], row["detail"], row["fix"]) == ("PASS", "", None)
    assert not [c for c in checks if c["name"] == "pcscd running"]


def test_a_service_that_cannot_be_reached_is_a_warning_naming_the_cause(monkeypatch):
    row = _row(_doctor(monkeypatch, windows=True, readers=_scard_failure()),
               "Smart Card service available")

    assert row["status"] == "WARN"
    assert "0x8010001D" in row["detail"]              # the PC/SC error, not our own wrapper again
    assert row["fix"] == (
        "Connect the reader; Windows starts the Smart Card service (SCardSvr) on its own.")


@pytest.mark.parametrize("native, readers", [
    (False, ()),
    (True, ()),
    (True, ["Reader 0"]),
    (False, "failure"),
    (True, "failure"),
])
def test_windows_never_suggests_a_linux_command(monkeypatch, native, readers):
    if readers == "failure":
        readers = _scard_failure()
    checks = _doctor(monkeypatch, windows=True, native=native, readers=readers)

    for check in checks:
        text = f"{check['name']} {check['detail']} {check['fix'] or ''}"
        assert not [w for w in _LINUX_ONLY if w in text], check


def test_windows_fix_texts(monkeypatch):
    missing = _row(_doctor(monkeypatch, windows=True, pkcs11_lib=r"C:\nowhere\gclib.dll"),
                   "PKCS#11 module present")
    assert missing["fix"] == (
        "Install Thales Classic Client (the cédula middleware), or pass --pkcs11-lib.")

    none = _row(_doctor(monkeypatch, windows=True, native=True), "PC/SC reader detected")
    assert none["fix"] == ('Connect a reader and check that Windows lists it under "Smart card '
                           'readers" in Device Manager.')


def test_windows_token_fix(monkeypatch):
    class _Lib:
        def get_tokens(self):
            return []

    monkeypatch.setattr(_shared, "load_pkcs11_lib", lambda path: _Lib())
    checks = _doctor(monkeypatch, windows=True, pkcs11_lib=__file__)

    assert _row(checks, "cédula token detected")["fix"] == (
        "Insert the cédula and check the reader connection / Smart Card service.")


def test_windows_reader_messages(monkeypatch):
    monkeypatch.setattr(_platform, "WINDOWS", True)
    assert card_reader.no_readers_message() == "No PC/SC readers found. Is a reader connected?"

    smartcard_system = pytest.importorskip("smartcard.System")

    def no_service():
        raise Exception("Failure to establish context: 0x8010001D")

    monkeypatch.setattr(smartcard_system, "readers", no_service)
    with pytest.raises(RuntimeError) as failure:
        card_reader.list_readers()
    assert str(failure.value) == (
        "Could not reach the Smart Card service (Failure to establish context: 0x8010001D). "
        "Connect the reader; Windows starts the Smart Card service (SCardSvr) on its own.")


# --- the 32-bit module on a 64-bit Python -----------------------------------------------------

def _pe(path: Path, machine: int) -> str:
    """A file with just enough of a PE header to say which machine it was built for."""
    header = bytearray(0x40)
    header[:2] = b"MZ"
    header[0x3C:0x40] = (0x40).to_bytes(4, "little")
    path.write_bytes(bytes(header) + b"PE\0\0" + machine.to_bytes(2, "little") + b"\0" * 16)
    return str(path)


@pytest.mark.skipif(sys.maxsize <= 2**32, reason="the hint is for a 64-bit Python")
def test_a_32bit_module_that_fails_to_load_says_which_one_to_use(tmp_path, monkeypatch):
    from firmauy.constants import DEFAULT_PKCS11_LIB

    def not_win32(path):
        raise RuntimeError("%1 is not a valid Win32 application.")

    monkeypatch.setattr(_shared, "load_pkcs11_lib", not_win32)
    lib = _pe(tmp_path / "gclib.dll", 0x014C)
    row = _row(_doctor(monkeypatch, windows=True, pkcs11_lib=lib), "PKCS#11 module loads")

    assert row["status"] == "FAIL"
    assert row["fix"] == (
        f"A 64-bit Python cannot load the 32-bit gclib.dll. Use the 64-bit one: {DEFAULT_PKCS11_LIB}")


@pytest.mark.skipif(sys.maxsize <= 2**32, reason="the hint is for a 64-bit Python")
def test_a_64bit_module_that_fails_to_load_gets_the_ordinary_fix(tmp_path, monkeypatch):
    def broken(path):
        raise RuntimeError("CKR_GENERAL_ERROR")

    monkeypatch.setattr(_shared, "load_pkcs11_lib", broken)
    lib = _pe(tmp_path / "gclib.dll", 0x8664)
    row = _row(_doctor(monkeypatch, windows=True, pkcs11_lib=lib), "PKCS#11 module loads")

    assert row["fix"] == (
        "The module is present but could not be initialised; check the middleware install.")


@pytest.mark.skipif(sys.maxsize <= 2**32, reason="the hint is for a 64-bit Python")
def test_a_missing_module_under_program_files_x86_gets_the_bitness_hint(monkeypatch):
    lib = r"C:\Program Files (x86)\Thales\Classic Client\BIN\gclib.dll"
    if Path(lib).exists():
        pytest.skip("this machine has the 32-bit module installed, so it is not missing")
    row = _row(_doctor(monkeypatch, windows=True, pkcs11_lib=lib), "PKCS#11 module present")

    assert row["fix"].startswith("A 64-bit Python cannot load the 32-bit gclib.dll.")


# --- platform defaults ------------------------------------------------------------------------

def test_the_default_pkcs11_module_is_the_platforms_middleware():
    from firmauy.constants import DEFAULT_PKCS11_LIB

    if sys.platform == "win32":
        import os
        assert DEFAULT_PKCS11_LIB == os.path.join(
            os.environ.get("ProgramFiles", r"C:\Program Files"),
            "Thales", "Classic Client", "BIN", "gclib.dll")
    else:
        assert DEFAULT_PKCS11_LIB == "/usr/lib/pkcs11/libgclib.so"


def test_the_national_ca_cache_lives_under_localappdata_on_windows(monkeypatch, tmp_path):
    from firmauy.national_ca import cache_dir

    monkeypatch.setattr(_platform, "WINDOWS", True)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    assert cache_dir() == tmp_path / "Local" / "firmauy" / "national-ca"

    monkeypatch.setattr(_platform, "WINDOWS", False)
    assert cache_dir() == tmp_path / "xdg" / "firmauy" / "national-ca"
