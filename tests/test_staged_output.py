"""The output staging and commit, on every platform: signing._staged_output and its callers.

The Windows branch (signing._staged_output_windows) is also run off Windows by flipping the
platform seam, because nothing in it is Windows-only except what Windows refuses: closing before
the commit is just as correct on POSIX. What only Windows refuses (renaming, linking or deleting a
file that is open) is exercised for real on the Windows CI runner. The POSIX access-control tests
stay in test_cli.py.
"""

import sys
import threading

import pytest

from firmauy import _platform, signing
from firmauy.errors import OutputExistsError
from firmauy.signing import _atomic_write_bytes, _staged_output

# Every byte value, and every line ending in both orders, so a text-mode descriptor anywhere on the
# way shows up as a difference instead of slipping through.
_PAYLOAD = bytes(range(256)) + b"line\nCRLF\r\nCR\rLF-CR\n\r%%EOF\n"


@pytest.fixture(params=["windows", "posix"])
def branch(request, monkeypatch):
    """Run a test against each staging branch this machine can run: the POSIX one needs fchmod and
    the rest of POSIX, so on Windows only the Windows one runs."""
    if request.param == "posix" and sys.platform == "win32":
        pytest.skip("the POSIX branch needs POSIX")
    monkeypatch.setattr(_platform, "WINDOWS", request.param == "windows")
    return request.param


def _leftovers(directory):
    return sorted(p.name for p in directory.iterdir() if p.name.startswith(".firmauy-"))


# --- committing -------------------------------------------------------------------------------

@pytest.mark.parametrize("overwrite", [False, True])
def test_a_new_file_is_written_byte_for_byte(tmp_path, branch, overwrite):
    out = tmp_path / "x.pdf"

    with _staged_output(out, overwrite=overwrite) as f:
        f.write(_PAYLOAD)

    assert out.read_bytes() == _PAYLOAD
    assert _leftovers(tmp_path) == []


def test_an_existing_file_is_replaced(tmp_path, branch):
    out = tmp_path / "x.xml"
    out.write_bytes(b"old")

    _atomic_write_bytes(out, _PAYLOAD, overwrite=True)

    assert out.read_bytes() == _PAYLOAD
    assert _leftovers(tmp_path) == []


def test_without_overwrite_an_existing_file_is_refused(tmp_path, branch):
    out = tmp_path / "x.xml"
    out.write_bytes(b"keep me")

    with pytest.raises(OutputExistsError):
        _atomic_write_bytes(out, _PAYLOAD, overwrite=False)

    assert out.read_bytes() == b"keep me"
    assert _leftovers(tmp_path) == []


def test_without_overwrite_a_file_appearing_mid_signing_survives(tmp_path, branch):
    """The callers' early exists() check cannot be the guarantee: the commit refuses by itself."""
    out = tmp_path / "x.xml"

    with pytest.raises(OutputExistsError):
        with _staged_output(out, overwrite=False) as f:
            f.write(_PAYLOAD)
            out.write_bytes(b"arrived meanwhile")

    assert out.read_bytes() == b"arrived meanwhile"
    assert _leftovers(tmp_path) == []


# --- failing ----------------------------------------------------------------------------------

@pytest.mark.parametrize("overwrite", [False, True])
def test_an_exception_inside_the_with_leaves_no_part_file(tmp_path, branch, overwrite):
    out = tmp_path / "x.pdf"
    if overwrite:
        out.write_bytes(b"PREVIOUS GOOD OUTPUT")

    with pytest.raises(RuntimeError, match="card removed"):
        with _staged_output(out, overwrite=overwrite) as f:
            f.write(b"%PDF-1.7 partial\n")
            raise RuntimeError("card removed mid-signing (simulated)")

    assert _leftovers(tmp_path) == []
    if overwrite:
        assert out.read_bytes() == b"PREVIOUS GOOD OUTPUT"
    else:
        assert not out.exists()


def test_a_failed_commit_leaves_no_part_file(tmp_path, branch, monkeypatch):
    import os

    def refuse(src, dst):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(os, "replace", refuse)
    out = tmp_path / "x.xml"
    out.write_bytes(b"old")

    with pytest.raises(PermissionError):
        _atomic_write_bytes(out, _PAYLOAD, overwrite=True)

    assert out.read_bytes() == b"old"
    assert _leftovers(tmp_path) == []


@pytest.mark.skipif(sys.platform != "win32", reason="Windows refuses to delete an open file")
def test_a_part_file_held_open_elsewhere_is_still_removed(tmp_path):
    """Something else (a scanner, the indexer) has the staging file open when signing fails, and
    Windows refuses the delete while it does. The cleanup waits it out."""
    out = tmp_path / "x.pdf"
    with pytest.raises(RuntimeError, match="simulated"):
        with _staged_output(out, overwrite=False) as f:
            f.write(b"partial")
            (staging,) = tmp_path.glob(".firmauy-*.part")
            holder = open(staging, "rb")        # Python's open() does not share delete access
            threading.Timer(0.15, holder.close).start()
            raise RuntimeError("simulated")

    assert _leftovers(tmp_path) == []
    assert not out.exists()


# --- links at the output ----------------------------------------------------------------------

def test_a_symlink_at_the_output_is_replaced_not_followed(tmp_path, branch, symlinks):
    target = tmp_path / "target.txt"
    target.write_bytes(b"DO NOT TOUCH")
    out = tmp_path / "x.xml"
    out.symlink_to(target)

    _atomic_write_bytes(out, _PAYLOAD, overwrite=True)

    assert not out.is_symlink()
    assert out.read_bytes() == _PAYLOAD
    assert target.read_bytes() == b"DO NOT TOUCH"
    assert _leftovers(tmp_path) == []


def test_without_overwrite_a_dangling_symlink_counts_as_occupied(tmp_path, branch, symlinks):
    out = tmp_path / "x.xml"
    out.symlink_to(tmp_path / "nowhere")

    with pytest.raises(OutputExistsError):
        _atomic_write_bytes(out, _PAYLOAD, overwrite=False)

    assert out.is_symlink()
    assert _leftovers(tmp_path) == []


# --- what the Windows branch reads off a file it replaces -------------------------------------

@pytest.fixture
def windows(monkeypatch):
    monkeypatch.setattr(_platform, "WINDOWS", True)


def test_a_regular_file_has_nothing_to_carry_across(tmp_path, windows):
    out = tmp_path / "x.pdf"
    out.write_bytes(b"old")

    replaced = signing._capture_replaced(out)

    assert replaced is not None and replaced.acl is signing._ACL_UNSUPPORTED


def test_nothing_there_or_not_a_file_is_nothing_to_adopt(tmp_path, windows):
    assert signing._capture_replaced(tmp_path / "absent.pdf") is None
    (tmp_path / "dir.pdf").mkdir()
    assert signing._capture_replaced(tmp_path / "dir.pdf") is None


def test_a_link_is_not_the_file_being_replaced(tmp_path, windows, symlinks):
    target = tmp_path / "target.pdf"
    target.write_bytes(b"x")
    out = tmp_path / "x.pdf"
    out.symlink_to(target)

    assert signing._capture_replaced(out) is None


def test_a_file_swapped_between_the_check_and_the_open_is_caught(tmp_path, windows, monkeypatch):
    """The open follows whatever is at the path by then. The identity comparison is what notices
    that this is no longer the file that was looked at, and the adoption starts over."""
    import os

    out = tmp_path / "x.pdf"
    out.write_bytes(b"looked at")
    other = tmp_path / "other.pdf"
    other.write_bytes(b"swapped in")
    real_open = os.open
    swaps = []

    def swap_then_open(path, flags, *args):
        if not swaps:
            swaps.append(path)
            os.replace(other, out)
        return real_open(path, flags, *args)

    monkeypatch.setattr(os, "open", swap_then_open)
    with pytest.raises(signing._Moved):
        signing._capture_replaced(out)

    monkeypatch.setattr(os, "open", real_open)
    assert signing._adopt_replaced(None, out) is not None   # the next attempt is clean


# --- --input-dir re-open, through the Windows branch ------------------------------------------

def test_a_listed_file_is_reopened_when_unchanged_and_refused_when_swapped(tmp_path, windows):
    import os

    path = tmp_path / "a.pdf"
    path.write_bytes(b"original\r\n")
    identity = signing._input_identity(path)

    with signing._open_input(path, identity) as f:
        assert f.read() == b"original\r\n"          # binary: no \r\n folded into \n

    replacement = tmp_path / "other.pdf"
    replacement.write_bytes(b"something else")
    os.replace(replacement, path)
    with pytest.raises(RuntimeError, match="changed after --input-dir was listed"):
        signing._open_input(path, identity)


def test_a_listed_file_replaced_by_a_link_is_refused_on_windows_too(tmp_path, windows, symlinks):
    path = tmp_path / "a.pdf"
    path.write_bytes(b"original")
    identity = signing._input_identity(path)
    private = tmp_path / "private.pdf"
    private.write_bytes(b"not for signing")
    path.unlink()
    path.symlink_to(private)

    with pytest.raises(RuntimeError, match="changed after --input-dir was listed"):
        signing._open_input(path, identity)


# --- the national CA cache --------------------------------------------------------------------

def test_the_cache_write_replaces_an_existing_file(tmp_path, branch):
    from firmauy.national_ca import _atomic_cache_write

    dest = tmp_path / "acrn.pem"
    dest.write_bytes(b"old")

    _atomic_cache_write(dest, _PAYLOAD)

    assert dest.read_bytes() == _PAYLOAD
    assert [p.name for p in tmp_path.iterdir()] == ["acrn.pem"]


# --- the whole way through the public API -----------------------------------------------------

@pytest.fixture
def software_card(monkeypatch):
    """A signing session backed by a key in memory, standing in for the cédula. Everything after
    the session (the per-format signers, the staging, the commit) is the shipped code."""
    import datetime
    from contextlib import contextmanager

    from asn1crypto import keys as asn1keys
    from asn1crypto import x509 as asn1x509
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509.oid import NameOID
    from pyhanko.sign.signers import SimpleSigner
    from pyhanko_certvalidator.registry import SimpleCertificateStore

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TEST SIGNER")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256()))

    def pyhanko_signer():
        return SimpleSigner(
            signing_cert=asn1x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER)),
            signing_key=asn1keys.PrivateKeyInfo.load(key.private_bytes(
                serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption())),
            cert_registry=SimpleCertificateStore())

    def raw_signer():
        return lambda data: key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    @contextmanager
    def session(**kwargs):
        yield signing._SigningContext(
            cert=cert, signer_name="TEST SIGNER", issuer_name="TEST SIGNER", cert_serial="1",
            source_caption="Reader", source_display="software", key_id=None,
            pyhanko_signer_factory=pyhanko_signer, raw_signer_factory=raw_signer)

    monkeypatch.setattr(signing, "_signing_session", session)


def test_sign_files_writes_pdf_xml_and_p7s_new_and_over_existing(tmp_path, software_card):
    """The brief's acceptance case, minus the card: a PDF, an XML and a detached .p7s, first to new
    names, then over the files that run produced, with nothing staged left behind."""
    from firmauy.api import BatchSignError, sign_files
    from test_cli import _valid_pdf_bytes

    pdf = tmp_path / "doc.pdf"
    pdf.write_bytes(_valid_pdf_bytes())
    xml = tmp_path / "doc.xml"
    xml.write_bytes(b"<?xml version=\"1.0\"?>\n<root>\n  <a>1</a>\n</root>\n")
    txt = tmp_path / "doc.txt"
    txt.write_bytes(b"line one\r\nline two\n")
    out = tmp_path / "out"

    first = sign_files([pdf, xml, txt], pin="0000", native=True, output_dir=out)
    outputs = [r.output_path for r in first]
    assert [p.suffix for p in outputs] == [".pdf", ".xml", ".p7s"]
    signed_pdf = outputs[0].read_bytes()
    assert signed_pdf.startswith(pdf.read_bytes())  # an incremental update, bytes untouched
    assert b"Signature" in outputs[1].read_bytes()
    assert outputs[2].read_bytes()[:1] == b"\x30"   # DER SEQUENCE
    assert _leftovers(out) == []

    with pytest.raises(BatchSignError) as refused:
        sign_files([pdf], pin="0000", native=True, output_dir=out)
    assert isinstance(refused.value.__cause__, OutputExistsError)
    assert outputs[0].read_bytes() == signed_pdf

    again = sign_files([pdf, xml, txt], pin="0000", native=True, output_dir=out, overwrite=True)
    assert [r.output_path for r in again] == outputs
    assert outputs[0].read_bytes() != signed_pdf    # a fresh signature, not the old file
    assert _leftovers(out) == []
