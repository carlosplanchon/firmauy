# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""The files a signature is made over: a listed file is the file that was listed.

--input-dir is checked when it is listed, and signed some time later, after the PIN. Whoever can
write to the folder can put something else in a file's place in between: another file, a link, a
FIFO, or a link where a directory was. Each of those is refused when the file is opened, without
blocking. A file named as an argument is opened as named, links included, because that is the
documented way to sign a linked file on purpose.
"""

import os
import sys
import threading

import pytest

from firmauy import signing
from firmauy.signing import _input_identity, _open_input


def _listed(path):
    """What --input-dir recorded for ``path`` when it listed it."""
    return _input_identity(path)


def test_an_argument_is_opened_as_named_links_included(tmp_path, symlinks):
    target = tmp_path / "target.pdf"
    target.write_bytes(b"original")
    link = tmp_path / "link.pdf"
    link.symlink_to(target)

    with _open_input(link) as f:
        assert f.read() == b"original"


def test_a_listed_file_that_did_not_change_is_opened(tmp_path):
    path = tmp_path / "a.pdf"
    path.write_bytes(b"original")

    with _open_input(path, _listed(path)) as f:
        assert f.read() == b"original"


def test_a_listed_file_replaced_by_another_is_refused(tmp_path):
    path = tmp_path / "a.pdf"
    path.write_bytes(b"original")
    identity = _listed(path)
    replacement = tmp_path / "other.pdf"
    replacement.write_bytes(b"something else")
    os.replace(replacement, path)

    with pytest.raises(RuntimeError, match="changed after --input-dir was listed"):
        _open_input(path, identity)


def test_a_listed_file_replaced_by_a_link_is_refused(tmp_path, symlinks):
    path = tmp_path / "a.pdf"
    path.write_bytes(b"original")
    identity = _listed(path)
    private = tmp_path / "private.pdf"
    private.write_bytes(b"not for signing")
    path.unlink()
    path.symlink_to(private)

    with pytest.raises(RuntimeError, match="changed after --input-dir was listed"):
        _open_input(path, identity)


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has no FIFOs")
def test_a_listed_file_replaced_by_a_fifo_is_refused_without_blocking(tmp_path):
    """Opening a FIFO for reading waits for a writer that never comes, which would hang the
    batch after the PIN. Run in a thread so a regression fails the test instead of hanging it."""
    path = tmp_path / "a.pdf"
    path.write_bytes(b"original")
    identity = _listed(path)
    path.unlink()
    os.mkfifo(path)

    outcome = {}

    def attempt():
        try:
            _open_input(path, identity)
        except Exception as exc:
            outcome["error"] = exc

    worker = threading.Thread(target=attempt, daemon=True)
    worker.start()
    worker.join(5)
    assert not worker.is_alive(), "opening the FIFO blocked"
    assert isinstance(outcome.get("error"), RuntimeError)


def test_a_directory_swapped_for_a_link_is_refused(tmp_path, symlinks):
    """O_NOFOLLOW only looks at the last component. The identity check is what catches a
    directory on the way turned into a link to somewhere else."""
    listed_dir = tmp_path / "in" / "sub"
    listed_dir.mkdir(parents=True)
    path = listed_dir / "a.pdf"
    path.write_bytes(b"original")
    identity = _listed(path)

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "a.pdf").write_bytes(b"not for signing")
    (listed_dir / "a.pdf").unlink()
    listed_dir.rmdir()
    listed_dir.symlink_to(elsewhere, target_is_directory=True)

    with pytest.raises(RuntimeError, match="changed after --input-dir was listed"):
        _open_input(path, identity)


def test_an_xml_past_the_limit_is_refused_without_being_read_whole(tmp_path, monkeypatch):
    source = tmp_path / "input.xml"
    source.write_bytes(b"<root>" + b"x" * 64 + b"</root>")
    monkeypatch.setattr(signing, "MAX_XML_BYTES", 16)

    with pytest.raises(ValueError, match="exceeds the 16 byte limit"):
        signing._sign_one_xml(input_xml=source, output_xml=tmp_path / "out.xml", cert=None,
                              signer=None, signing_time=None, overwrite=False)
    assert not (tmp_path / "out.xml").exists()
