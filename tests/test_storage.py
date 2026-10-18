"""
Unit tests for storage.py (pytest): file names, writing without overwriting,
and reading uploads back, all in a temporary folder.

Run:  pytest -v
"""

import json
import os

import pytest

from file_dropbox import storage


@pytest.mark.parametrize("raw, expected", [
    ("../../etc/passwd", "passwd"),
    ("..\\..\\win.ini", "win.ini"),
    ("/abs/path/report.pdf", "report.pdf"),
    ("a b*c?.txt", "a b_c_.txt"),
    ("", "file"),
    ("...", "file"),
    (None, "file"),
])
def test_safe_filename(raw, expected):
    assert storage.safe_filename(raw) == expected


def test_safe_filename_truncates():
    assert len(storage.safe_filename("x" * 500)) == 200


def test_create_unique_adds_suffix_on_clash(tmp_path):
    names = []
    for _ in range(3):
        fd, name = storage.create_unique(str(tmp_path), "LICENSE.txt")
        os.close(fd)
        names.append(name)
    assert names == ["LICENSE.txt", "LICENSE-1.txt", "LICENSE-2.txt"]


def test_save_file_and_index_round_trip(tmp_path):
    root = str(tmp_path)
    rel = storage.save_file(root, "alice", "2026-10-15", "../report.pdf", b"data")
    assert rel == "2026-10-15/report.pdf"
    assert storage.save_file(root, "alice", "2026-10-15", "report.pdf", b"more") == "2026-10-15/report-1.pdf"

    storage.append_index(root, "alice", {"path": rel, "size": 4})
    with open(os.path.join(root, "alice", storage.INDEX_NAME)) as fh:
        assert json.loads(fh.readline()) == {"path": rel, "size": 4}
    assert storage.read_meta(root, "alice", rel) == {"path": rel, "size": 4}
    assert storage.read_meta(root, "alice", "2026-10-15/report-1.pdf") == {}


def test_listing_skips_index_logs_and_symlinks(tmp_path):
    root = str(tmp_path)
    storage.save_file(root, "alice", "2026-10-15", "a.txt", b"a")
    storage.append_index(root, "alice", {"path": "2026-10-15/a.txt"})
    os.makedirs(os.path.join(root, "_logs"))
    os.symlink("/etc/hostname", os.path.join(root, "alice", "2026-10-15", "link.txt"))
    with open(os.path.join(root, "alice", "old.txt"), "w") as fh:  # pre-day-folder layout
        fh.write("old")

    assert sorted(f.rel for f in storage.list_files(root, "alice")) == ["2026-10-15/a.txt", "old.txt"]
    [summary] = storage.list_clients(root)
    assert (summary.name, summary.files, summary.size) == ("alice", 2, 4)


@pytest.mark.parametrize("client, rel", [
    ("alice", "../../etc/passwd"),
    ("alice", "2026-10-15/../../x"),
    ("alice", "not-a-day/a.txt"),
    ("alice", "uploads.jsonl"),
    ("_logs", "access.log"),
    ("..", "alice/2026-10-15/a.txt"),
    ("alice", "2026-10-15/missing.txt"),
])
def test_resolve_file_refuses_anything_but_stored_files(tmp_path, client, rel):
    storage.save_file(str(tmp_path), "alice", "2026-10-15", "a.txt", b"a")
    assert storage.resolve_file(str(tmp_path), client, rel) is None


def test_resolve_file_finds_stored_files(tmp_path):
    root = str(tmp_path)
    rel = storage.save_file(root, "alice", "2026-10-15", "a.txt", b"a")
    assert storage.resolve_file(root, "alice", rel) == os.path.join(root, "alice", "2026-10-15", "a.txt")


@pytest.mark.parametrize("name, data, kind", [
    ("notes.txt", b"hello\n", "text"),
    ("empty.txt", b"", "empty"),
    ("blob.bin", b"\x00\x01\x02", "binary"),
    ("photo.png", b"\x89PNG", "image"),
])
def test_load_preview_kinds(tmp_path, name, data, kind):
    path = tmp_path / name
    path.write_bytes(data)
    assert storage.load_preview(str(path)).kind == kind
