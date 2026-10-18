"""
Tests for the file-drop server (pytest).

Two layers:
  * helper tests  - pure unit tests for the parsing/sanitizing helpers.
  * server tests  - integration tests against a real server instance bound to an
                    ephemeral port on 127.0.0.1, driven over HTTP.

Run:  pytest -v
"""

import http.client
import json
import os
import threading
from http.server import ThreadingHTTPServer
from types import SimpleNamespace
from typing import Dict
from typing import Iterator
from typing import Optional
from typing import Tuple

import pytest

import server

TOKEN = "test-token-abc123"


# --------------------------------------------------------------------------
# Helpers shared by the tests
# --------------------------------------------------------------------------


def do_request(
    port: int,
    method: str,
    path: str = "/upload",
    body: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[int, bytes, Dict[str, str]]:
    """Make one HTTP request on a fresh connection; return (status, body, headers)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, data, hdrs
    finally:
        conn.close()


def auth(**extra: str) -> Dict[str, str]:
    """Headers carrying the valid test token, plus any ``extra`` ones."""
    headers = {"Authorization": "Bearer " + TOKEN}
    headers.update(extra)
    return headers


@pytest.fixture(scope="module")
def live(tmp_path_factory: pytest.TempPathFactory) -> Iterator[SimpleNamespace]:
    """A real server on an ephemeral port, storing into a temp dir."""
    root = tmp_path_factory.mktemp("uploads")
    server.configure({
        "host": "127.0.0.1",
        "port": 0,
        "upload_root": str(root),
        "max_upload_bytes": 1073741824,
        "api_token": TOKEN,
    })
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.DropHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield SimpleNamespace(port=httpd.server_address[1], root=str(root))
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


@pytest.fixture(autouse=True)
def fresh_limiter() -> Iterator[None]:
    """Every test starts with no failed attempts on record."""
    yield
    server.LIMITER.reset()


def client_dir(live: SimpleNamespace, name: str) -> str:
    """Path of a client's upload folder inside the test upload root."""
    return os.path.join(live.root, name)


# --------------------------------------------------------------------------
# Unit tests for the helpers
# --------------------------------------------------------------------------


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
    assert server.safe_filename(raw) == expected


def test_safe_filename_truncates():
    assert len(server.safe_filename("x" * 500)) == 200


def test_create_unique_adds_suffix_on_clash(tmp_path):
    names = []
    for _ in range(3):
        fd, name = server.create_unique(str(tmp_path), "LICENSE.txt")
        os.close(fd)
        names.append(name)
    assert names == ["LICENSE.txt", "LICENSE-1.txt", "LICENSE-2.txt"]


def test_parse_multipart_extracts_file():
    boundary = b"BOUNDARY123"
    body = (
        b"--BOUNDARY123\r\n"
        b'Content-Disposition: form-data; name="file"; filename="a.bin"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n"
        b"\x00\x01hello"
        b"\r\n--BOUNDARY123--\r\n"
    )
    parts = server.parse_multipart(body, boundary)
    assert len(parts) == 1
    name, filename, ctype, data = parts[0]
    assert (name, filename, ctype, data) == ("file", "a.bin", "application/octet-stream", b"\x00\x01hello")


def test_parse_multipart_ignores_non_file_fields():
    boundary = b"B"
    body = (
        b"--B\r\n"
        b'Content-Disposition: form-data; name="note"\r\n\r\n'
        b"just a field"
        b"\r\n--B--\r\n"
    )
    assert server.parse_multipart(body, boundary) == []


# --------------------------------------------------------------------------
# Method handling
# --------------------------------------------------------------------------


def test_get_is_404_without_allow_header(live):
    status, _, hdrs = do_request(live.port, "GET")
    assert status == 404
    assert "allow" not in hdrs


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
def test_other_methods_are_404_without_allow_header(live, method):
    status, _, hdrs = do_request(live.port, method, headers=auth())
    assert status == 404
    assert "allow" not in hdrs


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------


def test_post_without_token_is_401(live):
    status, body, hdrs = do_request(live.port, "POST", body=b"data", headers={"X-Filename": "a.txt"})
    assert status == 401
    assert "www-authenticate" in hdrs
    assert json.loads(body)["error"] == "missing credentials"


def test_post_with_wrong_token_is_403(live):
    status, body, _ = do_request(
        live.port, "POST", body=b"data",
        headers={"Authorization": "Bearer nope", "X-Filename": "a.txt"},
    )
    assert status == 403
    assert json.loads(body)["error"] == "invalid credentials"


def test_x_api_key_header_also_authenticates(live):
    status, _, _ = do_request(
        live.port, "POST", body=b"hi",
        headers={"X-API-Key": TOKEN, "X-Client-Id": "apikey-client", "X-Filename": "k.txt"},
    )
    assert status == 201


def test_repeated_wrong_tokens_lock_the_address_out(live):
    for _ in range(5):
        status, _, _ = do_request(live.port, "POST", body=b"x",
                                  headers={"Authorization": "Bearer nope", "X-Filename": "a"})
        assert status == 403
    status, body, hdrs = do_request(live.port, "POST", body=b"x", headers=auth(**{"X-Filename": "a"}))
    assert status == 429  # even the right token waits out the lockout
    assert int(hdrs["retry-after"]) > 0
    assert json.loads(body)["error"] == "too many failed attempts"


def test_non_ascii_token_is_rejected_not_crashing(live):
    status, _, _ = do_request(live.port, "POST", body=b"x",
                              headers={"Authorization": "Bearer t\u00f6ken", "X-Filename": "a"})
    assert status == 403


def test_no_token_configured_is_503(live, monkeypatch):
    monkeypatch.setattr(server, "API_TOKEN", "")
    status, _, _ = do_request(live.port, "POST", body=b"x", headers=auth(**{"X-Filename": "a"}))
    assert status == 503


# --------------------------------------------------------------------------
# Routing / validation
# --------------------------------------------------------------------------


def test_wrong_path_is_404(live):
    status, _, _ = do_request(live.port, "POST", path="/elsewhere",
                              body=b"x", headers=auth(**{"X-Filename": "a"}))
    assert status == 404


def test_empty_body_is_400(live):
    status, _, _ = do_request(live.port, "POST", body=b"", headers=auth(**{"X-Filename": "a"}))
    assert status == 400


def test_too_large_is_413(live, monkeypatch):
    monkeypatch.setattr(server, "MAX_BYTES", 10)
    status, _, _ = do_request(live.port, "POST", body=b"x" * 50, headers=auth(**{"X-Filename": "a"}))
    assert status == 413


# --------------------------------------------------------------------------
# Successful uploads
# --------------------------------------------------------------------------


def test_raw_upload_stores_file_and_metadata(live):
    payload = b"hello from alice\n"
    status, body, _ = do_request(
        live.port, "POST", body=payload,
        headers=auth(**{
            "X-Client-Id": "alice-laptop",
            "X-Filename": "report.txt",
            "X-Client-Host": "alice-pc",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
        }),
    )
    assert status == 201
    meta = json.loads(body)["files"][0]
    assert meta["client"] == "alice-laptop"
    assert meta["original_filename"] == "report.txt"
    assert meta["size"] == len(payload)
    assert "os" not in meta
    assert meta["hostname_claimed"] == "alice-pc"
    assert meta["source_ip"] == "127.0.0.1"

    day, name = meta["path"].split("/")
    assert name == "report.txt"
    assert day == meta["received_at"][:10]

    stored = os.path.join(client_dir(live, "alice-laptop"), meta["path"])
    with open(stored, "rb") as fh:
        assert fh.read() == payload
    # Only the file itself sits in the day folder: no sidecars.
    assert os.listdir(os.path.dirname(stored)) == ["report.txt"]
    with open(os.path.join(client_dir(live, "alice-laptop"), "uploads.jsonl")) as fh:
        assert json.loads(fh.readline()) == meta


def test_same_name_twice_is_not_overwritten(live):
    paths = []
    for payload in (b"first", b"second"):
        status, body, _ = do_request(
            live.port, "POST", body=payload,
            headers=auth(**{"X-Client-Id": "dupes", "X-Filename": "LICENSE.txt"}),
        )
        assert status == 201
        paths.append(json.loads(body)["files"][0]["path"])
    assert [p.split("/")[1] for p in paths] == ["LICENSE.txt", "LICENSE-1.txt"]
    with open(os.path.join(client_dir(live, "dupes"), paths[0]), "rb") as fh:
        assert fh.read() == b"first"


def test_multipart_upload_preserves_binary(live):
    blob = bytes(range(256)) * 4  # 1024 bytes incl. NULs and high bytes
    boundary = "----testboundary987"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="photo.bin"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + blob + f"\r\n--{boundary}--\r\n".encode()
    status, resp, _ = do_request(
        live.port, "POST", body=body,
        headers=auth(**{
            "X-Client-Id": "bob-desktop",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        }),
    )
    assert status == 201
    meta = json.loads(resp)["files"][0]
    assert meta["original_filename"] == "photo.bin"
    assert meta["size"] == len(blob)
    stored = os.path.join(client_dir(live, "bob-desktop"), meta["path"])
    with open(stored, "rb") as fh:
        assert fh.read() == blob


def test_missing_client_id_falls_back_to_ip(live):
    status, body, _ = do_request(
        live.port, "POST", body=b"anon", headers=auth(**{"X-Filename": "f.txt"}),
    )
    assert status == 201
    assert json.loads(body)["files"][0]["client"] == "ip-127.0.0.1"
    assert os.path.isdir(client_dir(live, "ip-127.0.0.1"))


def test_reserved_client_names_are_renamed(live):
    status, body, _ = do_request(
        live.port, "POST", body=b"x",
        headers=auth(**{"X-Client-Id": "_logs", "X-Filename": "f.txt"}),
    )
    assert status == 201
    assert json.loads(body)["client"] == "logs"


def test_admin_ui_is_off_without_a_password(live):
    status, body, _ = do_request(live.port, "GET", path="/admin/login")
    assert status == 404
    assert json.loads(body) == {"error": "not found"}


def test_two_client_ids_two_folders(live):
    for cid in ("team-a", "team-b"):
        status, _, _ = do_request(
            live.port, "POST", body=b"x",
            headers=auth(**{"X-Client-Id": cid, "X-Filename": "f.txt"}),
        )
        assert status == 201
    assert os.path.isdir(client_dir(live, "team-a"))
    assert os.path.isdir(client_dir(live, "team-b"))


def test_filename_traversal_is_contained(live):
    status, body, _ = do_request(
        live.port, "POST", body=b"evil",
        headers=auth(**{"X-Client-Id": "trav", "X-Filename": "../../../../etc/passwd"}),
    )
    assert status == 201
    meta = json.loads(body)["files"][0]
    assert meta["original_filename"] == "passwd"
    assert ".." not in meta["path"]
    stored = os.path.realpath(os.path.join(client_dir(live, "trav"), meta["path"]))
    assert stored.startswith(os.path.realpath(client_dir(live, "trav")) + os.sep)


def test_access_log_records_events(live):
    do_request(live.port, "POST", body=b"x", headers={"X-Filename": "a"})  # 401
    do_request(live.port, "POST", body=b"x",
               headers=auth(**{"X-Client-Id": "logtest", "X-Filename": "notes-2026.txt"}))  # 201
    with open(os.path.join(live.root, "_logs", "access.log")) as fh:
        log = fh.read()
    assert "AUTH-MISSING" in log
    assert "UPLOAD" in log
    assert "logtest" in log
    assert "notes-2026.txt" in log  # filename recorded in the log line
