"""
Tests for the admin web UI (pytest): sign-in, lockout, browsing, previews and
downloads, against a real server on an ephemeral port.

Run:  pytest -v
"""

import http.client
import json
import os
import re
import threading
from http.server import ThreadingHTTPServer
from types import SimpleNamespace
from typing import Any
from typing import Dict
from typing import Iterator
from typing import Optional
from typing import Tuple
from urllib.parse import urlencode

import pytest

from file_dropbox import server
from file_dropbox.security import hash_password

TOKEN = "upload-token-xyz"
PASSWORD = "correct horse battery staple"
NOTES = b"<script>alert(1)</script>\nsecond line\n"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32

Response = Tuple[int, bytes, Dict[str, str]]


def request(
    port: int,
    method: str,
    path: str,
    body: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Response:
    """Make one HTTP request on a fresh connection; return (status, body, headers)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, resp.read(), {k.lower(): v for k, v in resp.getheaders()}
    finally:
        conn.close()


def upload(port: int, client: str, name: str, data: bytes) -> Dict[str, Any]:
    """Upload one file through the real endpoint and return its metadata."""
    status, body, _ = request(port, "POST", "/upload", data, {
        "Authorization": "Bearer " + TOKEN, "X-Client-Id": client, "X-Filename": name,
    })
    assert status == 201
    return json.loads(body)["files"][0]


@pytest.fixture(scope="module")
def live(tmp_path_factory: pytest.TempPathFactory) -> Iterator[SimpleNamespace]:
    """A server with the admin UI on, holding a couple of uploads from alice."""
    root = tmp_path_factory.mktemp("uploads")
    server.configure({
        "host": "127.0.0.1",
        "port": 0,
        "upload_root": str(root),
        "max_upload_bytes": 1073741824,
        "api_token": TOKEN,
        "admin_path": "/admin",
        "admin_password_hash": hash_password(PASSWORD, iterations=1000),
    })
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.DropHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    port = httpd.server_address[1]
    try:
        yield SimpleNamespace(
            port=port,
            root=str(root),
            notes=upload(port, "alice", "notes.txt", NOTES)["path"],
            picture=upload(port, "alice", "pic.png", PNG)["path"],
        )
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def login(live: SimpleNamespace, password: str = PASSWORD, **headers: str) -> Response:
    """Submit the sign-in form."""
    return request(live.port, "POST", "/admin/login", urlencode({"password": password}).encode(), {
        "Content-Type": "application/x-www-form-urlencoded", **headers,
    })


def get(live: SimpleNamespace, path: str, cookie: Optional[str] = None) -> Response:
    """GET an admin URL, optionally signed in."""
    return request(live.port, "GET", path, headers={"Cookie": cookie} if cookie else {})


@pytest.fixture
def cookie(live: SimpleNamespace) -> str:
    """A signed-in session cookie (``fdb_session=...``)."""
    status, _, hdrs = login(live)
    assert status == 303
    return hdrs["set-cookie"].split(";")[0]


# --------------------------------------------------------------------------
# Sign-in
# --------------------------------------------------------------------------


def test_login_page_has_strict_headers(live):
    status, body, hdrs = get(live, "/admin/login")
    assert status == 200
    assert hdrs["content-type"] == "text/html; charset=utf-8"
    assert "default-src 'none'" in hdrs["content-security-policy"]
    assert "script-src" not in hdrs["content-security-policy"]  # no scripts at all
    assert hdrs["x-frame-options"] == "DENY"
    assert hdrs["cache-control"] == "no-store"
    assert b'name="password"' in body


@pytest.mark.parametrize("path", ["/admin", "/admin/", "/admin/clients/alice", "/admin/raw/alice/x.txt"])
def test_pages_need_a_session(live, path):
    status, _, hdrs = get(live, path)
    assert status == 303
    assert hdrs["location"] == "/admin/login"


def test_static_assets_are_public_but_fixed(live):
    status, _, hdrs = get(live, "/admin/static/admin.css")
    assert status == 200
    assert hdrs["content-type"].startswith("text/css")
    assert get(live, "/admin/static/../server.py")[0] == 404
    assert get(live, "/admin/static/nope.js")[0] == 404


def test_login_sets_hardened_cookie(live):
    status, _, hdrs = login(live)
    assert status == 303
    assert hdrs["location"] == "/admin/"
    cookie = hdrs["set-cookie"]
    assert cookie.startswith("fdb_session=")
    for attr in ("HttpOnly", "SameSite=Strict", "Path=/admin"):
        assert attr in cookie


def test_wrong_password_counts_down(live):
    status, body, _ = login(live, "nope")
    assert status == 401
    assert b"4 tries left" in body


def test_lockout_after_too_many_wrong_passwords(live):
    for _ in range(4):
        assert login(live, "nope")[0] == 401
    status, body, hdrs = login(live, "nope")
    assert status == 429
    assert int(hdrs["retry-after"]) > 0
    assert b"blocked" in body
    assert login(live)[0] == 429  # even the right password waits out the lockout


def test_wrong_upload_tokens_lock_out_the_admin_too(live):
    for _ in range(5):
        request(live.port, "POST", "/upload", b"x", {"Authorization": "Bearer wrong", "X-Filename": "a"})
    assert login(live)[0] == 429


def test_cross_origin_login_is_refused(live):
    status, _, hdrs = login(live, Origin="http://evil.example")
    assert status == 403
    assert "set-cookie" not in hdrs


def test_same_origin_login_is_accepted(live):
    assert login(live, Origin=f"http://127.0.0.1:{live.port}")[0] == 303


def test_browser_login_with_null_origin_is_accepted(live):
    # What a real browser sends from our own page under a strict referrer policy.
    assert login(live, Origin="null", **{"Sec-Fetch-Site": "same-origin"})[0] == 303


@pytest.mark.parametrize("site", ["cross-site", "same-site"])
def test_login_posted_from_another_site_is_refused(live, site):
    status, _, hdrs = login(live, Origin=f"http://127.0.0.1:{live.port}", **{"Sec-Fetch-Site": site})
    assert status == 403
    assert "set-cookie" not in hdrs


def test_pages_send_a_referrer_policy_that_keeps_origin(live):
    _, _, hdrs = get(live, "/admin/login")
    assert hdrs["referrer-policy"] == "same-origin"


def test_made_up_session_cookie_is_ignored(live):
    status, _, _ = get(live, "/admin/", "fdb_session=" + "A" * 43)
    assert status == 303


def test_logout_needs_the_csrf_token(live, cookie):
    form = {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie}
    status, _, _ = request(live.port, "POST", "/admin/logout", b"csrf=wrong", form)
    assert status == 403
    status, page, _ = get(live, "/admin/", cookie)
    assert status == 200  # still signed in

    csrf = re.search(rb'name="csrf" value="([^"]+)"', page).group(1).decode()
    status, _, hdrs = request(live.port, "POST", "/admin/logout", urlencode({"csrf": csrf}).encode(), form)
    assert status == 303
    assert "Max-Age=0" in hdrs["set-cookie"]
    assert get(live, "/admin/", cookie)[0] == 303  # signed out


# --------------------------------------------------------------------------
# Browsing
# --------------------------------------------------------------------------


def test_dashboard_shows_clients_and_activity(live, cookie):
    upload(live.port, "bob", "hello.txt", b"hi")  # newest event, so it's on the list
    status, body, _ = get(live, "/admin/", cookie)
    assert status == 200
    assert b"alice" in body and b"bob" in body
    assert b"3 files from 2 clients" in body
    assert b"Delivery" in body
    assert b"127.0.0.1 as bob" in body


def test_client_page_lists_and_filters_files(live, cookie):
    status, body, _ = get(live, "/admin/clients/alice", cookie)
    assert status == 200
    assert b"notes.txt" in body and b"pic.png" in body
    _, body, _ = get(live, "/admin/clients/alice?q=PIC", cookie)
    assert b"pic.png" in body and b"notes.txt" not in body


def test_text_preview_is_escaped(live, cookie):
    status, body, _ = get(live, f"/admin/files/alice/{live.notes}", cookie)
    assert status == 200
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in body
    assert b"<script>" not in body
    assert b"second line" in body
    assert b"127.0.0.1" in body  # upload metadata is shown


def test_download_is_a_sandboxed_attachment(live, cookie):
    status, body, hdrs = get(live, f"/admin/raw/alice/{live.notes}?download=1", cookie)
    assert status == 200
    assert body == NOTES
    assert hdrs["content-type"] == "application/octet-stream"
    assert hdrs["content-disposition"] == 'attachment; filename="notes.txt"'
    assert "sandbox" in hdrs["content-security-policy"]
    assert hdrs["x-content-type-options"] == "nosniff"


def test_only_raster_images_are_shown_inline(live, cookie):
    _, body, hdrs = get(live, f"/admin/raw/alice/{live.picture}", cookie)
    assert hdrs["content-type"] == "image/png"
    assert hdrs["content-disposition"].startswith("inline")
    assert body == PNG
    _, _, hdrs = get(live, f"/admin/raw/alice/{live.notes}", cookie)
    assert hdrs["content-type"] == "application/octet-stream"
    assert hdrs["content-disposition"].startswith("attachment")


@pytest.mark.parametrize("path", [
    "/admin/files/alice/..%2F..%2Fconfig.json",
    "/admin/files/alice/../_logs/access.log",
    "/admin/raw/_logs/access.log",
    "/admin/raw/alice/uploads.jsonl",
    "/admin/files/..%2F/etc/passwd",
    "/admin/clients/..",
    "/admin/clients/_logs",
    "/admin/files/alice/2026-01-01/missing.txt",
])
def test_nothing_outside_the_uploads_is_reachable(live, cookie, path):
    assert get(live, path, cookie)[0] == 404


def test_symlinks_are_not_followed(live, cookie, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("top secret")
    day = live.notes.split("/")[0]
    os.symlink(secret, os.path.join(live.root, "alice", day, "link.txt"))
    assert get(live, f"/admin/raw/alice/{day}/link.txt", cookie)[0] == 404
    _, body, _ = get(live, "/admin/clients/alice", cookie)
    assert b"link.txt" not in body


def test_other_gets_stay_a_bland_404(live):
    for path in ("/", "/upload", "/administrator", "/admin-x"):
        status, body, _ = get(live, path)
        assert status == 404
        assert json.loads(body) == {"error": "not found"}
