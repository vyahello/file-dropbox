"""
The upload server.

Behavior
--------
- Accepts ONLY POST requests (uploads). Every other method -> generic 404 (no Allow header).
- Requires a bearer token / API key. Missing creds -> 401, bad creds -> 403.
  Too many bad tokens from one address -> 429 for a while (brute-force lockout).
- Files land in uploads/<client>/<YYYY-MM-DD>/ under their original names;
  a name clash gets a numeric suffix (report.pdf, report-1.pdf, ...).
- Records who sent what: date, time, client, IP, User-Agent, filename, size,
  content-type -> one line per file in uploads/<client>/uploads.jsonl, plus a
  combined server access log.
- The one exception to "POST only": the owner's admin UI under /admin (see
  :mod:`file_dropbox.admin`), protected by a separate admin password.
"""

import hmac
import json
import os
import re
import signal
import sys
from datetime import datetime
from datetime import timezone
from http.server import ThreadingHTTPServer
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

from file_dropbox import admin
from file_dropbox.config import DEFAULT_CONFIG
from file_dropbox.config import Config
from file_dropbox.security import LoginLimiter
from file_dropbox.security import client_key
from file_dropbox.storage import Meta
from file_dropbox.storage import append_index
from file_dropbox.storage import safe_filename
from file_dropbox.storage import save_file

# (field_name, filename, content_type, data) for one multipart file part.
MultipartFile = Tuple[Optional[str], str, str, bytes]


# Runtime state, populated by configure(). Declared here so the handler's
# global lookups always resolve; serve() (and tests) call configure() to set them.
CONFIG: Optional[Config] = None
UPLOAD_ROOT: str = ""
LOG_DIR: str = ""
ACCESS_LOG: str = ""
API_TOKEN: str = ""                    # single shared bearer token
MAX_BYTES: int = int(DEFAULT_CONFIG["max_upload_bytes"])
LIMITER = LoginLimiter()               # brute-force lockout, shared with the admin UI


def configure(cfg: Config) -> Config:
    """Apply a config dict to module state and create the log directory.

    Args:
        cfg: Configuration with the same keys as :data:`DEFAULT_CONFIG`.

    Returns:
        The same ``cfg``, for convenience.
    """
    global CONFIG, UPLOAD_ROOT, LOG_DIR, ACCESS_LOG, API_TOKEN, MAX_BYTES, LIMITER
    CONFIG = cfg
    UPLOAD_ROOT = os.path.abspath(cfg["upload_root"])  # relative to the current directory
    LOG_DIR = os.path.join(UPLOAD_ROOT, "_logs")
    ACCESS_LOG = os.path.join(LOG_DIR, "access.log")
    API_TOKEN = cfg.get("api_token", "")
    MAX_BYTES = int(cfg["max_upload_bytes"])
    os.makedirs(LOG_DIR, exist_ok=True)

    def setting(key: str) -> Any:
        return cfg.get(key, DEFAULT_CONFIG[key])

    lockout = float(setting("lockout_minutes")) * 60
    LIMITER = LoginLimiter(
        max_failures=int(setting("max_failed_logins")),
        window_seconds=lockout,
        lockout_seconds=lockout,
    )
    admin.configure(
        path=setting("admin_path"),
        username=setting("admin_username"),
        password_hash=setting("admin_password_hash"),
        upload_root=UPLOAD_ROOT,
        access_log=ACCESS_LOG,
        session_minutes=float(setting("session_minutes")),
        secure_cookies=bool(setting("secure_cookies")),
        limiter=LIMITER,
    )
    return cfg


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def now() -> datetime:
    """Return the current time as a timezone-aware datetime in local time."""
    return datetime.now(timezone.utc).astimezone()


def parse_multipart(body: bytes, boundary: bytes) -> List[MultipartFile]:
    """Extract the file parts from a ``multipart/form-data`` body.

    Args:
        body: The raw request body.
        boundary: The multipart boundary (without the leading ``--``).

    Returns:
        A list of ``(field_name, filename, content_type, data)`` tuples. Plain
        form fields (parts without a ``filename``) are skipped.
    """
    results: List[MultipartFile] = []
    delim = b"--" + boundary
    for part in body.split(delim):
        part = part.strip(b"\r\n")
        if not part or part == b"--":
            continue
        if b"\r\n\r\n" not in part:
            continue
        raw_headers, data = part.split(b"\r\n\r\n", 1)
        headers: Dict[bytes, bytes] = {}
        for line in raw_headers.split(b"\r\n"):
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.strip().lower()] = v.strip()
        disp = headers.get(b"content-disposition", b"").decode("utf-8", "replace")
        name: Optional[str] = None
        filename: Optional[str] = None
        for tok in disp.split(";"):
            tok = tok.strip()
            if tok.startswith("name="):
                name = tok[5:].strip('"')
            elif tok.startswith("filename="):
                filename = tok[9:].strip('"')
        ctype = headers.get(b"content-type", b"application/octet-stream").decode(
            "utf-8", "replace"
        )
        if filename is not None:
            results.append((name, filename, ctype, data))
    return results


# --------------------------------------------------------------------------
# Request handler
# --------------------------------------------------------------------------


class DropHandler(admin.AdminRoutes):
    """HTTP handler that accepts authenticated POST uploads and nothing else.

    The only other thing it answers is the owner's admin UI (see admin.py).
    """

    protocol_version = "HTTP/1.1"

    # ---- response helpers ------------------------------------------------

    def send_json(
        self,
        code: int,
        payload: Dict[str, Any],
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Send ``payload`` as a JSON response with status ``code``."""
        body = json.dumps(payload, indent=2).encode("utf-8")
        # Error paths return without consuming the request body; with keep-alive
        # those unread bytes would corrupt the next request on this socket, so
        # close the connection after any error response.
        if code >= 400:
            self.close_connection = True
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if code >= 400:
            self.send_header("Connection", "close")
        for key, val in (extra_headers or {}).items():
            self.send_header(key, val)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_response(self, code: int, message: Optional[str] = None) -> None:
        """Like the standard one, minus the ``Server`` header that names the software."""
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def send_error(self, code: int, message: Optional[str] = None, explain: Optional[str] = None) -> None:
        """Answer malformed requests with the same bland JSON as everything else.

        The standard version sends an HTML page that gives away Python's
        http.server. Unknown methods (501 there) get the generic 404, exactly
        like GET or PUT.
        """
        if code == 501:
            self.reject_method()
        else:
            self.send_json(code, {"error": "bad request"})

    def reject_method(self) -> None:
        """Answer any non-POST method with a bland 404.

        Discloses nothing about which methods are accepted: no 405 and no
        Allow header, so a GET looks identical to hitting a dead path.
        """
        self.send_json(404, {"error": "not found"})

    def do_GET(self) -> None:
        """Serve the admin UI; any other GET is the same bland 404."""
        if self.is_admin_request():
            self.handle_admin_get()
        else:
            self.reject_method()

    # Only POST (and the admin UI) is served; every other method is a generic 404.
    do_HEAD = reject_method
    do_PUT = reject_method
    do_DELETE = reject_method
    do_PATCH = reject_method
    do_OPTIONS = reject_method

    # ---- auth ------------------------------------------------------------

    def authenticate(self) -> bool:
        """Check the request for the shared token.

        Accepts ``Authorization: Bearer <token>`` or ``X-API-Key: <token>``.

        An address that sends too many wrong tokens is locked out for a while
        (the same lockout that protects the admin password).

        Returns:
            True if the token matches. Otherwise an error response (401, 403,
            429 or 503) has already been sent and False is returned.
        """
        if not API_TOKEN:
            self.access_log("NO-TOKEN-CONFIGURED", "-", 503)
            self.send_json(503, {"error": "server has no api_token configured"})
            return False

        auth = self.headers.get("Authorization", "")
        token = ""
        if auth.startswith("Bearer "):
            token = auth[7:].strip()
        if not token:
            token = self.headers.get("X-API-Key", "").strip()

        if not token:
            self.access_log("AUTH-MISSING", "-", 401)
            self.send_json(
                401,
                {"error": "missing credentials",
                 "hint": "send 'Authorization: Bearer <token>' or 'X-API-Key: <token>'"},
                {"WWW-Authenticate": 'Bearer realm="file-drop"'},
            )
            return False

        key = client_key(self.client_address[0])
        wait = LIMITER.retry_after(key)
        if wait:
            self.access_log("AUTH-LOCKED", "-", 429)
            self.send_json(
                429,
                {"error": "too many failed attempts", "retry_after_seconds": wait},
                {"Retry-After": str(wait)},
            )
            return False

        # Compare bytes: compare_digest raises on non-ASCII str, and headers can be anything.
        if hmac.compare_digest(token.encode("utf-8"), API_TOKEN.encode("utf-8")):
            LIMITER.record_success(key)
            return True

        left = LIMITER.record_failure(key)
        self.access_log("AUTH-BAD", "-", 403, extra=f"{left} tries left" if left else "address locked out")
        self.send_json(403, {"error": "invalid credentials"})
        return False

    def client_id(self) -> str:
        """Return who sent this: the declared X-Client-Id/Name, else ``ip-<addr>``.

        Leading underscores are dropped: names like ``_logs`` are reserved.
        """
        cid = self.headers.get("X-Client-Id") or self.headers.get("X-Client-Name") or ""
        cid = safe_filename(cid).lstrip("_") if cid.strip() else ""
        if not cid:
            cid = "ip-" + self.client_address[0].replace(":", "_")
        return cid

    # ---- the one allowed method -----------------------------------------

    def do_POST(self) -> None:
        """Handle an upload: authenticate, read the body, store every file."""
        if self.is_admin_request():
            self.handle_admin_post()
            return
        if not self.authenticate():
            return
        client = self.client_id()

        path = self.path.split("?", 1)[0]
        if path not in ("/", "/upload"):
            self.send_json(404, {"error": "not found", "hint": "POST files to /upload"})
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        if length <= 0:
            self.send_json(400, {"error": "empty body / missing Content-Length"})
            return
        if length > MAX_BYTES:
            self.send_json(413, {"error": "payload too large", "max_bytes": MAX_BYTES})
            return

        body = self._read_exactly(length)
        if body is None:
            self.send_json(400, {"error": "could not read full body"})
            return

        files = self._extract_files(body)
        if files is None:
            self.send_json(400, {"error": "multipart boundary missing"})
            return
        if not files:
            self.send_json(400, {"error": "no file found in request"})
            return

        stored = [self._store_one(client, fn, ct, data) for fn, ct, data in files]
        names = ", ".join(s["original_filename"] for s in stored)
        total = sum(s["size"] for s in stored)
        self.access_log(
            "UPLOAD", client, 201,
            extra=f"{len(stored)} file(s), {total} bytes: {names}",
        )
        self.send_json(201, {"status": "stored", "client": client, "files": stored})

    def _extract_files(self, body: bytes) -> Optional[List[Tuple[str, str, bytes]]]:
        """Split the request body into ``(filename, content_type, data)`` triples.

        Multipart bodies may hold several files. Any other body is treated as
        one raw file, named by ``X-Filename`` or ``Content-Disposition``.

        Returns:
            The files found, or None if a multipart body has no boundary.
        """
        ctype = self.headers.get("Content-Type", "")

        if ctype.startswith("multipart/form-data"):
            m = re.search(r"boundary=([^;]+)", ctype)
            if not m:
                return None
            boundary = m.group(1).strip().strip('"').encode("utf-8")
            return [
                (filename, part_ctype, data)
                for _name, filename, part_ctype, data in parse_multipart(body, boundary)
            ]

        filename = self.headers.get("X-Filename", "")
        if not filename:
            disp = self.headers.get("Content-Disposition", "")
            m = re.search(r'filename="?([^";]+)"?', disp)
            filename = m.group(1) if m else "upload.bin"
        return [(filename, ctype or "application/octet-stream", body)]

    # ---- storage ---------------------------------------------------------

    def _store_one(
        self, client: str, raw_filename: str, content_type: str, data: bytes
    ) -> Meta:
        """Write one file to ``uploads/<client>/<YYYY-MM-DD>/`` and index it.

        The file keeps its original (sanitized) name; a clash with an earlier
        upload that day gets a numeric suffix instead of overwriting it. The
        metadata record is appended to ``uploads/<client>/uploads.jsonl``.

        Returns:
            The metadata record for the stored file.
        """
        ts = now()
        orig = safe_filename(raw_filename)
        rel = save_file(UPLOAD_ROOT, client, ts.strftime("%Y-%m-%d"), orig, data)
        meta: Meta = {
            "client": client,
            "path": rel,
            "original_filename": orig,
            "size": len(data),
            "content_type": content_type,
            "received_at": ts.isoformat(),
            "source_ip": self.client_address[0],
            "source_port": self.client_address[1],
            "user_agent": self.headers.get("User-Agent", ""),
            "hostname_claimed": self.headers.get("X-Client-Host", ""),
        }

        append_index(UPLOAD_ROOT, client, meta)
        return meta

    # ---- utilities --------------------------------------------------------

    def _read_exactly(self, n: int) -> Optional[bytes]:
        """Read exactly ``n`` bytes of request body, or None if the client hangs up early."""
        chunks: List[bytes] = []
        remaining = n
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def access_log(self, event: str, client: str, status: int, extra: str = "") -> None:
        """Append one tab-separated line to the access log and echo it to stdout."""
        line = (
            f"{now().isoformat()}\t{event}\t{self.client_address[0]}\t"
            f"{client}\t{self.command} {self.path}\t{status}\t{extra}\n"
        )
        try:
            with open(ACCESS_LOG, "a") as fh:
                fh.write(line)
        except OSError:
            pass
        sys.stdout.write(line)
        sys.stdout.flush()

    def log_message(self, format: str, *args: Any) -> None:
        """Silence the default noisy stderr logging; :meth:`access_log` does ours."""


def _stop(signum: int, frame: Any) -> None:
    """Turn SIGTERM (``docker stop``) into the same clean exit as Ctrl+C."""
    raise KeyboardInterrupt


def serve(cfg: Config) -> None:
    """Apply ``cfg`` and serve until Ctrl+C or SIGTERM."""
    configure(cfg)
    httpd = ThreadingHTTPServer((cfg["host"], cfg["port"]), DropHandler)
    signal.signal(signal.SIGTERM, _stop)
    print(f"File-drop server listening on http://{cfg['host']}:{cfg['port']}")
    print("Upload endpoint: POST /upload   (POST only; all else -> 404)")
    print(f"Storing files under: {UPLOAD_ROOT}")
    print(f"Auth: shared bearer token ({'set' if API_TOKEN else 'MISSING - edit config.json'})")
    if admin.PREFIX:
        print(f"Admin UI: http://{cfg['host']}:{cfg['port']}{admin.PREFIX}/")
    else:
        print("Admin UI: off")
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        httpd.shutdown()
        httpd.server_close()
