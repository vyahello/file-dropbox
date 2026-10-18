"""
Admin web UI for file-dropbox.

The server owner signs in with the admin password and can browse every
client's uploads, read text files, view images, download anything, and see
recent server activity (deliveries, wrong tokens, blocked addresses).

Mounted under ``admin_path`` (default ``/admin``). Every page except the
sign-in page and the static assets needs a signed-in session.

Security notes
--------------
- Uploaded files are never rendered as HTML. Text is escaped into a <pre>,
  only raster images are served inline, everything else is a download.
- Every page is sent with a strict Content-Security-Policy (no scripts at
  all), ``X-Frame-Options: DENY`` and ``Cache-Control: no-store``.
- Sessions live in an HttpOnly, SameSite=Strict cookie with an idle timeout.
- POSTs from another origin are refused; signing out also needs the
  session's CSRF token.
- Wrong passwords count towards the same per-address lockout as wrong
  upload tokens.

Standard library only.
"""

import hmac
import html
import json
import os
import re
import shutil
import time
from dataclasses import dataclass
from datetime import datetime
from http import cookies
from http.server import BaseHTTPRequestHandler
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from urllib.parse import parse_qs
from urllib.parse import quote
from urllib.parse import unquote
from urllib.parse import urlsplit

from security import LoginLimiter
from security import Session
from security import SessionStore
from security import client_key
from security import verify_password

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(HERE, "static")
STATIC_FILES = {
    "admin.css": "text/css; charset=utf-8",
    "icon.svg": "image/svg+xml",
}

COOKIE_NAME = "fdb_session"
PREVIEW_BYTES = 256 * 1024     # show at most this much of a text file
MAX_FORM_BYTES = 4096          # sign-in / sign-out forms are tiny
ACTIVITY_LINES = 15            # recent events on the dashboard
ACTIVITY_TAIL_BYTES = 64 * 1024

INDEX_FILES = {"uploads.jsonl", "_uploads.jsonl"}
DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# Names the upload server can produce (see server.safe_filename); no leading dot.
NAME_RE = re.compile(r"^[A-Za-z0-9_ -][A-Za-z0-9._ -]{0,254}$")

# Raster images are safe to show inline. SVG is not: it can carry scripts.
IMAGE_TYPES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".avif": "image/avif",
    ".bmp": "image/bmp",
    ".ico": "image/x-icon",
}

PAGE_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'self'; img-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cache-Control": "no-store",
}
# Raw file responses: sandboxed, so even a mislabelled file can't run code.
RAW_CSP = "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; sandbox"

# Access-log events in plain words: event -> (css modifier, label).
EVENTS = {
    "UPLOAD": ("ok", "Delivery"),
    "AUTH-MISSING": ("warn", "Upload without a token"),
    "AUTH-BAD": ("bad", "Wrong upload token"),
    "AUTH-LOCKED": ("bad", "Blocked: too many wrong tokens"),
    "NO-TOKEN-CONFIGURED": ("warn", "Upload refused: no token set"),
    "ADMIN-LOGIN": ("info", "Admin signed in"),
    "ADMIN-LOGOUT": ("info", "Admin signed out"),
    "ADMIN-LOGIN-FAIL": ("bad", "Wrong admin password"),
    "ADMIN-LOCKED": ("bad", "Admin sign-in blocked"),
    "ADMIN-BAD-ORIGIN": ("bad", "Cross-site form refused"),
}

# Runtime state, set by configure(). An empty PREFIX means the UI is off.
PREFIX = ""
PASSWORD_HASH = ""
UPLOAD_ROOT = ""
ACCESS_LOG = ""
SECURE_COOKIES = False
LOCKOUT_MINUTES = 15
LIMITER = LoginLimiter()
SESSIONS = SessionStore()


def configure(
    *,
    path: str,
    password_hash: str,
    upload_root: str,
    access_log: str,
    session_minutes: float,
    secure_cookies: bool,
    limiter: LoginLimiter,
) -> None:
    """Set up the admin UI.

    Args:
        path: URL prefix such as ``/admin``. Empty turns the UI off.
        password_hash: Hash from :func:`security.hash_password`. Empty turns
            the UI off too, so it can never be opened without a password.
        upload_root: Folder holding one sub-folder per client.
        access_log: The server's access log, shown as recent activity.
        session_minutes: Idle time after which the admin is signed out.
        secure_cookies: Mark the cookie ``Secure`` (only when served via HTTPS).
        limiter: Shared brute-force limiter, also used for upload tokens.
    """
    global PREFIX, PASSWORD_HASH, UPLOAD_ROOT, ACCESS_LOG, SECURE_COOKIES
    global LOCKOUT_MINUTES, LIMITER, SESSIONS
    prefix = path.strip().strip("/")
    PREFIX = "/" + prefix if prefix and password_hash else ""
    PASSWORD_HASH = password_hash
    UPLOAD_ROOT = upload_root
    ACCESS_LOG = access_log
    SECURE_COOKIES = secure_cookies
    LIMITER = limiter
    LOCKOUT_MINUTES = max(1, round(limiter.lockout_seconds / 60))
    SESSIONS = SessionStore(idle_seconds=session_minutes * 60)


# --------------------------------------------------------------------------
# Reading the upload folder
# --------------------------------------------------------------------------


@dataclass
class StoredFile:
    """One uploaded file as found on disk."""

    rel: str      # path inside the client folder, e.g. "2026-10-15/report.pdf"
    name: str
    day: str      # "2026-10-15", or "" for files from the old flat layout
    size: int
    mtime: float


@dataclass
class ClientSummary:
    """Totals for one client folder."""

    name: str
    files: int = 0
    size: int = 0
    last: float = 0.0  # mtime of the newest file; 0 when the folder is empty


@dataclass
class Preview:
    """What the file page can show for a file."""

    kind: str            # "text", "image", "binary" or "empty"
    text: str = ""
    truncated: bool = False


@dataclass
class Event:
    """One parsed line of the access log."""

    when: str
    event: str
    ip: str
    client: str
    extra: str


def is_client_name(name: str) -> bool:
    """True for names that can be a client folder (``_logs`` & co. are reserved)."""
    return bool(NAME_RE.match(name)) and not name.startswith("_")


def _is_listed(name: str) -> bool:
    """True for upload files; hides the metadata index and old sidecars."""
    return bool(NAME_RE.match(name)) and name not in INDEX_FILES and not name.endswith(".meta.json")


def list_files(root: str, client: str) -> List[StoredFile]:
    """List a client's files, newest first.

    Looks at ``<client>/<YYYY-MM-DD>/*`` plus loose files in the client folder
    itself (the flat layout older versions used). Symlinks are ignored.
    """
    files: List[StoredFile] = []

    def scan(directory: str, day: str) -> None:
        try:
            entries = os.scandir(directory)
        except OSError:
            return
        with entries:
            for entry in entries:
                if entry.is_dir(follow_symlinks=False):
                    if not day and DAY_RE.match(entry.name):
                        scan(entry.path, entry.name)
                elif entry.is_file(follow_symlinks=False) and _is_listed(entry.name):
                    st = entry.stat(follow_symlinks=False)
                    rel = f"{day}/{entry.name}" if day else entry.name
                    files.append(StoredFile(rel, entry.name, day, st.st_size, st.st_mtime))

    scan(os.path.join(root, client), "")
    files.sort(key=lambda f: f.mtime, reverse=True)
    return files


def list_clients(root: str) -> List[ClientSummary]:
    """Summarise every client folder, most recently active first."""
    clients: List[ClientSummary] = []
    try:
        entries = os.scandir(root)
    except OSError:
        return clients
    with entries:
        for entry in entries:
            if not is_client_name(entry.name) or not entry.is_dir(follow_symlinks=False):
                continue
            summary = ClientSummary(entry.name)
            for f in list_files(root, entry.name):
                summary.files += 1
                summary.size += f.size
                summary.last = max(summary.last, f.mtime)
            clients.append(summary)
    clients.sort(key=lambda c: c.last, reverse=True)
    return clients


def resolve_file(root: str, client: str, rel: str) -> Optional[str]:
    """Turn a client name and relative path from a URL into a real file path.

    Accepts only ``<day>/<name>`` or ``<name>`` built from safe characters,
    refuses symlinks, and double-checks the result stays inside ``root``.

    Returns:
        The absolute path, or None if the request doesn't name a stored file.
    """
    parts = rel.split("/")
    if not is_client_name(client) or not 1 <= len(parts) <= 2:
        return None
    if len(parts) == 2 and not DAY_RE.match(parts[0]):
        return None
    if not all(NAME_RE.match(p) for p in parts) or not _is_listed(parts[-1]):
        return None
    path = os.path.join(root, client, *parts)
    if os.path.islink(path) or not os.path.isfile(path):
        return None
    real_root = os.path.realpath(root)
    if not os.path.realpath(path).startswith(real_root + os.sep):
        return None
    return path


def read_meta(root: str, client: str, rel: str) -> Dict[str, Any]:
    """Find the upload record for a file.

    Checks the client's ``uploads.jsonl`` index first, then an old-style
    ``.meta.json`` sidecar. Returns an empty dict when nothing is recorded.
    """
    client_dir = os.path.join(root, client)
    found: Dict[str, Any] = {}
    try:
        with open(os.path.join(client_dir, "uploads.jsonl"), encoding="utf-8") as fh:
            for line in fh:
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if isinstance(record, dict) and record.get("path") == rel:
                    found = record
    except OSError:
        pass
    if found:
        return found
    try:
        with open(os.path.join(client_dir, rel + ".meta.json"), encoding="utf-8") as fh:
            record = json.load(fh)
            return record if isinstance(record, dict) else {}
    except (OSError, ValueError):
        return {}


def load_preview(path: str) -> Preview:
    """Read enough of a file to preview it safely."""
    if os.path.getsize(path) == 0:
        return Preview("empty")
    if os.path.splitext(path)[1].lower() in IMAGE_TYPES:
        return Preview("image")
    with open(path, "rb") as fh:
        data = fh.read(PREVIEW_BYTES + 1)
    truncated = len(data) > PREVIEW_BYTES
    data = data[:PREVIEW_BYTES]
    if b"\x00" in data[:8192]:
        return Preview("binary")
    return Preview("text", data.decode("utf-8", "replace"), truncated)


def recent_activity(log_path: str, limit: int = ACTIVITY_LINES) -> List[Event]:
    """Return the newest ``limit`` events from the access log, newest first."""
    try:
        with open(log_path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - ACTIVITY_TAIL_BYTES))
            data = fh.read()
    except OSError:
        return []
    lines = data.decode("utf-8", "replace").splitlines()
    if size > ACTIVITY_TAIL_BYTES:
        lines = lines[1:]  # the first line is probably cut in half
    events: List[Event] = []
    for line in reversed(lines):
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        events.append(Event(
            when=parts[0], event=parts[1], ip=parts[2], client=parts[3],
            extra=parts[6] if len(parts) > 6 else "",
        ))
        if len(events) == limit:
            break
    return events


# --------------------------------------------------------------------------
# Formatting
# --------------------------------------------------------------------------


def h(value: Any) -> str:
    """HTML-escape anything for use in text or an attribute."""
    return html.escape(str(value), quote=True)


def url(*parts: str) -> str:
    """Build an admin URL from path segments, quoting each one."""
    return PREFIX + "/" + "/".join(quote(p) for p in parts)


def count(n: int, word: str) -> str:
    """``count(1, "file")`` -> "1 file", ``count(3, "file")`` -> "3 files"."""
    return f"{n:,} {word}" + ("" if n == 1 else "s")


def human_size(size: int) -> str:
    """Format a byte count, e.g. ``4301233`` -> "4.1 MB"."""
    value = float(size)
    unit = "B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            break
        value /= 1024
    if unit == "B":
        return f"{size} B"
    return f"{value:.1f} {unit}" if value < 10 else f"{value:.0f} {unit}"


def short_date(dt: datetime) -> str:
    """``15 Oct 2026``."""
    return f"{dt.day} {dt:%b %Y}"


def ago(ts: float) -> str:
    """How long ago a timestamp was, in words."""
    seconds = max(0.0, time.time() - ts)
    if seconds < 60:
        return "just now"
    minutes = int(seconds // 60)
    if minutes < 60:
        return f"{minutes} min ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours} h ago"
    days = hours // 24
    if days == 1:
        return "yesterday"
    if days < 30:
        return f"{days} days ago"
    return short_date(datetime.fromtimestamp(ts))


def day_title(day: str) -> str:
    """``2026-10-15`` -> "Thursday, 15 October 2026"."""
    try:
        d = datetime.strptime(day, "%Y-%m-%d")
    except ValueError:
        return day
    return f"{d:%A}, {d.day} {d:%B %Y}"


def event_time(stamp: str) -> str:
    """Access-log ISO timestamp -> "15 Oct, 16:30"."""
    try:
        dt = datetime.fromisoformat(stamp)
    except ValueError:
        return stamp
    return f"{dt.day} {dt:%b}, {dt:%H:%M}"


DOWNLOAD_ICON = (
    '<svg viewBox="0 0 20 20" width="20" height="20" aria-hidden="true">'
    '<path d="M10 3v10m0 0l-4-4m4 4l4-4M4 16h12" fill="none" stroke="currentColor" '
    'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>'
)


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------


def layout(title: str, main: str, session: Optional[Session] = None) -> str:
    """Wrap page content in the shared document shell.

    With a ``session`` the page gets the top bar with the sign-out button.
    """
    header = ""
    if session is not None:
        header = f"""
<div class="airmail" aria-hidden="true"></div>
<header class="bar">
  <a class="brand" href="{url()}"><img src="{url('static', 'icon.svg')}" alt="" width="28" height="28">file-dropbox</a>
  <form method="post" action="{url('logout')}">
    <input type="hidden" name="csrf" value="{h(session.csrf)}">
    <button class="btn btn-quiet" type="submit">Sign out</button>
  </form>
</header>"""
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{h(title)} | file-dropbox</title>
<link rel="icon" href="{url('static', 'icon.svg')}" type="image/svg+xml">
<link rel="stylesheet" href="{url('static', 'admin.css')}">
</head>
<body>{header}
{main}
</body>
</html>
"""


def render_login(error: str = "", locked_seconds: int = 0) -> str:
    """The sign-in page, optionally with an error or a lockout notice."""
    message = ""
    if locked_seconds:
        minutes = max(1, -(-locked_seconds // 60))
        message = (
            f'<p class="alert" role="alert">Too many wrong passwords from your network '
            f'address. Sign-in is blocked for {count(minutes, "more minute")}.</p>'
        )
    elif error:
        message = f'<p class="alert" role="alert">{h(error)}</p>'
    disabled = " disabled" if locked_seconds else ""
    return layout("Sign in", f"""
<main class="login">
  <div class="envelope">
    <div class="letter">
      <img class="letter-icon" src="{url('static', 'icon.svg')}" alt="" width="48" height="48">
      <h1>Sign in</h1>
      <p class="lede">This page is for the server owner. Use the admin password the server printed when it first started.</p>
      {message}
      <form method="post" action="{url('login')}" class="stack">
        <label for="password">Admin password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required autofocus{disabled}>
        <button class="btn btn-primary" type="submit"{disabled}>Sign in</button>
      </form>
      <p class="hint">Lost it? On the server, run <code>python3 manage_token.py admin-password</code> and restart.</p>
    </div>
  </div>
</main>""")


def render_dashboard(session: Session, clients: List[ClientSummary], events: List[Event]) -> str:
    """Home page: every client as a pigeonhole, plus recent activity."""
    total_files = sum(c.files for c in clients)
    total_size = sum(c.size for c in clients)
    last = max((c.last for c in clients), default=0.0)

    if clients:
        lede = (
            f"{count(total_files, 'file')} from {count(len(clients), 'client')}, "
            f"{human_size(total_size)} in total."
        )
        if last:
            lede += f" Last delivery {ago(last)}."
        slots = "\n".join(
            f"""<li><a href="{url('clients', c.name)}">
      <span class="slot-name">{h(c.name)}</span>
      <span class="slot-meta">{count(c.files, 'file')}, {human_size(c.size)}</span>
      <span class="slot-time">{'Last delivery ' + ago(c.last) if c.last else 'Empty'}</span>
    </a></li>"""
            for c in clients
        )
        cabinet = f'<ul class="cabinet">\n{slots}\n</ul>'
    else:
        lede = "Nothing has arrived yet."
        cabinet = (
            '<p class="empty">Files show up here as soon as a client uploads one. '
            'Each client gets its own pigeonhole.</p>'
        )

    if events:
        rows = []
        for e in events:
            tone, label = EVENTS.get(e.event, ("info", e.event.title()))
            who = h(e.ip) + (f" as {h(e.client)}" if e.client not in ("", "-") else "")
            extra = f'<span class="ev-extra">{h(e.extra)}</span>' if e.extra else ""
            rows.append(
                f'<li class="ev ev-{tone}"><time>{h(event_time(e.when))}</time>'
                f'<span class="ev-name">{h(label)}</span>'
                f'<span class="ev-detail">{who}{extra}</span></li>'
            )
        activity = '<ol class="log">\n' + "\n".join(rows) + "\n</ol>"
    else:
        activity = '<p class="empty">No requests yet.</p>'

    return layout("Mailbox", f"""
<main class="wrap">
  <h1>Mailbox</h1>
  <p class="lede">{lede}</p>
  <section class="block" aria-labelledby="clients-title">
    <h2 id="clients-title">Clients</h2>
    {cabinet}
  </section>
  <section class="block" aria-labelledby="activity-title">
    <h2 id="activity-title">Recent activity</h2>
    {activity}
  </section>
</main>""", session)


def render_client(session: Session, client: str, files: List[StoredFile], query: str) -> str:
    """One client's files, grouped by day, with a filename filter."""
    total = sum(f.size for f in files)
    if files:
        lede = f"{count(len(files), 'file')}, {human_size(total)}. Last delivery {ago(files[0].mtime)}."
    else:
        lede = "This folder is empty."

    shown = [f for f in files if query.lower() in f.name.lower()] if query else files
    groups: Dict[str, List[StoredFile]] = {}
    for f in shown:
        groups.setdefault(f.day, []).append(f)

    sections = []
    for day in sorted(groups, reverse=True):
        title = day_title(day) if day else "Earlier uploads"
        items = "\n".join(
            f"""<li>
      <a class="file" href="{url('files', client, f.rel)}">
        <span class="file-name">{h(f.name)}</span>
        <span class="file-size">{human_size(f.size)}</span>
        <span class="file-time">{datetime.fromtimestamp(f.mtime):%H:%M}</span>
      </a>
      <a class="dl" href="{url('raw', client, f.rel)}?download=1" title="Download" aria-label="Download {h(f.name)}">{DOWNLOAD_ICON}</a>
    </li>"""
            for f in groups[day]
        )
        sections.append(f"""
  <section class="day">
    <h2 class="day-head">{h(title)} <span class="count">{count(len(groups[day]), 'file')}</span></h2>
    <ul class="files">
    {items}
    </ul>
  </section>""")

    if query and not shown:
        sections.append(
            f'<p class="empty">No file names contain “{h(query)}”. '
            f'<a href="{url("clients", client)}">Show all files</a></p>'
        )
    clear = f'<a class="btn btn-quiet" href="{url("clients", client)}">Clear</a>' if query else ""
    search = ""
    if files:
        search = f"""
  <form class="filter" method="get" action="{url('clients', client)}" role="search">
    <label class="sr-only" for="q">Filter by file name</label>
    <input id="q" name="q" type="search" value="{h(query)}" placeholder="Filter by file name">
    <button class="btn" type="submit">Filter</button>
    {clear}
  </form>"""

    return layout(client, f"""
<main class="wrap">
  <nav class="crumbs" aria-label="Breadcrumb"><a href="{url()}">All clients</a></nav>
  <h1 class="break">{h(client)}</h1>
  <p class="lede">{lede}</p>
  {search}
  {''.join(sections)}
</main>""", session)


def render_file(session: Session, client: str, rel: str, path: str, meta: Dict[str, Any]) -> str:
    """One file: what we know about the upload, plus a safe preview."""
    name = os.path.basename(path)
    size = os.path.getsize(path)
    received = meta.get("received_at")
    try:
        when = datetime.fromisoformat(received) if received else datetime.fromtimestamp(os.path.getmtime(path))
    except (TypeError, ValueError):
        when = datetime.fromtimestamp(os.path.getmtime(path))

    facts = [
        ("Received", f"{short_date(when)}, {when:%H:%M:%S}"),
        ("Size", human_size(size) + ("" if size < 1024 else f" ({size:,} bytes)")),
        ("Content type", meta.get("content_type") or "Not recorded"),
        ("Sent from", (
            f"{meta['source_ip']}, port {meta.get('source_port', '?')}"
            if meta.get("source_ip") else "Not recorded"
        )),
        ("User-Agent", meta.get("user_agent") or "Not recorded"),
        ("Hostname (claimed)", meta.get("hostname_claimed") or "Not sent"),
        ("Stored as", f"uploads/{client}/{rel}"),
    ]
    if meta.get("original_filename") and meta["original_filename"] != name:
        facts.insert(1, ("Original name", meta["original_filename"]))
    fact_html = "\n".join(f"<div><dt>{h(k)}</dt><dd>{h(v)}</dd></div>" for k, v in facts)

    preview = load_preview(path)
    if preview.kind == "text":
        lines = preview.text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        body = "".join(f'<span class="l">{h(line.rstrip(chr(13)))}</span>' for line in lines)
        note = (
            f'<p class="note">Showing the first {human_size(PREVIEW_BYTES)}. Download the file to see the rest.</p>'
            if preview.truncated else ""
        )
        shown = f'<pre class="content">{body}</pre>{note}'
    elif preview.kind == "image":
        shown = f'<figure class="picture"><img src="{url("raw", client, rel)}" alt="Preview of {h(name)}"></figure>'
    elif preview.kind == "empty":
        shown = '<p class="empty">This file is empty.</p>'
    else:
        shown = '<p class="empty">This file isn’t text or an image, so there’s no preview. Download it to open it.</p>'

    return layout(name, f"""
<main class="wrap">
  <nav class="crumbs" aria-label="Breadcrumb"><a href="{url()}">All clients</a><span aria-hidden="true">/</span><a href="{url('clients', client)}">{h(client)}</a></nav>
  <div class="file-head">
    <h1 class="break">{h(name)}</h1>
    <a class="btn btn-primary" href="{url('raw', client, rel)}?download=1">{DOWNLOAD_ICON}Download</a>
  </div>
  <dl class="facts">
  {fact_html}
  </dl>
  <section aria-label="Preview">
  {shown}
  </section>
</main>""", session)


def render_message(session: Optional[Session], title: str, text: str) -> str:
    """A plain page with a heading, a sentence and a way back."""
    back = f'<p><a href="{url()}">Back to the mailbox</a></p>' if session else f'<p><a href="{url("login")}">Go to sign-in</a></p>'
    return layout(title, f"""
<main class="wrap">
  <h1>{h(title)}</h1>
  <p class="lede">{h(text)}</p>
  {back}
</main>""", session)


def render_not_found(session: Optional[Session]) -> str:
    """404 page for admin URLs."""
    return render_message(
        session, "Nothing here",
        "There’s no client or file at this address. It may have been moved or deleted on the server.",
    )


# --------------------------------------------------------------------------
# Request handling
# --------------------------------------------------------------------------


class AdminRoutes(BaseHTTPRequestHandler):
    """Admin UI routes. The upload server's handler inherits from this.

    Subclasses must implement :meth:`access_log`.
    """

    def access_log(self, event: str, client: str, status: int, extra: str = "") -> None:
        """Record one event in the server's access log."""
        raise NotImplementedError

    # ---- routing -----------------------------------------------------------

    def is_admin_request(self) -> bool:
        """True if this request is for the admin UI (and the UI is on)."""
        if not PREFIX:
            return False
        path = self.path.split("?", 1)[0]
        return path == PREFIX or path.startswith(PREFIX + "/")

    def handle_admin_get(self) -> None:
        """Serve an admin page, asset or file download."""
        path, _, query = self.path.partition("?")
        route = path[len(PREFIX):] or "/"

        if route.startswith("/static/"):
            self._serve_static(route[len("/static/"):])
            return

        session = self._session()
        if route == "/login":
            if session:
                self._redirect(url())
            else:
                self._send_page(200, render_login())
            return
        if session is None:
            self._redirect(url("login"))
            return

        if route == "/":
            self._send_page(200, render_dashboard(
                session, list_clients(UPLOAD_ROOT), recent_activity(ACCESS_LOG),
            ))
            return

        params = parse_qs(query)
        kind, _, rest = route[1:].partition("/")
        client, _, rel = unquote(rest).partition("/")

        if kind == "clients" and not rel and is_client_name(client):
            client_dir = os.path.join(UPLOAD_ROOT, client)
            if os.path.isdir(client_dir) and not os.path.islink(client_dir):
                q = params.get("q", [""])[0].strip()[:200]
                self._send_page(200, render_client(session, client, list_files(UPLOAD_ROOT, client), q))
                return

        if kind in ("files", "raw"):
            file_path = resolve_file(UPLOAD_ROOT, client, rel)
            if file_path and kind == "raw":
                self._send_raw(file_path, download="download" in params)
                return
            if file_path:
                meta = read_meta(UPLOAD_ROOT, client, rel)
                self._send_page(200, render_file(session, client, rel, file_path, meta))
                return

        self._send_page(404, render_not_found(session))

    def handle_admin_post(self) -> None:
        """Handle the sign-in and sign-out forms."""
        route = self.path.split("?", 1)[0][len(PREFIX):]
        if not self._same_origin():
            self.access_log("ADMIN-BAD-ORIGIN", "-", 403, extra=self.headers.get("Origin", ""))
            self._send_page(403, render_message(
                None, "Form refused", "This form was sent from another website, so it was ignored.",
            ))
            return
        if route == "/login":
            self._login()
        elif route == "/logout":
            self._logout()
        else:
            self._send_page(404, render_not_found(self._session()))

    # ---- sign in / out -----------------------------------------------------

    def _login(self) -> None:
        """Check the password, with per-address lockout after repeated failures."""
        key = client_key(self.client_address[0])
        wait = LIMITER.retry_after(key)
        if wait:
            self.access_log("ADMIN-LOCKED", "-", 429)
            self._send_page(429, render_login(locked_seconds=wait), {"Retry-After": str(wait)})
            return

        form = self._read_form()
        if form is None:
            self._send_page(400, render_login(error="That sign-in request was malformed. Try again."))
            return

        if verify_password(form.get("password", ""), PASSWORD_HASH):
            LIMITER.record_success(key)
            session = SESSIONS.create()
            self.access_log("ADMIN-LOGIN", "-", 303)
            self._redirect(url(), {"Set-Cookie": self._cookie(session.sid)})
            return

        left = LIMITER.record_failure(key)
        if left == 0:
            wait = LIMITER.retry_after(key)
            self.access_log("ADMIN-LOGIN-FAIL", "-", 429, extra="address locked out")
            self._send_page(429, render_login(locked_seconds=wait), {"Retry-After": str(wait)})
            return
        self.access_log("ADMIN-LOGIN-FAIL", "-", 401, extra=f"{left} tries left")
        tries = "1 try" if left == 1 else f"{left} tries"
        self._send_page(401, render_login(
            error=f"That password is wrong. {tries} left, then sign-in is blocked for {LOCKOUT_MINUTES} minutes.",
        ))

    def _logout(self) -> None:
        """End the session if the form carries its CSRF token."""
        session = self._session()
        form = self._read_form() or {}
        if session is None:
            self._redirect(url("login"), {"Set-Cookie": self._cookie("", expire=True)})
            return
        if hmac.compare_digest(form.get("csrf", "").encode(), session.csrf.encode()):
            SESSIONS.delete(session.sid)
            self.access_log("ADMIN-LOGOUT", "-", 303)
            self._redirect(url("login"), {"Set-Cookie": self._cookie("", expire=True)})
            return
        self._send_page(403, render_message(
            session, "Sign-out didn’t go through",
            "The page was out of date. Reload it and press Sign out again.",
        ))

    # ---- request helpers ---------------------------------------------------

    def _session(self) -> Optional[Session]:
        """The signed-in session from the cookie, if any."""
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        jar: cookies.SimpleCookie = cookies.SimpleCookie()
        try:
            jar.load(raw)
        except cookies.CookieError:
            return None
        morsel = jar.get(COOKIE_NAME)
        return SESSIONS.get(morsel.value) if morsel else None

    def _cookie(self, value: str, expire: bool = False) -> str:
        """Build the Set-Cookie value for the session cookie."""
        parts = [f"{COOKIE_NAME}={value}", f"Path={PREFIX}", "HttpOnly", "SameSite=Strict"]
        if expire:
            parts.append("Max-Age=0")
        if SECURE_COOKIES:
            parts.append("Secure")
        return "; ".join(parts)

    def _same_origin(self) -> bool:
        """False if the browser says this POST came from another site."""
        origin = self.headers.get("Origin")
        if origin is None:
            return True  # not a browser, or an old one; SameSite still applies
        return urlsplit(origin).netloc.lower() == self.headers.get("Host", "").lower()

    def _read_form(self) -> Optional[Dict[str, str]]:
        """Read a small urlencoded form body; None if it's missing or too big."""
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return None
        if not 0 <= length <= MAX_FORM_BYTES:
            return None
        body = self.rfile.read(length) if length else b""
        if len(body) != length:
            return None
        try:
            fields = parse_qs(body.decode("utf-8", "replace"), max_num_fields=10)
        except ValueError:
            return None
        return {k: v[0] for k, v in fields.items()}

    # ---- responses -----------------------------------------------------------

    def _send(self, code: int, body: bytes, headers: Dict[str, str]) -> None:
        """Send a complete response. Errors close the connection, as in send_json."""
        if code >= 400:
            self.close_connection = True
        self.send_response(code)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        if code >= 400:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _send_page(self, code: int, page: str, extra: Optional[Dict[str, str]] = None) -> None:
        """Send an HTML page with the security headers."""
        headers = {"Content-Type": "text/html; charset=utf-8", **PAGE_HEADERS, **(extra or {})}
        self._send(code, page.encode("utf-8"), headers)

    def _redirect(self, location: str, extra: Optional[Dict[str, str]] = None) -> None:
        """303 See Other to ``location``."""
        self._send(303, b"", {"Location": location, **PAGE_HEADERS, **(extra or {})})

    def _serve_static(self, name: str) -> None:
        """Serve the stylesheet or icon. Anything else is a 404."""
        if name not in STATIC_FILES:
            self._send_page(404, render_not_found(None))
            return
        with open(os.path.join(STATIC_DIR, name), "rb") as fh:
            body = fh.read()
        self._send(200, body, {
            "Content-Type": STATIC_FILES[name],
            "Cache-Control": "max-age=300",
            "X-Content-Type-Options": "nosniff",
        })

    def _send_raw(self, path: str, download: bool) -> None:
        """Stream a stored file. Only raster images are ever shown inline."""
        name = os.path.basename(path)
        inline_type = None if download else IMAGE_TYPES.get(os.path.splitext(name)[1].lower())
        self.send_response(200)
        self.send_header("Content-Type", inline_type or "application/octet-stream")
        self.send_header("Content-Length", str(os.path.getsize(path)))
        # NAME_RE guarantees the name has no quotes or line breaks.
        self.send_header("Content-Disposition", f'{"inline" if inline_type else "attachment"}; filename="{name}"')
        self.send_header("Content-Security-Policy", RAW_CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            with open(path, "rb") as fh:
                shutil.copyfileobj(fh, self.wfile, 64 * 1024)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
