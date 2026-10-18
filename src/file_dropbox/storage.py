"""
How uploads are laid out on disk, and reading them back.

::

    uploads/
    ├── _logs/access.log          every request, one tab-separated line each
    └── <client>/
        ├── uploads.jsonl         one metadata record per stored file
        └── <YYYY-MM-DD>/<name>   the files, under their original names

Older versions stored files flat in ``<client>/`` with a ``.meta.json`` sidecar
each; those are still listed and readable.
"""

import json
import os
import re
import threading
from dataclasses import dataclass
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

Meta = Dict[str, Any]

INDEX_NAME = "uploads.jsonl"   # per-client metadata index
PREVIEW_BYTES = 256 * 1024     # show at most this much of a text file
ACTIVITY_LINES = 15            # recent events on the dashboard
ACTIVITY_TAIL_BYTES = 64 * 1024

INDEX_FILES = {INDEX_NAME, "_uploads.jsonl"}  # current and older index names
DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# Names safe_filename() can produce; no leading dot.
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

_INDEX_LOCK = threading.Lock()  # keeps concurrent JSONL appends whole


# --------------------------------------------------------------------------
# Writing
# --------------------------------------------------------------------------


def safe_filename(name: Optional[str]) -> str:
    """Make ``name`` safe to use as a single path component.

    Strips any directory part, replaces unusual characters with ``_`` and caps
    the length at 200 characters, so path traversal is impossible. Falls back
    to ``"file"`` if nothing usable is left.
    """
    name = (name or "").replace("\\", "/").split("/")[-1]
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name).strip().strip(".")
    return (name or "file")[:200]


def create_unique(directory: str, filename: str) -> Tuple[int, str]:
    """Atomically create a new file in ``directory``, never overwriting.

    Tries ``filename`` first, then ``stem-1.ext``, ``stem-2.ext``, ... until
    one doesn't exist. ``O_EXCL`` makes this safe across concurrent uploads.

    Returns:
        An open, writable file descriptor and the name actually used.
    """
    stem, ext = os.path.splitext(filename)
    candidate, n = filename, 0
    while True:
        try:
            fd = os.open(
                os.path.join(directory, candidate),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                0o644,
            )
            return fd, candidate
        except FileExistsError:
            n += 1
            candidate = f"{stem}-{n}{ext}"


def save_file(root: str, client: str, day: str, filename: str, data: bytes) -> str:
    """Write ``data`` to ``<root>/<client>/<day>/`` without overwriting anything.

    Args:
        root: The upload root.
        client: Client folder name.
        day: ``YYYY-MM-DD`` sub-folder.
        filename: Wanted file name; a clash gets a numeric suffix.
        data: File contents.

    Returns:
        The stored file's path relative to the client folder, e.g.
        ``"2026-10-15/report-1.pdf"``.
    """
    day_dir = os.path.join(root, safe_filename(client), day)
    os.makedirs(day_dir, exist_ok=True)
    fd, stored_name = create_unique(day_dir, safe_filename(filename))
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return f"{day}/{stored_name}"


def append_index(root: str, client: str, meta: Meta) -> None:
    """Append one metadata record to the client's ``uploads.jsonl``."""
    path = os.path.join(root, safe_filename(client), INDEX_NAME)
    with _INDEX_LOCK, open(path, "a") as fh:
        fh.write(json.dumps(meta) + "\n")


# --------------------------------------------------------------------------
# Reading
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
        with open(os.path.join(client_dir, INDEX_NAME), encoding="utf-8") as fh:
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
