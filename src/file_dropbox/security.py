"""
Security building blocks for file-dropbox.

- Password hashing (PBKDF2-HMAC-SHA256 with a random salt).
- Brute-force protection: lock an address out after too many failed attempts.
- Admin sessions with an idle timeout and a per-session CSRF token.

Standard library only.
"""

import base64
import binascii
import hashlib
import hmac
import ipaddress
import math
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional

Clock = Callable[[], float]

PBKDF2_ITERATIONS = 600_000   # OWASP recommendation for PBKDF2-HMAC-SHA256
MAX_TRACKED_ADDRESSES = 10_000  # soft cap on limiter memory
MAX_SESSIONS = 100

# --------------------------------------------------------------------------
# Passwords
# --------------------------------------------------------------------------


def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Hash ``password`` with PBKDF2-HMAC-SHA256 and a fresh random salt.

    Returns:
        A self-describing string ``pbkdf2_sha256$<iterations>$<salt>$<hash>``
        (salt and hash base64-encoded), safe to store in config.json.
    """
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "$".join([
        "pbkdf2_sha256",
        str(iterations),
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    ])


def verify_password(password: str, stored: str) -> bool:
    """Check ``password`` against a hash made by :func:`hash_password`.

    A malformed or empty ``stored`` value never matches.
    """
    try:
        algorithm, iterations, salt, digest = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        expected = base64.b64decode(digest, validate=True)
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            base64.b64decode(salt, validate=True),
            int(iterations),
        )
    except (ValueError, binascii.Error):
        return False
    return hmac.compare_digest(actual, expected)


# --------------------------------------------------------------------------
# Brute-force protection
# --------------------------------------------------------------------------


def client_key(ip: str) -> str:
    """Return the key used to rate-limit an address.

    IPv4 addresses are used as-is (IPv4-mapped IPv6 is unwrapped). IPv6
    addresses are grouped by their /64, since one host usually owns a whole
    /64 and could otherwise rotate addresses to dodge the lockout.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


class LoginLimiter:
    """Locks out an address after too many failed attempts in a short window.

    After ``max_failures`` failures within ``window_seconds``, the address is
    locked for ``lockout_seconds``. A success clears its failure count.
    Thread-safe.
    """

    def __init__(
        self,
        max_failures: int = 5,
        window_seconds: float = 900,
        lockout_seconds: float = 900,
        clock: Clock = time.monotonic,
    ) -> None:
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._clock = clock
        self._failures: Dict[str, List[float]] = {}
        self._locked_until: Dict[str, float] = {}
        self._lock = threading.Lock()

    def retry_after(self, key: str) -> int:
        """Seconds until ``key`` may try again; 0 if it isn't locked out."""
        with self._lock:
            until = self._locked_until.get(key)
            if until is None:
                return 0
            remaining = until - self._clock()
            if remaining <= 0:
                del self._locked_until[key]
                return 0
            return math.ceil(remaining)

    def record_failure(self, key: str) -> int:
        """Count one failed attempt for ``key``.

        Returns:
            How many attempts are left before a lockout; 0 means ``key`` has
            just been locked out.
        """
        with self._lock:
            now = self._clock()
            recent = [t for t in self._failures.get(key, []) if now - t < self.window_seconds]
            recent.append(now)
            if len(recent) >= self.max_failures:
                self._failures.pop(key, None)
                self._locked_until[key] = now + self.lockout_seconds
                left = 0
            else:
                self._failures[key] = recent
                left = self.max_failures - len(recent)
            self._prune(now)
            return left

    def record_success(self, key: str) -> None:
        """Forget earlier failures for ``key``."""
        with self._lock:
            self._failures.pop(key, None)

    def reset(self) -> None:
        """Forget all failures and lockouts."""
        with self._lock:
            self._failures.clear()
            self._locked_until.clear()

    def _prune(self, now: float) -> None:
        """Drop stale entries once too many addresses are tracked. Caller holds the lock."""
        if len(self._failures) + len(self._locked_until) <= MAX_TRACKED_ADDRESSES:
            return
        self._failures = {
            k: ts for k, ts in self._failures.items() if now - ts[-1] < self.window_seconds
        }
        self._locked_until = {k: u for k, u in self._locked_until.items() if u > now}
        if len(self._failures) + len(self._locked_until) > MAX_TRACKED_ADDRESSES:
            # Still flooded: give up on counting failures, but keep every lockout.
            self._failures.clear()


# --------------------------------------------------------------------------
# Admin sessions
# --------------------------------------------------------------------------


@dataclass
class Session:
    """One signed-in admin browser."""

    sid: str       # value of the session cookie
    csrf: str      # token that every state-changing form must echo back
    expires: float


class SessionStore:
    """In-memory admin sessions with a sliding idle timeout. Thread-safe.

    Sessions don't survive a restart, so restarting the server signs
    everyone out.
    """

    def __init__(self, idle_seconds: float = 1800, clock: Clock = time.monotonic) -> None:
        self.idle_seconds = idle_seconds
        self._clock = clock
        self._sessions: Dict[str, Session] = {}
        self._lock = threading.Lock()

    def create(self) -> Session:
        """Start a new session with fresh random ids."""
        with self._lock:
            now = self._clock()
            self._sessions = {k: s for k, s in self._sessions.items() if s.expires > now}
            while len(self._sessions) >= MAX_SESSIONS:
                oldest = min(self._sessions.values(), key=lambda s: s.expires)
                del self._sessions[oldest.sid]
            session = Session(
                sid=secrets.token_urlsafe(32),
                csrf=secrets.token_urlsafe(32),
                expires=now + self.idle_seconds,
            )
            self._sessions[session.sid] = session
            return session

    def get(self, sid: Optional[str]) -> Optional[Session]:
        """Return the live session for ``sid`` and extend it, or None."""
        if not sid:
            return None
        with self._lock:
            session = self._sessions.get(sid)
            if session is None:
                return None
            now = self._clock()
            if session.expires <= now:
                del self._sessions[sid]
                return None
            session.expires = now + self.idle_seconds
            return session

    def delete(self, sid: str) -> None:
        """End a session (sign out)."""
        with self._lock:
            self._sessions.pop(sid, None)
