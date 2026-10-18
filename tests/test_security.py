"""
Unit tests for security.py (pytest): password hashing, the brute-force
limiter and admin sessions. Time is faked, so nothing here sleeps.

Run:  pytest -v
"""

import pytest

from file_dropbox.security import LoginLimiter
from file_dropbox.security import SessionStore
from file_dropbox.security import client_key
from file_dropbox.security import hash_password
from file_dropbox.security import verify_password


class FakeClock:
    """A clock the test moves by hand."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


# --------------------------------------------------------------------------
# Passwords
# --------------------------------------------------------------------------


def test_hash_and_verify_round_trip():
    stored = hash_password("s3cret-enough", iterations=1000)
    assert stored.startswith("pbkdf2_sha256$1000$")
    assert verify_password("s3cret-enough", stored)
    assert not verify_password("s3cret-enougH", stored)
    assert not verify_password("", stored)


def test_hashes_are_salted():
    assert hash_password("same", iterations=1000) != hash_password("same", iterations=1000)


@pytest.mark.parametrize("stored", [
    "",
    "garbage",
    "md5$1$YQ==$YQ==",
    "pbkdf2_sha256$x$YQ==$YQ==",
    "pbkdf2_sha256$1000$!!$!!",
    "pbkdf2_sha256$0$YQ==$YQ==",
])
def test_malformed_hash_never_matches(stored):
    assert not verify_password("anything", stored)


# --------------------------------------------------------------------------
# Brute-force limiter
# --------------------------------------------------------------------------


def test_limiter_locks_after_max_failures():
    clock = FakeClock()
    limiter = LoginLimiter(max_failures=3, window_seconds=60, lockout_seconds=300, clock=clock)
    assert limiter.record_failure("1.2.3.4") == 2
    assert limiter.record_failure("1.2.3.4") == 1
    assert limiter.retry_after("1.2.3.4") == 0
    assert limiter.record_failure("1.2.3.4") == 0
    assert limiter.retry_after("1.2.3.4") == 300
    assert limiter.retry_after("5.6.7.8") == 0  # other addresses are unaffected


def test_lockout_expires():
    clock = FakeClock()
    limiter = LoginLimiter(max_failures=1, window_seconds=60, lockout_seconds=300, clock=clock)
    limiter.record_failure("a")
    clock.now += 299.5
    assert limiter.retry_after("a") == 1
    clock.now += 1
    assert limiter.retry_after("a") == 0


def test_old_failures_fall_out_of_the_window():
    clock = FakeClock()
    limiter = LoginLimiter(max_failures=2, window_seconds=60, lockout_seconds=300, clock=clock)
    limiter.record_failure("a")
    clock.now += 61
    assert limiter.record_failure("a") == 1  # the first one no longer counts
    assert limiter.retry_after("a") == 0


def test_success_clears_failures():
    limiter = LoginLimiter(max_failures=2, clock=FakeClock())
    limiter.record_failure("a")
    limiter.record_success("a")
    assert limiter.record_failure("a") == 1


@pytest.mark.parametrize("ip, key", [
    ("192.168.1.42", "192.168.1.42"),
    ("::ffff:192.168.1.42", "192.168.1.42"),
    ("2001:db8:1:2:aaaa::1", "2001:db8:1:2::/64"),
    ("2001:db8:1:2:bbbb::9", "2001:db8:1:2::/64"),  # same /64, same bucket
    ("not-an-ip", "not-an-ip"),
])
def test_client_key(ip, key):
    assert client_key(ip) == key


# --------------------------------------------------------------------------
# Sessions
# --------------------------------------------------------------------------


def test_session_idle_timeout_slides():
    clock = FakeClock()
    store = SessionStore(idle_seconds=100, clock=clock)
    session = store.create()
    clock.now += 90
    assert store.get(session.sid) is session  # use extends it...
    clock.now += 90
    assert store.get(session.sid) is session
    clock.now += 101
    assert store.get(session.sid) is None     # ...but idling ends it


def test_sessions_are_random_and_deletable():
    store = SessionStore(clock=FakeClock())
    a, b = store.create(), store.create()
    assert a.sid != b.sid and a.csrf != b.csrf and a.sid != a.csrf
    assert len(a.sid) >= 40
    store.delete(a.sid)
    assert store.get(a.sid) is None
    assert store.get(b.sid) is b
    assert store.get(None) is None
    assert store.get("made-up") is None
