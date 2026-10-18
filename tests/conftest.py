"""Fixtures shared by every test module."""

from typing import Iterator

import pytest

from file_dropbox import server


@pytest.fixture(autouse=True)
def fresh_limiter() -> Iterator[None]:
    """Every test starts with no failed attempts on record."""
    yield
    server.LIMITER.reset()
