"""Shared pytest fixtures.

`_T0` is a fixed test clock far enough in the future that real wall-clock
never catches up to it during a test run — the lesson from sub-project #6's
Task 8 (JWT expiry checks were going stale overnight against a 2026-fixed clock).
"""
from __future__ import annotations

import os
from collections.abc import Callable
from datetime import datetime, timezone

import pytest

_T0 = datetime(2030, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def fixed_now() -> Callable[[], datetime]:
    """Returns a `now` callable that always returns `_T0`."""
    return lambda: _T0


@pytest.fixture
def jwt_secret() -> str:
    return "test-jwt-secret-not-for-prod-use"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Each test starts with a clean reporting-relevant env."""
    _exact = {"DB_PATH", "REPORTS_DIR", "BIND_HOST", "PORT"}
    _prefixes = ("KAFKA_", "JWT_", "ORCHESTRATOR_", "CORS_")
    for k in list(os.environ):
        if k in _exact or k.startswith(_prefixes):
            monkeypatch.delenv(k, raising=False)
