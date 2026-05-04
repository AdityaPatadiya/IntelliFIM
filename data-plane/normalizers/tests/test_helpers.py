from datetime import datetime, timezone

import pytest

from normalizers._helpers import maybe_int, maybe_lower, parse_utc


# --- maybe_int ---

def test_maybe_int_passes_none_through():
    assert maybe_int(None) is None


def test_maybe_int_treats_empty_string_as_none():
    assert maybe_int("") is None


def test_maybe_int_converts_numeric_string():
    assert maybe_int("42") == 42


def test_maybe_int_passes_int_through():
    assert maybe_int(42) == 42


# --- maybe_lower ---

def test_maybe_lower_passes_none_through():
    assert maybe_lower(None) is None


def test_maybe_lower_lowercases_string():
    assert maybe_lower("ABC123") == "abc123"


# --- parse_utc ---

def test_parse_utc_normalises_utc_timestamp():
    result = parse_utc("2026-05-04T12:00:00.000+0000")
    assert result == datetime(2026, 5, 4, 12, 0, 0, tzinfo=timezone.utc)


def test_parse_utc_converts_non_utc_offset_to_utc():
    """Tz-aware non-UTC input is converted to UTC, not preserved."""
    result = parse_utc("2026-05-04T17:30:00+05:30")
    assert result == datetime(2026, 5, 4, 12, 0, 0, tzinfo=timezone.utc)


def test_parse_utc_rejects_naive_timestamp():
    """A tz-less input would silently use the system local time — refuse it."""
    with pytest.raises(ValueError, match="missing tz"):
        parse_utc("2026-05-04T12:00:00")
