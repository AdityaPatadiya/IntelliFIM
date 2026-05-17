from datetime import datetime, timezone

import pytest

from normalizers._helpers import maybe_int, maybe_lower, parse_unix_utc, parse_utc


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


# --- parse_unix_utc ---

def test_parse_unix_utc_normalises_to_utc():
    """Zeek emits ts as float seconds since epoch; result is tz-aware UTC."""
    result = parse_unix_utc(1746374400.0)
    assert result == datetime(2025, 5, 4, 16, 0, 0, tzinfo=timezone.utc)


def test_parse_unix_utc_preserves_subsecond():
    result = parse_unix_utc(1746374400.123456)
    assert result.microsecond == 123456
    assert result.tzinfo == timezone.utc


# --- ZEEK_HOST_ID env override ---

def test_zeek_host_id_defaults_when_env_unset(monkeypatch):
    monkeypatch.delenv("ZEEK_HOST_ID", raising=False)
    from normalizers._helpers import _zeek_host_id
    assert _zeek_host_id() == "zeek-sensor"


def test_zeek_host_id_reads_env_override(monkeypatch):
    monkeypatch.setenv("ZEEK_HOST_ID", "001")
    from normalizers._helpers import _zeek_host_id
    assert _zeek_host_id() == "001"
