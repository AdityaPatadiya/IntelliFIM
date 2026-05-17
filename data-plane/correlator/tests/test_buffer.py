from datetime import datetime, timedelta, timezone

from correlator.buffer import HostBuffer


_T0 = datetime(2026, 5, 4, 12, 0, 0, tzinfo=timezone.utc)


def _now_factory(seconds_offset: int):
    """Returns a callable that always returns _T0 + seconds_offset."""
    def _now() -> datetime:
        return _T0 + timedelta(seconds=seconds_offset)
    return _now


def test_add_and_recent_returns_event(make_event):
    buf = HostBuffer(window_seconds=60, now=_now_factory(0))
    event = make_event(timestamp=_T0)
    buf.add(event)
    found = buf.recent("host-001", lambda e: e.event_type.startswith("file."))
    assert found == [event]


def test_recent_isolates_by_host(make_event):
    buf = HostBuffer(window_seconds=60, now=_now_factory(0))
    a = make_event(host_id="host-A", timestamp=_T0)
    b = make_event(host_id="host-B", timestamp=_T0)
    buf.add(a)
    buf.add(b)
    found_a = buf.recent("host-A", lambda e: True)
    found_b = buf.recent("host-B", lambda e: True)
    assert found_a == [a]
    assert found_b == [b]


def test_recent_returns_empty_for_unknown_host(make_event):
    buf = HostBuffer(window_seconds=60, now=_now_factory(0))
    buf.add(make_event(host_id="host-A", timestamp=_T0))
    assert buf.recent("host-NOPE", lambda e: True) == []


def test_old_events_are_expired_on_add(make_event):
    """Events older than window_seconds (relative to `now`) are dropped when
    new entries are added or queried."""
    buf = HostBuffer(window_seconds=60, now=_now_factory(120))  # now is T0 + 120s
    old = make_event(timestamp=_T0)  # 120s old, outside 60s window
    fresh = make_event(timestamp=_T0 + timedelta(seconds=90))  # 30s old, inside window
    buf.add(old)
    buf.add(fresh)
    found = buf.recent("host-001", lambda e: True)
    assert found == [fresh]


def test_recent_filters_by_predicate(make_event):
    buf = HostBuffer(window_seconds=60, now=_now_factory(0))
    file_event = make_event(event_type="file.modified", timestamp=_T0)
    net_event = make_event(event_type="network.flow", source="zeek.conn", timestamp=_T0)
    buf.add(file_event)
    buf.add(net_event)
    files = buf.recent("host-001", lambda e: e.event_type.startswith("file."))
    nets = buf.recent("host-001", lambda e: e.event_type.startswith("network."))
    assert files == [file_event]
    assert nets == [net_event]
