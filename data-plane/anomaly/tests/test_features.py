from datetime import datetime, timezone
from math import log1p

from anomaly.features import extract


_EXPECTED_KEYS = {
    "hour_of_day", "day_of_week", "log_file_size", "src_port", "dst_port",
    "event_type__file_modified", "event_type__file_created",
    "event_type__file_deleted", "event_type__file_read",
    "event_type__auth_login_success", "event_type__auth_login_failed",
    "event_type__auth_logout", "event_type__auth_sudo",
    "event_type__network_flow", "event_type__network_dns_query",
    "event_type__network_http_request", "event_type__network_file_transfer",
    "source__wazuh_fim", "source__wazuh_auth",
    "source__zeek_conn", "source__zeek_dns",
    "source__zeek_http", "source__zeek_files",
}


def test_extract_returns_exactly_23_keys(make_event):
    """Regression guard. The pickled model's feature_names is derived from
    these keys; adding/removing one would silently break inference."""
    features = extract(make_event())
    assert set(features.keys()) == _EXPECTED_KEYS
    assert len(features) == 23


def test_one_hot_event_type_set_correctly(make_event):
    features = extract(make_event(event_type="file.created"))
    assert features["event_type__file_created"] == 1.0
    et_keys = [k for k in features if k.startswith("event_type__")]
    set_keys = [k for k, v in features.items() if k.startswith("event_type__") and v == 1.0]
    assert len(et_keys) == 12
    assert set_keys == ["event_type__file_created"]


def test_one_hot_source_set_correctly(make_event):
    features = extract(make_event(source="zeek.conn", event_type="network.flow"))
    assert features["source__zeek_conn"] == 1.0
    src_keys = [k for k in features if k.startswith("source__")]
    set_keys = [k for k, v in features.items() if k.startswith("source__") and v == 1.0]
    assert len(src_keys) == 6
    assert set_keys == ["source__zeek_conn"]


def test_file_event_has_zero_ports(make_event):
    features = extract(make_event(event_type="file.modified", file_size_bytes=42))
    assert features["src_port"] == 0.0
    assert features["dst_port"] == 0.0


def test_network_event_has_zero_log_file_size(make_event):
    features = extract(make_event(
        event_type="network.flow", source="zeek.conn",
        src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=49152, dst_port=443, protocol="tcp",
    ))
    assert features["log_file_size"] == 0.0
    assert features["src_port"] == 49152.0
    assert features["dst_port"] == 443.0


def test_log_file_size_uses_log1p(make_event):
    features = extract(make_event(file_size_bytes=1023))
    assert features["log_file_size"] == log1p(1023)


def test_hour_and_day_of_week_from_utc(make_event):
    # 2026-05-17 was a Sunday (weekday=6); choose 14:30 UTC
    ts = datetime(2026, 5, 17, 14, 30, 0, tzinfo=timezone.utc)
    features = extract(make_event(timestamp=ts))
    assert features["hour_of_day"] == 14.0
    assert features["day_of_week"] == 6.0


def test_non_utc_timestamp_normalized_to_utc(make_event):
    """Defense in depth: even if a future ingestor ships a non-UTC AwareDatetime,
    hour_of_day and day_of_week must reflect UTC, not the source tz."""
    from datetime import timedelta

    # 2026-05-17 20:00 +05:30 == 2026-05-17 14:30 UTC == hour 14, Sunday (6)
    tz_ist = timezone(timedelta(hours=5, minutes=30))
    ts = datetime(2026, 5, 17, 20, 0, 0, tzinfo=tz_ist)
    features = extract(make_event(timestamp=ts))
    assert features["hour_of_day"] == 14.0
    assert features["day_of_week"] == 6.0


def test_all_keys_present_for_every_event_type(make_event):
    """No matter the event_type, all 23 keys must appear (one-hots stay 0.0)."""
    for et in ("file.deleted", "auth.login_failed", "network.dns_query"):
        src = "wazuh.fim" if et.startswith("file.") else (
            "wazuh.auth" if et.startswith("auth.") else "zeek.dns"
        )
        features = extract(make_event(event_type=et, source=src))
        assert set(features.keys()) == _EXPECTED_KEYS
