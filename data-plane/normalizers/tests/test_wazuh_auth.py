import pytest

from intellifim_schemas import CanonicalEvent

from normalizers.wazuh_auth import transform


def test_login_success_maps(load_fixture):
    raw = load_fixture("wazuh_auth_login_success.json")
    event = transform(raw)
    assert isinstance(event, CanonicalEvent)
    assert event.event_type == "auth.login_success"
    assert event.source == "wazuh.auth"
    assert event.host_id == "001"
    assert event.user == "alice"
    assert event.user_uid == 1001
    assert str(event.src_ip) == "10.0.0.42"
    assert event.raw == raw


def test_login_failed_maps(load_fixture):
    raw = load_fixture("wazuh_auth_login_failed.json")
    event = transform(raw)
    assert event.event_type == "auth.login_failed"
    assert event.user == "alice"
    assert str(event.src_ip) == "10.0.0.99"
    assert event.user_uid is None  # not present in this event


def test_sudo_maps(load_fixture):
    raw = load_fixture("wazuh_auth_sudo.json")
    event = transform(raw)
    assert event.event_type == "auth.sudo"
    assert event.user == "alice"  # source user, not target
    assert event.user_uid == 0


def test_unknown_rule_groups_raises_value_error(load_fixture):
    """Unknown rule groups must raise ValueError so the base loop log+skips."""
    raw = load_fixture("wazuh_auth_login_success.json")
    raw["rule"]["groups"] = ["pam", "syslog"]  # no auth-related group
    raw["rule"]["id"] = "9999"
    with pytest.raises(ValueError, match="rule.id='9999'"):
        transform(raw)
