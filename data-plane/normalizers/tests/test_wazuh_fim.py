from datetime import timezone

from intellifim_schemas import CanonicalEvent

from normalizers.wazuh_fim import transform


def test_modify_event_maps_to_file_modified(load_fixture):
    raw = load_fixture("wazuh_fim_modify.json")
    event = transform(raw)
    assert isinstance(event, CanonicalEvent)
    assert event.event_type == "file.modified"
    assert event.source == "wazuh.fim"
    assert event.host_id == "001"
    assert event.host_name == "linux-endpoint-1"
    assert event.user == "alice"
    assert event.user_uid == 1001
    assert event.process_name == "vim"
    assert event.process_pid == 4242
    assert event.file_path == "/etc/shadow"
    assert event.file_size_bytes == 1842
    assert event.file_hash_sha256 == "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef561234"
    assert event.raw == raw


def test_create_event_maps_to_file_created(load_fixture):
    raw = load_fixture("wazuh_fim_create.json")
    event = transform(raw)
    assert event.event_type == "file.created"
    assert event.file_path == "/tmp/new-file.txt"


def test_delete_event_maps_to_file_deleted(load_fixture):
    raw = load_fixture("wazuh_fim_delete.json")
    event = transform(raw)
    assert event.event_type == "file.deleted"
    assert event.file_size_bytes is None
    assert event.file_hash_sha256 is None


def test_timestamp_is_normalized_to_utc(load_fixture):
    """Convention: every canonical event carries a UTC tz-aware timestamp."""
    raw = load_fixture("wazuh_fim_modify.json")
    event = transform(raw)
    assert event.timestamp.tzinfo == timezone.utc
    assert event.timestamp.isoformat() == "2026-05-04T12:00:00+00:00"


def test_sha256_hash_is_lowercased(load_fixture):
    """Convention: SHA-256 hashes are lowercase hex (Sha256Hex schema constraint)."""
    raw = load_fixture("wazuh_fim_modify.json")
    raw["syscheck"]["sha256_after"] = "AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12CD34EF561234"
    event = transform(raw)
    assert event.file_hash_sha256 == "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef561234"
