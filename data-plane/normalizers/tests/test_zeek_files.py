from intellifim_schemas import CanonicalEvent

from normalizers._helpers import ZEEK_HOST_ID
from normalizers.zeek_files import transform


def test_files_maps_to_network_file_transfer(load_fixture):
    raw = load_fixture("zeek_files.json")
    event = transform(raw)
    assert isinstance(event, CanonicalEvent)
    assert event.event_type == "network.file_transfer"
    assert event.source == "zeek.files"
    assert event.host_id == ZEEK_HOST_ID
    assert str(event.src_ip) == "10.10.0.20"   # tx_hosts[0]
    assert str(event.dst_ip) == "10.10.0.10"   # rx_hosts[0]
    assert event.file_path == "index.html"
    assert event.file_size_bytes == 1500
    assert event.file_hash_sha256 == "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef5678ab"
    assert event.raw == raw


def test_sha256_is_lowercased(load_fixture):
    """Defensive: Zeek normally emits lowercase, but if it ever emits uppercase
    we must still satisfy the canonical Sha256Hex pattern (lowercase-only)."""
    raw = load_fixture("zeek_files.json")
    raw["sha256"] = "AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12CD34EF5678AB"
    event = transform(raw)
    assert event.file_hash_sha256 == "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef5678ab"


def test_missing_tx_or_rx_hosts_yields_none(load_fixture):
    """Some files.log entries may have empty arrays — IPs should be None then."""
    raw = load_fixture("zeek_files.json")
    raw["tx_hosts"] = []
    raw["rx_hosts"] = []
    event = transform(raw)
    assert event.src_ip is None
    assert event.dst_ip is None
