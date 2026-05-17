from intellifim_schemas import CanonicalEvent

from normalizers._helpers import ZEEK_HOST_ID
from normalizers.zeek_conn import transform


def test_conn_maps_to_network_flow(load_fixture):
    raw = load_fixture("zeek_conn.json")
    event = transform(raw)
    assert isinstance(event, CanonicalEvent)
    assert event.event_type == "network.flow"
    assert event.source == "zeek.conn"
    assert event.host_id == ZEEK_HOST_ID
    assert str(event.src_ip) == "10.10.0.10"
    assert event.src_port == 49152
    assert str(event.dst_ip) == "10.10.0.20"
    assert event.dst_port == 80
    assert event.protocol == "tcp"
    assert event.raw == raw


def test_conn_with_zero_ports_yields_none(load_fixture):
    """Zeek records ICMP/connectionless flows with port 0; canonical schema
    requires port >= 1, so the transform must coalesce 0 to None."""
    raw = load_fixture("zeek_conn.json")
    raw["id.orig_p"] = 0
    raw["id.resp_p"] = 0
    raw["proto"] = "icmp"
    event = transform(raw)
    assert event.src_port is None
    assert event.dst_port is None
