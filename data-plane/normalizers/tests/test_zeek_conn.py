from intellifim_schemas import CanonicalEvent

from normalizers.zeek_conn import transform


def test_conn_maps_to_network_flow(load_fixture):
    raw = load_fixture("zeek_conn.json")
    event = transform(raw)
    assert isinstance(event, CanonicalEvent)
    assert event.event_type == "network.flow"
    assert event.source == "zeek.conn"
    assert event.host_id == "zeek-sensor"
    assert str(event.src_ip) == "10.10.0.10"
    assert event.src_port == 49152
    assert str(event.dst_ip) == "10.10.0.20"
    assert event.dst_port == 80
    assert event.protocol == "tcp"
    assert event.raw == raw
