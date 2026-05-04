from intellifim_schemas import CanonicalEvent

from normalizers.zeek_dns import transform


def test_dns_maps_to_network_dns_query(load_fixture):
    raw = load_fixture("zeek_dns.json")
    event = transform(raw)
    assert isinstance(event, CanonicalEvent)
    assert event.event_type == "network.dns_query"
    assert event.source == "zeek.dns"
    assert event.host_id == "zeek-sensor"
    assert str(event.src_ip) == "10.10.0.10"
    assert event.src_port == 51234
    assert str(event.dst_ip) == "10.10.0.1"
    assert event.dst_port == 53
    assert event.protocol == "dns"
    assert event.raw == raw
