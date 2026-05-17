from intellifim_schemas import CanonicalEvent

from normalizers._helpers import ZEEK_HOST_ID
from normalizers.zeek_http import transform


def test_http_maps_to_network_http_request(load_fixture):
    raw = load_fixture("zeek_http.json")
    event = transform(raw)
    assert isinstance(event, CanonicalEvent)
    assert event.event_type == "network.http_request"
    assert event.source == "zeek.http"
    assert event.host_id == ZEEK_HOST_ID
    assert str(event.src_ip) == "10.10.0.10"
    assert event.src_port == 49160
    assert str(event.dst_ip) == "10.10.0.20"
    assert event.dst_port == 80
    assert event.protocol == "http"
    assert event.raw == raw
