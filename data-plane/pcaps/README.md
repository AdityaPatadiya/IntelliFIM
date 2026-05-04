# Curated PCAPs

These captures are used by `scripts/replay-pcap.sh` to inject deterministic
network traffic at the Zeek sensor.

| File | Description | Expected canonical events |
|---|---|---|
| `http_get_basic.pcap` | Single HTTP GET from victim-client to victim-server. | One `network.flow` (zeek.conn), one `network.http_request` (zeek.http), possibly one `network.file_transfer` (zeek.files). |

## Capturing a new pcap

1. Bring up `zeek-sensor` and the victim containers.
2. `docker exec zeek-sensor tcpdump -i eth0 -w /tmp/<name>.pcap <bpf-filter>`
3. Generate the traffic in another shell.
4. `docker cp zeek-sensor:/tmp/<name>.pcap pcaps/<name>.pcap`
5. Add the file to this table.

Note: Zeek shares victim-server's network namespace (see `docker-compose.yml`),
so the only interface inside the zeek-sensor container is `eth0`.
