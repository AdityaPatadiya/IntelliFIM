#!/usr/bin/env bash
# data-plane/scripts/replay-pcap.sh
# Replay a pcap into the Zeek sensor's monitored network.
#
# Usage:
#   scripts/replay-pcap.sh pcaps/http_get_basic.pcap
#
# The pcap is copied into the zeek-sensor container, replayed via
# tcpreplay onto the same interface Zeek is listening on, then deleted.
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 <pcap-file>" >&2
  exit 1
fi

pcap="$1"
if [ ! -f "${pcap}" ]; then
  echo "pcap not found: ${pcap}" >&2
  exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -q '^zeek-sensor$'; then
  echo "zeek-sensor container is not running" >&2
  exit 1
fi

echo "ensuring tcpreplay is available inside zeek-sensor"
docker exec zeek-sensor sh -c "command -v tcpreplay >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq tcpreplay >/dev/null)"

echo "copying ${pcap} -> zeek-sensor:/tmp/replay.pcap"
docker cp "${pcap}" zeek-sensor:/tmp/replay.pcap

echo "replaying onto eth0"
docker exec zeek-sensor tcpreplay -i eth0 -K /tmp/replay.pcap

docker exec zeek-sensor rm -f /tmp/replay.pcap
echo "done. Zeek should produce logs within a second; canonical events follow within ~15s."
