#!/usr/bin/env bash
# data-plane/scripts/seed-test-traffic.sh
# Produces a small, deterministic burst of FIM and network events
# against an already-running data-plane stack.
set -euo pipefail

MONITORED_DIR="${MONITORED_DIR:-./monitored}"

if [ ! -d "${MONITORED_DIR}" ]; then
  echo "monitored dir ${MONITORED_DIR} does not exist" >&2
  exit 1
fi

stamp=$(date +%s)
echo "seeding FIM events under ${MONITORED_DIR}/seed-${stamp}/"
mkdir -p "${MONITORED_DIR}/seed-${stamp}"
echo "alpha"  > "${MONITORED_DIR}/seed-${stamp}/a.txt"
echo "bravo"  > "${MONITORED_DIR}/seed-${stamp}/b.txt"
echo "charlie modified" > "${MONITORED_DIR}/seed-${stamp}/a.txt"
rm "${MONITORED_DIR}/seed-${stamp}/b.txt"

echo "seeding network events through victim-client -> victim-server"
docker exec victim-client sh -c '
  for path in / /seed-1 /seed-2 /seed-3; do
    curl -s -o /dev/null "http://victim-server${path}" || true
  done
' || echo "(victim-client not running -- skipping network seed)"

echo "done. wait ~15s, then check events.normalized."
