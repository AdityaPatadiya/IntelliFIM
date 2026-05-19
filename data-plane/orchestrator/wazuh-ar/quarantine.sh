#!/bin/bash
# data-plane/orchestrator/wazuh-ar/quarantine.sh
# IntelliFIM v1 walking-skeleton: touch a marker file so we can prove the AR
# pipeline (manager -> agent -> script execution) end-to-end.
set -euo pipefail

LOG_FILE="${LOG_FILE_OVERRIDE:-/var/ossec/logs/active-responses.log}"
MARKER_DIR="${MARKER_DIR_OVERRIDE:-/tmp}"

INPUT=$(cat)
echo "$(date -u +%FT%TZ) quarantine.sh invoked input=${INPUT}" >> "$LOG_FILE" 2>/dev/null || true

# Extract update_id from the parameters block (passed by the dispatcher).
# Fall back to a timestamp if absent so the script never crashes.
UPDATE_ID=$(echo "$INPUT" | grep -oE '"update_id"[[:space:]]*:[[:space:]]*"[^"]+"' \
              | sed -E 's/.*"([^"]+)"$/\1/' \
              | head -1)
if [ -z "$UPDATE_ID" ]; then
    UPDATE_ID="no-id-$(date +%s)"
fi

MARKER="${MARKER_DIR}/intellifim-quarantine-${UPDATE_ID}.flag"
touch "$MARKER"

# Confirmation Wazuh expects (origin.name "quarantine" identifies us).
echo '{"version":1,"origin":{"name":"quarantine","module":"active-response"},"command":"check_keys","parameters":{"keys":[]}}'
exit 0
