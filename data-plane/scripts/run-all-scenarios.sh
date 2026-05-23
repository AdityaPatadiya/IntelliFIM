#!/usr/bin/env bash
# Run all 5 scenarios sequentially with a 5s settle between each.
# Exit 0 if every scenario was detected; non-zero if any failed.
set -uo pipefail
cd "$(dirname "$0")/.."   # data-plane/

SCENARIOS=(data-exfil webshell-drop port-scan dns-tunnel ransomware-rapid)
PASS=()
FAIL=()

for s in "${SCENARIOS[@]}"; do
  echo "=== $s ==="
  if ./scripts/run-scenario.sh "$s"; then
    PASS+=("$s")
  else
    FAIL+=("$s")
  fi
  echo ""
  sleep 5   # give policy-engine sliding window time to settle between attacks
done

echo "================================================================"
echo "PASS (${#PASS[@]}/${#SCENARIOS[@]}): ${PASS[*]:-}"
echo "FAIL (${#FAIL[@]}/${#SCENARIOS[@]}): ${FAIL[*]:-}"
[ ${#FAIL[@]} -eq 0 ]
