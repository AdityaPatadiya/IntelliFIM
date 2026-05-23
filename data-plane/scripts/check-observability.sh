#!/usr/bin/env bash
# Verifies Prometheus is scraping all 6 IntelliFIM services and the
# IntelliFIMServiceDown alert rule is loaded.
set -uo pipefail
cd "$(dirname "$0")/.."

echo "=== Prometheus health ==="
curl -fsS http://127.0.0.1:9090/-/healthy && echo " OK"

echo "=== Scrape targets ==="
UP_COUNT=$(curl -fsSG --data-urlencode 'query=up{job=~"intellifim-.+"}' http://127.0.0.1:9090/api/v1/query \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print(sum(1 for r in d["data"]["result"] if r["value"][1]=="1"))')
echo "scrape targets up: $UP_COUNT / 6"
[ "$UP_COUNT" = "6" ] || { echo "ERROR: expected 6"; exit 2; }

echo "=== Alert rule loaded ==="
curl -fsS http://127.0.0.1:9090/api/v1/rules | python3 -c '
import sys, json
d = json.load(sys.stdin)
rules = [r for g in d["data"]["groups"] for r in g["rules"]]
names = [r["name"] for r in rules]
print("rules:", names)
assert "IntelliFIMServiceDown" in names, "missing IntelliFIMServiceDown rule"
'

echo "=== Grafana health ==="
curl -fsS http://127.0.0.1:3000/api/health | python3 -m json.tool

echo "=== Alertmanager health ==="
curl -fsS http://127.0.0.1:9093/-/healthy && echo " OK"

echo "PASS"
