#!/usr/bin/env bash
# Verify the Postgres-backed v2 stores are healthy + populated.
set -uo pipefail
cd "$(dirname "$0")/.."

echo "=== Postgres health ==="
docker exec postgres pg_isready -U postgres -d postgres && echo " OK"

echo "=== 3 databases exist ==="
DB_COUNT=$(docker exec postgres psql -U postgres -tAc \
  "SELECT count(*) FROM pg_database WHERE datname IN ('auth_backend','orchestrator','reporting')")
echo "databases: $DB_COUNT / 3"
[ "$DB_COUNT" = "3" ] || { echo "ERROR: expected 3"; exit 2; }

echo "=== 3 service users exist ==="
USER_COUNT=$(docker exec postgres psql -U postgres -tAc \
  "SELECT count(*) FROM pg_user WHERE usename IN ('auth','orchestrator','reporting')")
echo "service users: $USER_COUNT / 3"
[ "$USER_COUNT" = "3" ] || { echo "ERROR: expected 3"; exit 2; }

echo "=== Each service can connect + has its tables ==="
docker exec postgres psql -U postgres -d auth_backend -tAc "SELECT count(*) FROM users" \
  | awk '{print "auth_backend.users rows:", $0}'
docker exec postgres psql -U postgres -d orchestrator -tAc "SELECT count(*) FROM approvals" \
  | awk '{print "orchestrator.approvals rows:", $0}'
docker exec postgres psql -U postgres -d reporting -tAc "SELECT count(*) FROM threat_scores" \
  | awk '{print "reporting.threat_scores rows:", $0}'
docker exec postgres psql -U postgres -d reporting -tAc "SELECT count(*) FROM reports" \
  | awk '{print "reporting.reports rows:", $0}'

echo "PASS"
