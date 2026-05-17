#!/usr/bin/env bash
# Backend container entrypoint.
#
# Responsibilities, in order:
#   1. Block until Postgres + Redis are reachable.
#   2. Optionally run migrations (only one service should: usually `backend`).
#   3. Optionally run collectstatic (prod).
#   4. exec the actual command (daphne / celery worker / celery beat).
set -euo pipefail

wait_for_tcp() {
    local host="$1"
    local port="$2"
    local label="$3"
    echo "[entrypoint] Waiting for ${label} at ${host}:${port}..."
    for _ in $(seq 1 60); do
        if python - <<EOF >/dev/null 2>&1
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect(("${host}", int("${port}")))
    s.close()
except Exception:
    sys.exit(1)
EOF
        then
            echo "[entrypoint] ${label} reachable."
            return 0
        fi
        sleep 1
    done
    echo "[entrypoint] ERROR: ${label} did not become reachable in 60s."
    return 1
}

# ---- Postgres ----
if [ -n "${DB_HOST:-}" ] && [ -n "${DB_PORT:-}" ]; then
    wait_for_tcp "${DB_HOST}" "${DB_PORT}" "postgres"
fi

# ---- Redis (use broker URL host) ----
if [ -n "${CELERY_BROKER_URL:-}" ]; then
    echo "[entrypoint] Waiting for redis (broker)..."
    for _ in $(seq 1 60); do
        if python - <<EOF >/dev/null 2>&1
import os, sys
import redis
try:
    r = redis.Redis.from_url(os.environ["CELERY_BROKER_URL"], socket_connect_timeout=2)
    r.ping()
except Exception:
    sys.exit(1)
EOF
        then
            echo "[entrypoint] Redis reachable."
            break
        fi
        sleep 1
    done
fi

# ---- Migrations ----
if [ "${RUN_MIGRATIONS:-0}" = "1" ]; then
    echo "[entrypoint] Running migrations..."
    python manage.py migrate --database=auth_db --noinput
    python manage.py migrate --database=default --noinput
fi

# ---- collectstatic ----
if [ "${RUN_COLLECTSTATIC:-0}" = "1" ]; then
    echo "[entrypoint] Running collectstatic..."
    python manage.py collectstatic --noinput --clear
fi

echo "[entrypoint] Launching: $*"
exec "$@"
