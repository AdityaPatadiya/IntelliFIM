#!/usr/bin/env bash
# data-plane/scripts/init-secrets.sh
# Generates JWT_SECRET in .env.dataplane on first stack-up (idempotent).
# Safe to re-run: skips if JWT_SECRET is already set to a non-empty value.
set -euo pipefail

ENV_FILE="$(dirname "$0")/../.env.dataplane"

if [ ! -f "$ENV_FILE" ]; then
    echo "ERROR: $ENV_FILE not found. Copy .env.dataplane.example first." >&2
    exit 1
fi

if grep -q '^JWT_SECRET=.\+' "$ENV_FILE"; then
    echo "JWT_SECRET already set in ${ENV_FILE}; skipping."
else
    SECRET=$(openssl rand -base64 48 | tr -d '\n')

    # If a blank JWT_SECRET= line exists, replace it; else append.
    if grep -q '^JWT_SECRET=$' "$ENV_FILE"; then
        sed -i "s|^JWT_SECRET=$|JWT_SECRET=${SECRET}|" "$ENV_FILE"
    else
        echo "JWT_SECRET=${SECRET}" >> "$ENV_FILE"
    fi

    echo "JWT_SECRET written to ${ENV_FILE}"
fi

# v2: 4 Postgres passwords (root + 3 service users)
for var in POSTGRES_ROOT_PASSWORD POSTGRES_AUTH_PASSWORD POSTGRES_ORCH_PASSWORD POSTGRES_REPORTING_PASSWORD; do
    if grep -q "^${var}=.\+" "$ENV_FILE"; then
        echo "${var} already set in ${ENV_FILE}; skipping."
        continue
    fi
    # hex (not base64) — Postgres passwords go into DATABASE_URL; base64 chars `/+=` break URL parsing
    PG_SECRET=$(openssl rand -hex 24)
    if grep -q "^${var}=$" "$ENV_FILE"; then
        sed -i "s|^${var}=$|${var}=${PG_SECRET}|" "$ENV_FILE"
    else
        echo "${var}=${PG_SECRET}" >> "$ENV_FILE"
    fi
    echo "${var} written to ${ENV_FILE}"
done
