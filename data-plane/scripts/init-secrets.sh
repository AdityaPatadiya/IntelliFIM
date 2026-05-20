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
    exit 0
fi

SECRET=$(openssl rand -base64 48 | tr -d '\n')

# If a blank JWT_SECRET= line exists, replace it; else append.
if grep -q '^JWT_SECRET=$' "$ENV_FILE"; then
    sed -i "s|^JWT_SECRET=$|JWT_SECRET=${SECRET}|" "$ENV_FILE"
else
    echo "JWT_SECRET=${SECRET}" >> "$ENV_FILE"
fi

echo "JWT_SECRET written to ${ENV_FILE}"
