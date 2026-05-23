#!/usr/bin/env bash
# Run a single attack scenario.
# Usage: ./scripts/run-scenario.sh <scenario-name> [--threshold N] [--timeout S]
set -euo pipefail
cd "$(dirname "$0")/.."   # data-plane/
exec docker compose --env-file .env.dataplane --profile sim run --rm simulator "$@"
