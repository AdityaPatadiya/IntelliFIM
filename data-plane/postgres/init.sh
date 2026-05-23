#!/usr/bin/env bash
# data-plane/postgres/init.sh
# Runs ONCE on first postgres boot when $PGDATA is empty.
# Creates the 3 service users + 3 databases for IntelliFIM v2 Postgres.
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE USER auth         WITH PASSWORD '${POSTGRES_AUTH_PASSWORD}';
    CREATE USER orchestrator WITH PASSWORD '${POSTGRES_ORCH_PASSWORD}';
    CREATE USER reporting    WITH PASSWORD '${POSTGRES_REPORTING_PASSWORD}';

    CREATE DATABASE auth_backend OWNER auth;
    CREATE DATABASE orchestrator OWNER orchestrator;
    CREATE DATABASE reporting    OWNER reporting;
EOSQL
