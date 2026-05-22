# reporting

IntelliFIM v1 reporting service — generates persistent PDF "Security Summary" reports from `threat.scores` (consumed from Kafka into local SQLite) + `/approvals` (fetched on-demand from `response-orchestrator`).

**Port:** 8300 (bound to `127.0.0.1`).
**Storage:** `/data/reporting.db` + `/data/reports/*.pdf` on the `reporting_data` Compose volume.
**Auth:** HS256 JWT (shared `JWT_SECRET` with `auth-backend` + `response-orchestrator`).
**Roles:** `admin | analyst` can generate/delete; any logged-in user can list/download.

## Endpoints

- `GET /healthz`
- `POST /reports/generate` (admin|analyst)
- `GET /reports?limit=N&offset=M` (any role)
- `GET /reports/{id}` (any role)
- `GET /reports/{id}/download` (any role)
- `DELETE /reports/{id}` (admin)

## Local dev

```bash
cd data-plane/reporting
pip install -e .[dev]
pytest -v
```

The service is built and run via Docker Compose; see `data-plane/docker-compose.yml`.

## Smoke

```bash
# from data-plane/
docker compose up -d
./scripts/generate-report.py
```

See `data-plane/scripts/generate-report.py` for the end-to-end happy path.
