# simulator

IntelliFIM v1 simulation lab — curated attack scenarios that verify the data plane detects real adversarial activity end-to-end.

**Invocation:** `docker compose --profile sim run --rm simulator <scenario>` (or the wrapper `./scripts/run-scenario.sh`).
**Lifetime:** fire-and-exit (`--rm`). Stack stays at 24 services in normal operation.

## Scenarios

- `data-exfil` — FIM + zeek.http + zeek.dns + zeek.conn (multi-layer chain)
- `webshell-drop` — FIM + zeek.http
- `port-scan` — zeek.conn flurry
- `dns-tunnel` — zeek.dns burst
- `ransomware-rapid` — FIM rapid create/truncate/delete churn

## Local dev

```bash
cd data-plane/simulator
pip install -e .[dev]
pytest -v
```

The scenarios are exercised against the live stack via Docker Compose; see `data-plane/docker-compose.yml`.

## Smoke

```bash
# From data-plane/:
docker compose up -d
./scripts/run-all-scenarios.sh
```

## Cleanup

File-based scenarios (`data-exfil`, `webshell-drop`, `ransomware-rapid`) leave artifacts in `monitored/`. After a smoke run:

```bash
rm -rf monitored/sensitive_* monitored/cmd.php monitored/doc_*
# Or nuke everything:
sudo rm -rf monitored/* 2>/dev/null || true
```
