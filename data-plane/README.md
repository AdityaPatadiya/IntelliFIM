# IntelliFIM Data Plane (v1 — walking skeleton)

Self-contained Docker Compose stack that delivers validated, canonical
security events from a Linux endpoint and a network sensor into the
`events.normalized` Kafka topic. This is the foundation every other
IntelliFIM sub-project (correlation, ML, scoring, dashboard) consumes.

See [`docs/superpowers/specs/2026-05-04-data-plane-v1-design.md`](../docs/superpowers/specs/2026-05-04-data-plane-v1-design.md)
for the full design. v2 (Schema Registry, observability, secrets) and
v3 (HA Kafka, K8s, multi-agent) are explicit follow-ups.

## What's in the box

16 services on Docker Compose:

- **Sources:** `wazuh-manager`, `wazuh-agent`, `zeek-sensor`
- **Shipping:** `filebeat-wazuh`, `filebeat-zeek`
- **Bus:** `kafka` (single broker, KRaft mode)
- **Correlation:** `correlation-engine` (per-host file ↔ network time-window join, see [correlator/](correlator/))
- **Normalizers:** `normalizer-wazuh-fim`, `normalizer-wazuh-auth`,
  `normalizer-zeek-conn`, `normalizer-zeek-dns`, `normalizer-zeek-http`,
  `normalizer-zeek-files`
- **Dev tooling:** `kafka-ui`, `victim-server`, `victim-client`

## Prerequisites

- Docker Engine >= 24 with Compose v2
- ~4 GB free RAM, ~5 GB disk
- Python 3.12 (only if you want to run `tail-normalized.py` from the host)

## Bring up the stack

```bash
cd data-plane

# 1. One-time: prepare env file and the FIM monitored dir.
cp .env.dataplane.example .env.dataplane
mkdir -p monitored

# 2. Build the normalizer image.
docker build -f normalizers/Dockerfile -t intellifim-normalizer:dev .

# 3. Start everything.
docker compose --env-file .env.dataplane up -d

# 4. Create Kafka topics (idempotent — safe to re-run).
./scripts/create-topics.sh
```

Wait ~90 seconds for Wazuh agent enrollment and Zeek to start writing logs.

## See events flow

### Browser

Open [http://localhost:8080](http://localhost:8080) for `kafka-ui`.
Topics -> `events.normalized` -> Messages.

### Terminal

```bash
# Install the schema package once (from repo root)
pip install -e schemas
pip install aiokafka

# Tail canonical events (Ctrl-C to stop)
python scripts/tail-normalized.py --bootstrap localhost:9094
```

## Generate test traffic

```bash
# Deterministic burst (FIM + a few HTTP GETs)
./scripts/seed-test-traffic.sh

# Replay a curated pcap
./scripts/replay-pcap.sh pcaps/http_get_basic.pcap
```

A FIM event also fires whenever you write to `monitored/`:

```bash
echo "hello" > monitored/anything.txt
```

## See correlations

The correlation engine joins file and network events from the same host
within ±60 s and publishes matches on `events.correlated`. Tail it:

```bash
python scripts/tail-correlated.py --bootstrap localhost:9094
```

Trigger a guaranteed correlation by running `seed-test-traffic.sh` (which
emits both FIM and network events for the same host) — at least one
`CorrelatedEvent` should print within ~30 s.

## Consume canonical events from a downstream service

The canonical schema lives in the `intellifim-schemas` package. Any
sub-project that consumes events should depend on it directly:

```toml
# pyproject.toml
[project]
dependencies = [
    "intellifim-schemas>=0.2,<1.0",
    "aiokafka>=0.10",
]
```

Then:

```python
from aiokafka import AIOKafkaConsumer
from intellifim_schemas import CanonicalEvent

consumer = AIOKafkaConsumer(
    "events.normalized",
    bootstrap_servers="kafka:9092",   # or "localhost:9094" from host
    group_id="my-downstream-service",
)
await consumer.start()
async for msg in consumer:
    event = CanonicalEvent.model_validate_json(msg.value)
    ...
```

## Adding a new pcap

See [pcaps/README.md](pcaps/README.md).

## Tear down

```bash
docker compose --env-file .env.dataplane down       # keep volumes
docker compose --env-file .env.dataplane down -v    # also wipe Kafka data, Wazuh state
```

## Running the unit tests

```bash
pip install -e schemas[dev]
pip install -e normalizers[dev]
pip install -e correlator[dev]

# Each package declares its own `tests/` package, which means a single
# combined `pytest` call collides on conftest registration. Run them
# in two passes (each with `--import-mode=importlib`):
pytest --import-mode=importlib schemas/tests normalizers/tests -v
pytest --import-mode=importlib correlator/tests -v
```

## Definition of done (v1)

This sub-project is "done" when all of the following pass on a fresh
checkout:

1. `docker compose up` after the steps above brings the stack up cleanly.
2. Touching a file in `monitored/` produces a `file.modified` /
   `file.created` canonical event on `events.normalized` within 5 s.
3. `victim-client`'s background curl loop produces ongoing
   `network.flow` / `network.http_request` events on
   `events.normalized`.
4. `scripts/replay-pcap.sh pcaps/http_get_basic.pcap` produces the
   expected zeek.* events.
5. Both `pytest --import-mode=importlib schemas/tests normalizers/tests`
   AND `pytest --import-mode=importlib correlator/tests` are green
   (see "Running the unit tests" above for why the two-pass form is needed).
6. `python scripts/tail-correlated.py` prints at least one correlation
   after running `./scripts/seed-test-traffic.sh`.
