# intellifim-correlator

Per-host time-window correlation engine. Consumes `events.normalized` and
publishes `CorrelatedEvent` instances on `events.correlated` whenever a
file event has at least one co-occurring network event from the same host
within the configured window (default 60 s), or vice versa.

Install for development:

    pip install -e data-plane/schemas
    pip install -e data-plane/correlator[dev]

Run tests:

    pytest --import-mode=importlib data-plane/correlator/tests
