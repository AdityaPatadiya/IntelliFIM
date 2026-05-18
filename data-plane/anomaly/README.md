# intellifim-anomaly

Per-event anomaly detection service. Consumes `events.normalized`, scores
each `CanonicalEvent` with a pre-trained scikit-learn `IsolationForest`,
and publishes a `ScoredEvent` to `events.scored`.

The trained model is baked into the Docker image at build time from the
bundled corpus at `training-data/baseline-events.jsonl`. Retrain by
recapturing that file (`scripts/capture-baseline.py`) and rebuilding the
image.

Install for development:

    pip install -e data-plane/schemas
    pip install -e data-plane/anomaly[dev]

Run tests (uses `--import-mode=importlib` so the suite can coexist with
the schemas / normalizers / correlator suites in CI):

    pytest --import-mode=importlib data-plane/anomaly/tests
