# intellifim-policy

Policy + dynamic threat scoring service. Consumes `events.scored`, queries
an OPA sidecar for a per-event `score_delta`, maintains a per-host
sliding-window threat score in Redis, and publishes `ThreatScoreUpdate`
to `threat.scores`.

Install for development:

    pip install -e data-plane/schemas
    pip install -e data-plane/policy[dev]

Run Python tests:

    pytest --import-mode=importlib data-plane/policy/tests

Run Rego policy tests (requires `opa` CLI or Docker):

    opa test data-plane/policy/policies/
    # OR
    docker run --rm -v $(pwd)/data-plane/policy/policies:/p \
        openpolicyagent/opa:latest test /p
