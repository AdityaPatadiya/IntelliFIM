# intellifim-orchestrator

Response orchestrator + admin approval workflow. Consumes `threat.scores`,
classifies into 3 tiers (IGNORE / LOW_URGENCY / HIGH_URGENCY), persists upper-
tier events as approval requests in SQLite, exposes an aiohttp REST API at
port 8200, and on approval dispatches the `quarantine.sh` Wazuh Active Response
script to the target agent.

Install for development:

    pip install -e data-plane/schemas
    pip install -e data-plane/orchestrator[dev]

Run Python tests:

    pytest --import-mode=importlib data-plane/orchestrator/tests

Run shell-script test for `quarantine.sh`:

    pytest --import-mode=importlib data-plane/orchestrator/tests/test_quarantine_sh.py
