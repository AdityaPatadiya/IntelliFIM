"""Scenario tests — verify each module exports the contract + run() does the right things.

Tests mock subprocess and use tmp_path as the /victim-data mount.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


# ---------- shared helpers ----------

@pytest.fixture
def victim_data(tmp_path, monkeypatch):
    """Patch the scenarios' /victim-data constant to a tmp dir."""
    d = tmp_path / "victim-data"
    d.mkdir()
    monkeypatch.setattr("simulator.scenarios.data_exfil.VICTIM_DATA", str(d))
    monkeypatch.setattr("simulator.scenarios.webshell_drop.VICTIM_DATA", str(d))
    monkeypatch.setattr("simulator.scenarios.ransomware_rapid.VICTIM_DATA", str(d))
    return d


@pytest.fixture
def captured_subprocess(monkeypatch):
    """Capture subprocess.run calls without actually executing them."""
    calls = []

    def fake_run(cmd, *args, **kwargs):
        calls.append({"cmd": cmd, "kwargs": kwargs})
        # Return a CompletedProcess-shaped object
        class _R:
            returncode = 0
            stdout = b""
            stderr = b""
        return _R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


# ---------- contract checks ----------

@pytest.mark.parametrize("name", [
    "data-exfil", "webshell-drop", "port-scan", "dns-tunnel", "ransomware-rapid",
])
def test_scenario_exports_contract(name):
    from simulator.scenarios import SCENARIOS
    module = SCENARIOS[name]
    assert isinstance(module.NAME, str) and module.NAME == name
    assert isinstance(module.DESCRIPTION, str) and len(module.DESCRIPTION) > 0
    assert callable(module.run)


# ---------- per-scenario behavior tests ----------

def test_data_exfil_writes_file_and_runs_curl_dig(victim_data, captured_subprocess):
    from simulator.scenarios import data_exfil
    data_exfil.run(target_host="test-victim")

    # Wrote a sensitive-looking CSV
    files = list(victim_data.iterdir())
    assert any(f.name.startswith("sensitive_") and f.suffix == ".csv" for f in files), files
    assert any(f.stat().st_size >= 1024 for f in files)

    # Called curl POST to test-victim
    curls = [c for c in captured_subprocess if c["cmd"][0] == "curl"]
    assert any(
        "POST" in c["cmd"] and "http://test-victim/upload" in c["cmd"]
        for c in curls
    ), curls

    # Called dig with .invalid domain pointed at test-victim
    digs = [c for c in captured_subprocess if c["cmd"][0] == "dig"]
    assert any(
        "@test-victim" in c["cmd"] and any(".invalid" in arg for arg in c["cmd"])
        for c in digs
    ), digs


def test_webshell_drop_writes_php_and_curls_with_query(victim_data, captured_subprocess):
    from simulator.scenarios import webshell_drop
    webshell_drop.run(target_host="test-victim")

    php_files = [f for f in victim_data.iterdir() if f.suffix == ".php"]
    assert php_files
    body = php_files[0].read_text()
    assert "<?php" in body

    curls = [c for c in captured_subprocess if c["cmd"][0] == "curl"]
    assert any(
        any("http://test-victim/" in arg and ".php?" in arg for arg in c["cmd"])
        for c in curls
    ), curls


def test_port_scan_attempts_many_ports(monkeypatch):
    """port_scan uses asyncio.open_connection — assert it's called many times."""
    from simulator.scenarios import port_scan
    attempts = []

    async def fake_open(host, port, *args, **kwargs):
        attempts.append((host, port))
        raise ConnectionRefusedError()   # most ports closed; expected

    monkeypatch.setattr("simulator.scenarios.port_scan.asyncio.open_connection", fake_open)

    port_scan.run(target_host="test-victim")

    # All attempts should hit the target host
    assert all(host == "test-victim" for host, _ in attempts)
    # Should have tried at least 500 distinct ports (the actual sweep is 1..1024)
    distinct_ports = {p for _, p in attempts}
    assert len(distinct_ports) >= 500


def test_dns_tunnel_issues_many_dig_calls(captured_subprocess):
    from simulator.scenarios import dns_tunnel
    dns_tunnel.run(target_host="test-victim")

    digs = [c for c in captured_subprocess if c["cmd"][0] == "dig"]
    assert len(digs) >= 50
    # Each dig must have a unique label under exfil.tunnel.invalid
    queried = set()
    for c in digs:
        # last positional before flags is the domain (or with @host between)
        for arg in c["cmd"]:
            if arg.endswith(".exfil.tunnel.invalid"):
                queried.add(arg)
    assert len(queried) >= 50


def test_ransomware_rapid_churns_files(victim_data):
    from simulator.scenarios import ransomware_rapid
    ransomware_rapid.run(target_host="test-victim")

    # After the churn, no doc_*.txt should remain (all deleted at the end)
    remaining_docs = [f for f in victim_data.iterdir() if f.name.startswith("doc_")]
    assert remaining_docs == []
