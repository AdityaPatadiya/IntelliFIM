import json
import os
import subprocess
from pathlib import Path


_SCRIPT = Path(__file__).resolve().parent.parent / "wazuh-ar" / "quarantine.sh"


def test_quarantine_sh_creates_marker_file(tmp_path):
    fixture = json.dumps({
        "version": 1,
        "origin": {"name": "node-1", "module": "wazuh-execd"},
        "command": "add",
        "parameters": {
            "extra_args": ["update_id", "test-abc-123"],
            "alert": {},
            "program": "quarantine0",
        },
    })
    # The script extracts update_id from any "update_id":"VALUE" pattern in
    # the JSON. Inject a top-level field for the v1 walking-skeleton.
    fixture_with_id = fixture.replace(
        '"parameters":',
        '"update_id":"test-abc-123","parameters":',
    )
    result = subprocess.run(
        ["bash", str(_SCRIPT)],
        input=fixture_with_id,
        capture_output=True,
        text=True,
        env={**os.environ, "MARKER_DIR_OVERRIDE": str(tmp_path), "LOG_FILE_OVERRIDE": str(tmp_path / "ar.log")},
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    marker = tmp_path / "intellifim-quarantine-test-abc-123.flag"
    assert marker.exists()


def test_quarantine_sh_stdout_is_valid_json(tmp_path):
    result = subprocess.run(
        ["bash", str(_SCRIPT)],
        input='{"update_id":"x"}',
        capture_output=True,
        text=True,
        env={**os.environ, "MARKER_DIR_OVERRIDE": str(tmp_path), "LOG_FILE_OVERRIDE": str(tmp_path / "ar.log")},
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    parsed = json.loads(result.stdout)
    assert parsed["origin"]["name"] == "quarantine"
