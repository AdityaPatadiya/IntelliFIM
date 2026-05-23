"""Runner + CLI tests — dispatch, --list, --help, unknown-name handling."""
from __future__ import annotations

import sys

import pytest

from simulator.__main__ import main
from simulator.runner import dispatch


def test_dispatch_returns_module_for_known_name():
    mod = dispatch("data-exfil")
    assert mod.NAME == "data-exfil"


def test_dispatch_raises_on_unknown_name():
    with pytest.raises(KeyError):
        dispatch("nonsense-scenario")


def test_cli_list_prints_all_five(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--list"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for name in ("data-exfil", "webshell-drop", "port-scan", "dns-tunnel", "ransomware-rapid"):
        assert name in out
