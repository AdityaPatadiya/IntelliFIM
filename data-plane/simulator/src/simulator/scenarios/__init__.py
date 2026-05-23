"""Scenario registry — kebab-case CLI name → module."""
from __future__ import annotations

from types import ModuleType

from simulator.scenarios import (
    data_exfil,
    dns_tunnel,
    port_scan,
    ransomware_rapid,
    webshell_drop,
)


SCENARIOS: dict[str, ModuleType] = {
    data_exfil.NAME: data_exfil,
    webshell_drop.NAME: webshell_drop,
    port_scan.NAME: port_scan,
    dns_tunnel.NAME: dns_tunnel,
    ransomware_rapid.NAME: ransomware_rapid,
}
