"""ransomware-rapid scenario — FIM rapid create/truncate/delete churn."""
from __future__ import annotations

import os


NAME = "ransomware-rapid"
DESCRIPTION = "Rapidly create, truncate, and delete 30 files in /victim-data"

VICTIM_DATA = "/victim-data"
FILE_COUNT = 30
CONTENT = b"A" * 1024   # 1 KB


def run(target_host: str) -> None:
    os.makedirs(VICTIM_DATA, exist_ok=True)
    for i in range(FILE_COUNT):
        path = os.path.join(VICTIM_DATA, f"doc_{i}.txt")
        with open(path, "wb") as f:
            f.write(CONTENT)
        # Truncate to 0
        with open(path, "wb") as f:
            f.write(b"")
        os.unlink(path)
