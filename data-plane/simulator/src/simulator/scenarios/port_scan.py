"""port-scan scenario — zeek.conn flurry via pure asyncio (no nmap)."""
from __future__ import annotations

import asyncio


NAME = "port-scan"
DESCRIPTION = "Burst TCP-connect sweep against victim-server ports 1..1024"

PORTS_TO_SCAN = range(1, 1025)
BATCH_SIZE = 32
CONNECT_TIMEOUT = 0.5


async def _probe(target_host: str, port: int) -> None:
    """Open + immediately close a TCP connection. Tolerates refusal/timeout."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target_host, port),
            timeout=CONNECT_TIMEOUT,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    except (OSError, asyncio.TimeoutError, ConnectionRefusedError):
        pass


async def _scan(target_host: str) -> None:
    ports = list(PORTS_TO_SCAN)
    for batch_start in range(0, len(ports), BATCH_SIZE):
        batch = ports[batch_start:batch_start + BATCH_SIZE]
        await asyncio.gather(*(_probe(target_host, p) for p in batch))


def run(target_host: str) -> None:
    asyncio.run(_scan(target_host))
