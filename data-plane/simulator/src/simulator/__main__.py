"""CLI entry point for the simulator.

Console-script entry `intellifim-simulator` (declared in pyproject.toml)
invokes `main()` which calls `sys.exit(...)` with the runner's exit code.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys

from simulator.runner import run_and_verify
from simulator.scenarios import SCENARIOS


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="simulator",
        description="Fire an attack scenario at victim-server and verify it produces a threat score.",
    )
    p.add_argument("scenario", nargs="?", help=f"one of: {', '.join(sorted(SCENARIOS))}")
    p.add_argument("--list", action="store_true", help="list available scenarios and exit")
    p.add_argument(
        "--threshold", type=float, default=float(os.environ.get("THRESHOLD_SCORE", "30.0")),
        help="minimum score to count as detection (default: 30.0)",
    )
    p.add_argument(
        "--timeout", type=float, default=float(os.environ.get("TIMEOUT_SECONDS", "60")),
        help="seconds to wait for a threat.scores message (default: 60)",
    )
    return p


def _print_list() -> None:
    print("available scenarios:")
    for name in sorted(SCENARIOS):
        module = SCENARIOS[name]
        print(f"  {name:<20s} {module.DESCRIPTION}")


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
    )
    args = _build_parser().parse_args(argv)

    if args.list:
        _print_list()
        raise SystemExit(0)

    if not args.scenario:
        print("error: scenario name required (or use --list)", file=sys.stderr)
        raise SystemExit(1)

    code = asyncio.run(run_and_verify(
        name=args.scenario,
        target_host=os.environ.get("TARGET_HOST", "victim-server"),
        bootstrap=os.environ.get("KAFKA_BOOTSTRAP", "kafka:9092"),
        topic=os.environ.get("TOPIC", "threat.scores"),
        host_id=os.environ.get("HOST_ID", "001"),
        threshold=args.threshold,
        timeout_seconds=args.timeout,
    ))
    raise SystemExit(code)


if __name__ == "__main__":
    main()
