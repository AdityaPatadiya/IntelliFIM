"""Train an IsolationForest on a bundled JSONL corpus of CanonicalEvents.

Runs both as a CLI (`python -m anomaly.train --input ... --output ...`) and
as a Docker build step. The output pickle is a dict bundling the fitted
model, the sorted feature_names (for stable column order), and the
model_version string.
"""
from __future__ import annotations

import argparse
import pickle
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

from intellifim_schemas import CanonicalEvent

from anomaly.features import extract

MODEL_VERSION = "isolation-forest-v1"


def train(events: list[CanonicalEvent]) -> dict[str, Any]:
    if not events:
        raise ValueError("cannot train on an empty event list")
    feature_rows = [extract(e) for e in events]
    feature_names = sorted(feature_rows[0].keys())
    X = np.array([[row[k] for k in feature_names] for row in feature_rows])
    model = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=42,
    )
    model.fit(X)
    return {
        "model": model,
        "feature_names": feature_names,
        "model_version": MODEL_VERSION,
    }


def _read_jsonl(path: Path) -> list[CanonicalEvent]:
    events: list[CanonicalEvent] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        events.append(CanonicalEvent.model_validate_json(line))
    return events


def main() -> None:
    parser = argparse.ArgumentParser(description="Train IsolationForest from JSONL corpus")
    parser.add_argument("--input", type=Path, required=True, help="JSONL of CanonicalEvents")
    parser.add_argument("--output", type=Path, required=True, help="Pickle output path")
    args = parser.parse_args()

    events = _read_jsonl(args.input)
    bundle = train(events)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "wb") as f:
        pickle.dump(bundle, f)
    print(f"trained {bundle['model_version']} on {len(events)} events; "
          f"wrote {args.output}")


if __name__ == "__main__":
    main()
