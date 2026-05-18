"""Pure stateless feature extractor.

Used identically by `train.py` and the inference engine. The set of keys
returned by `extract()` is the contract: drift between train and inference
is caught at engine startup via the drift guard in engine.py.
"""
from __future__ import annotations

from datetime import timezone
from math import log1p
from typing import get_args

from intellifim_schemas import CanonicalEvent, EventType, Source

_EVENT_TYPES: tuple[str, ...] = get_args(EventType)
_SOURCES: tuple[str, ...] = get_args(Source)


def _key(prefix: str, value: str) -> str:
    """`'event_type', 'file.modified'` -> `'event_type__file_modified'`."""
    return f"{prefix}__{value.replace('.', '_')}"


def extract(event: CanonicalEvent) -> dict[str, float]:
    # Normalize to UTC so hour/day are comparable across hosts even if a future
    # ingestor ever ships a non-UTC AwareDatetime. Today every normalizer
    # emits UTC, but the feature definition shouldn't silently depend on that.
    ts = event.timestamp.astimezone(timezone.utc)
    features: dict[str, float] = {
        "hour_of_day": float(ts.hour),
        "day_of_week": float(ts.weekday()),
        "log_file_size": log1p(event.file_size_bytes or 0),
        "src_port": float(event.src_port or 0),
        "dst_port": float(event.dst_port or 0),
    }
    for et in _EVENT_TYPES:
        features[_key("event_type", et)] = 1.0 if event.event_type == et else 0.0
    for src in _SOURCES:
        features[_key("source", src)] = 1.0 if event.source == src else 0.0
    return features
