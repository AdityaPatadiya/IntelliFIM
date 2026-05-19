"""Three-tier classifier for ThreatScoreUpdate.score."""
from __future__ import annotations

from enum import Enum


class Tier(str, Enum):
    IGNORE = "IGNORE"
    LOW_URGENCY = "LOW_URGENCY"
    HIGH_URGENCY = "HIGH_URGENCY"


def classify(score: float, *, low: float, high: float) -> Tier:
    if score < low:
        return Tier.IGNORE
    if score < high:
        return Tier.LOW_URGENCY
    return Tier.HIGH_URGENCY
