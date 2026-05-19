"""Policy / scoring schema for IntelliFIM.

Emitted by the policy-engine service onto the `threat.scores` Kafka topic.
Each ThreatScoreUpdate carries the per-host sliding-window threat score
plus enough context (last triggering event, last OPA decision) for
downstream consumers (response orchestrator, dashboard) to act without
joining other topics.
"""
from __future__ import annotations

from typing import Annotated
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    NonNegativeInt,
    PositiveInt,
)


class ThreatScoreUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    update_id: UUID
    computed_at: AwareDatetime
    host_id: str

    score: Annotated[float, Field(ge=0.0, le=100.0)]
    window_seconds: PositiveInt
    contributions_in_window: NonNegativeInt

    last_event_id: UUID
    last_score_delta: Annotated[int, Field(ge=0, le=100)]
    last_reason: str
