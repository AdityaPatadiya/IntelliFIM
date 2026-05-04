"""Correlation schema for IntelliFIM.

Emitted by the correlation engine onto the `events.correlated` Kafka topic.
Type constraints mirror CanonicalEvent's strictness: invalid values rejected
at the schema boundary.
"""
from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    PositiveInt,
)

from intellifim_schemas.event import CanonicalEvent

CorrelationType = Literal["file_with_network"]
# v2 will add: "rule_match", "behavioral_anomaly", "cross_host"


class CorrelatedEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    correlation_id: UUID
    correlation_type: CorrelationType
    correlated_at: AwareDatetime
    window_seconds: PositiveInt

    host_id: str
    triggering_event: CanonicalEvent
    co_occurring_events: list[CanonicalEvent] = Field(min_length=1)
