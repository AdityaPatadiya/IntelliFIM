"""Scoring schema for IntelliFIM.

Emitted by the anomaly-detector service onto the `events.scored` Kafka topic.
The `features` dict carries the exact numeric vector that fed the model so
v2's SHAP integration can compute attributions without a schema change.
"""
from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
)

from intellifim_schemas.event import CanonicalEvent

ModelVersion = Literal["isolation-forest-v1"]
# v2 will widen to include "lstm-v1", "isolation-forest-v2", etc.


class ScoredEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    score_id: UUID
    scored_at: AwareDatetime
    model_version: ModelVersion
    anomaly_score: Annotated[float, Field(ge=0.0, le=1.0)]
    is_anomaly: bool
    threshold: Annotated[float, Field(ge=0.0, le=1.0)]

    host_id: str
    source_event: CanonicalEvent
    features: dict[str, float]
