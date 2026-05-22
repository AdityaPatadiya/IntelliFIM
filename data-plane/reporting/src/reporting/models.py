"""Internal Pydantic models for the reporting service.

Kept OUT of `intellifim-schemas` because these types are not on any Kafka
topic — they're only on the HTTP wire to/from this service. Bumping
intellifim-schemas would force every other consumer to rev, for no benefit.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Literal
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    NonNegativeInt,
    model_validator,
)

Role = Literal["admin", "analyst", "viewer"]


@dataclass(frozen=True)
class Principal:
    """JWT subject extracted by the auth middleware.

    Field shape matches data-plane/orchestrator/src/orchestrator/auth.py
    so a single JWT contract holds across the two backend services.
    """
    user_id: UUID
    username: str
    role: Role


class GenerateReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    range_start: AwareDatetime
    range_end: AwareDatetime

    @model_validator(mode="after")
    def _validate_range(self) -> "GenerateReportRequest":
        if self.range_end <= self.range_start:
            raise ValueError("range_end must be strictly after range_start")
        if self.range_end - self.range_start > timedelta(days=90):
            raise ValueError("range may not exceed 90 days")
        return self


class ReportMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: UUID
    name: str
    range_start: AwareDatetime
    range_end: AwareDatetime
    generated_at: AwareDatetime
    generated_by: str
    size_bytes: NonNegativeInt
    approvals_count: NonNegativeInt
    scores_count: NonNegativeInt


class ReportListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reports: list[ReportMetadata]
    total: NonNegativeInt
