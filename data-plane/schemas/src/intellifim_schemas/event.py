"""Canonical event schema for IntelliFIM.

This is the contract every downstream sub-project (correlation engine, ML
inference, scoring, dashboard, response orchestrator) imports. Type
constraints are deliberately strict: invalid values must be rejected at
the schema boundary rather than propagated downstream.
"""
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    NonNegativeInt,
    PositiveInt,
)

EventType = Literal[
    "file.modified",
    "file.created",
    "file.deleted",
    "file.read",
    "auth.login_success",
    "auth.login_failed",
    "auth.logout",
    "auth.sudo",
    "network.flow",
    "network.dns_query",
    "network.http_request",
    "network.file_transfer",
]

Source = Literal[
    "wazuh.fim",
    "wazuh.auth",
    "zeek.conn",
    "zeek.dns",
    "zeek.http",
    "zeek.files",
]

Port = Annotated[int, Field(ge=1, le=65535)]
Sha256Hex = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class CanonicalEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # identity
    event_id: UUID
    event_type: EventType
    source: Source
    schema_version: str = "1.0.0"

    # time (timezone-aware UTC required so cross-host correlation is unambiguous)
    timestamp: AwareDatetime
    ingest_timestamp: AwareDatetime

    # host
    host_id: str
    host_name: str | None = None

    # actor
    user: str | None = None
    user_uid: NonNegativeInt | None = None       # uid 0 = root
    process_name: str | None = None
    process_pid: PositiveInt | None = None       # pid 0 is the kernel scheduler

    # file subject
    file_path: str | None = None
    file_hash_sha256: Sha256Hex | None = None
    file_size_bytes: NonNegativeInt | None = None  # 0 = empty file is valid

    # network subject
    src_ip: IPv4Address | IPv6Address | None = None
    src_port: Port | None = None
    dst_ip: IPv4Address | IPv6Address | None = None
    dst_port: Port | None = None
    protocol: str | None = None

    # passthrough — the unmodified source event, kept for debugging and XAI
    raw: dict[str, Any] = Field(default_factory=dict)
