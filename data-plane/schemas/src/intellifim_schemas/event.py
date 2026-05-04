from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

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


class CanonicalEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # identity
    event_id: UUID
    event_type: EventType
    source: Source
    schema_version: str = "1.0.0"

    # time
    timestamp: datetime
    ingest_timestamp: datetime

    # host
    host_id: str
    host_name: str | None = None

    # actor
    user: str | None = None
    user_uid: int | None = None
    process_name: str | None = None
    process_pid: int | None = None

    # file subject
    file_path: str | None = None
    file_hash_sha256: str | None = None
    file_size_bytes: int | None = None

    # network subject
    src_ip: IPv4Address | IPv6Address | None = None
    src_port: int | None = None
    dst_ip: IPv4Address | IPv6Address | None = None
    dst_port: int | None = None
    protocol: str | None = None

    # passthrough
    raw: dict = Field(default_factory=dict)
