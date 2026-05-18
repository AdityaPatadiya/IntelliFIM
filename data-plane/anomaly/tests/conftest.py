from datetime import datetime, timezone
from uuid import uuid4

import pytest

from intellifim_schemas import CanonicalEvent


@pytest.fixture
def make_event():
    """Factory for CanonicalEvent instances. Defaults to a wazuh.fim file.modified
    event at 2026-05-17T12:00:00Z for host-001. Override any field via kwargs."""

    def _make(
        *,
        event_type: str = "file.modified",
        source: str = "wazuh.fim",
        host_id: str = "host-001",
        timestamp: datetime | None = None,
        **extra,
    ) -> CanonicalEvent:
        if timestamp is None:
            timestamp = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
        return CanonicalEvent(
            event_id=uuid4(),
            event_type=event_type,
            source=source,
            timestamp=timestamp,
            ingest_timestamp=datetime.now(tz=timezone.utc),
            host_id=host_id,
            **extra,
        )

    return _make
