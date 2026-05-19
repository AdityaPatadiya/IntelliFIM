from datetime import datetime, timezone
from uuid import uuid4

import pytest

from intellifim_schemas import CanonicalEvent, ScoredEvent


@pytest.fixture
def make_scored_event():
    """Factory for ScoredEvent instances with embedded CanonicalEvent. Defaults to a
    wazuh.fim file.modified event scored at 0.6 (moderate anomaly), host-001."""

    def _make(
        *,
        host_id: str = "host-001",
        anomaly_score: float = 0.6,
        is_anomaly: bool | None = None,
        event_type: str = "file.modified",
        source: str = "wazuh.fim",
        threshold: float = 0.5,
    ) -> ScoredEvent:
        if is_anomaly is None:
            is_anomaly = anomaly_score >= threshold
        canonical = CanonicalEvent(
            event_id=uuid4(),
            event_type=event_type,
            source=source,
            timestamp=datetime(2026, 5, 18, 12, 0, 0, tzinfo=timezone.utc),
            ingest_timestamp=datetime.now(tz=timezone.utc),
            host_id=host_id,
        )
        return ScoredEvent(
            score_id=uuid4(),
            scored_at=datetime.now(tz=timezone.utc),
            model_version="isolation-forest-v1",
            anomaly_score=anomaly_score,
            is_anomaly=is_anomaly,
            threshold=threshold,
            host_id=host_id,
            source_event=canonical,
            features={"hour_of_day": 12.0, "src_port": 0.0},
        )

    return _make
