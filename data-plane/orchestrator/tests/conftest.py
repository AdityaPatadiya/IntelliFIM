# data-plane/orchestrator/tests/conftest.py
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from intellifim_schemas import ThreatScoreUpdate


@pytest.fixture
def make_threat_score_update():
    """Factory for ThreatScoreUpdate instances. Defaults to host-001, score=60,
    priority=low (per default thresholds 30/70)."""

    def _make(
        *,
        host_id: str = "001",
        score: float = 60.0,
        last_score_delta: int = 10,
        last_reason: str = "moderate anomaly",
        window_seconds: int = 300,
        contributions_in_window: int = 1,
    ) -> ThreatScoreUpdate:
        return ThreatScoreUpdate(
            update_id=uuid4(),
            computed_at=datetime.now(tz=timezone.utc),
            host_id=host_id,
            score=score,
            window_seconds=window_seconds,
            contributions_in_window=contributions_in_window,
            last_event_id=uuid4(),
            last_score_delta=last_score_delta,
            last_reason=last_reason,
        )

    return _make
