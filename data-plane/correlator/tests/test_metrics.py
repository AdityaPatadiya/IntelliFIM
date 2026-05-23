"""Prometheus metrics tests for correlation-engine.

Asserts the wiring around CorrelationEngine.process_one:
- happy-path call bumps intellifim_messages_processed_total{service="correlation-engine"}
- a call that raises bumps intellifim_errors_total{service="correlation-engine", kind="<ExcType>"}
  and re-raises so the outer loop can log it
"""
from __future__ import annotations

import pytest
from prometheus_client import REGISTRY

from correlator.buffer import HostBuffer
from correlator.engine import CorrelationEngine
from correlator.metrics import SERVICE_LABEL

from tests.test_engine import FakeConsumer, FakeProducer, _now_at


def _counter_value(name: str, **labels: str) -> float:
    """Read the current sample value for a labeled counter, returning 0.0 if absent.

    The 0.0 fallback matters because the very first test run in a fresh process
    has no sample yet — prometheus-client only materializes a series on first inc().
    """
    val = REGISTRY.get_sample_value(name, labels)
    return val if val is not None else 0.0


async def test_process_one_increments_messages_processed_counter(make_event):
    """Happy-path process_one bumps messages_processed_total{service=correlation-engine} by 1."""
    event = make_event(event_type="file.modified", source="wazuh.fim")
    consumer = FakeConsumer([])
    producer = FakeProducer()
    buffer = HostBuffer(window_seconds=60, now=_now_at(0))
    engine = CorrelationEngine(
        consumer=consumer, producer=producer,
        output_topic="events.correlated",
        buffer=buffer, window_seconds=60,
        now=_now_at(0),
    )

    before = _counter_value(
        "intellifim_messages_processed_total", service=SERVICE_LABEL
    )
    await engine.process_one(event)
    after = _counter_value(
        "intellifim_messages_processed_total", service=SERVICE_LABEL
    )
    assert after - before == 1.0


async def test_process_one_increments_errors_on_raise(make_event, monkeypatch):
    """A process_one call that raises bumps errors_total{kind=ValueError} by 1
    and re-raises (so the outer run-loop can log it)."""
    event = make_event(event_type="file.modified", source="wazuh.fim")
    consumer = FakeConsumer([])
    producer = FakeProducer()
    buffer = HostBuffer(window_seconds=60, now=_now_at(0))
    engine = CorrelationEngine(
        consumer=consumer, producer=producer,
        output_topic="events.correlated",
        buffer=buffer, window_seconds=60,
        now=_now_at(0),
    )

    # Force the per-message buffer.add to raise ValueError — the FIRST collaborator
    # call inside process_one after the (successful) extract. The metrics wrap must
    # increment errors_total{kind=ValueError} and re-raise.
    def _raise(*args, **kwargs):
        raise ValueError("test")

    monkeypatch.setattr(engine._buffer, "add", _raise)

    before = _counter_value(
        "intellifim_errors_total", service=SERVICE_LABEL, kind="ValueError"
    )
    with pytest.raises(ValueError):
        await engine.process_one(event)
    after = _counter_value(
        "intellifim_errors_total", service=SERVICE_LABEL, kind="ValueError"
    )
    assert after - before == 1.0
