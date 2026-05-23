"""Prometheus metrics tests for policy-engine.

Asserts the wiring around PolicyEngine.process_one:
- happy-path call bumps intellifim_messages_processed_total{service="policy-engine"}
- a call that raises bumps intellifim_errors_total{service="policy-engine", kind="<ExcType>"}
  and re-raises so the outer loop can log it
"""
from __future__ import annotations

import pytest
from prometheus_client import REGISTRY

from policy.engine import PolicyEngine
from policy.metrics import SERVICE_LABEL

from tests.test_engine import FakeConsumer, FakeOpa, FakeProducer, _make_store, _now_at


def _counter_value(name: str, **labels: str) -> float:
    """Read the current sample value for a labeled counter, returning 0.0 if absent.

    The 0.0 fallback matters because the very first test run in a fresh process
    has no sample yet — prometheus-client only materializes a series on first inc().
    """
    val = REGISTRY.get_sample_value(name, labels)
    return val if val is not None else 0.0


async def test_process_one_increments_messages_processed_counter(make_scored_event):
    """Happy-path process_one bumps messages_processed_total{service=policy-engine} by 1."""
    event = make_scored_event(anomaly_score=0.85)
    consumer = FakeConsumer([])
    producer = FakeProducer()
    store = await _make_store()
    opa = FakeOpa({"score_delta": 25, "reason": "strong anomaly"})
    try:
        engine = PolicyEngine(
            consumer=consumer, producer=producer, output_topic="threat.scores",
            opa=opa, store=store, window_seconds=300, now=_now_at(0),
        )

        before = _counter_value(
            "intellifim_messages_processed_total", service=SERVICE_LABEL
        )
        await engine.process_one(event)
        after = _counter_value(
            "intellifim_messages_processed_total", service=SERVICE_LABEL
        )
        assert after - before == 1.0
    finally:
        await store.aclose()


async def test_process_one_increments_errors_on_raise(make_scored_event, monkeypatch):
    """A process_one call that raises bumps errors_total{kind=ValueError} by 1
    and re-raises (so the outer run-loop can log it)."""
    event = make_scored_event(anomaly_score=0.85)
    consumer = FakeConsumer([])
    producer = FakeProducer()
    store = await _make_store()
    try:
        # OPA client raising ValueError mid-process_one is a realistic failure mode
        # (e.g. malformed bundle response). The metrics wrap must increment
        # errors_total{kind=ValueError} and re-raise.
        async def _raise_query(_event):
            raise ValueError("test")

        opa = FakeOpa({"score_delta": 5, "reason": "weak"})
        monkeypatch.setattr(opa, "query", _raise_query)

        engine = PolicyEngine(
            consumer=consumer, producer=producer, output_topic="threat.scores",
            opa=opa, store=store, window_seconds=300, now=_now_at(0),
        )

        before = _counter_value(
            "intellifim_errors_total", service=SERVICE_LABEL, kind="ValueError"
        )
        with pytest.raises(ValueError):
            await engine.process_one(event)
        after = _counter_value(
            "intellifim_errors_total", service=SERVICE_LABEL, kind="ValueError"
        )
        assert after - before == 1.0
    finally:
        await store.aclose()
