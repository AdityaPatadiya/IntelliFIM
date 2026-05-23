"""Per-service Prometheus metrics for response-orchestrator.

3 lean RED-method counters/histograms, uniform across all 6 in-house services.
"""
from __future__ import annotations

from prometheus_client import Counter, Histogram


SERVICE_LABEL = "response-orchestrator"

messages_processed_total = Counter(
    "intellifim_messages_processed_total",
    "Number of input messages processed by the service",
    ["service"],
)

errors_total = Counter(
    "intellifim_errors_total",
    "Number of errors encountered by the service",
    ["service", "kind"],
)

processing_seconds = Histogram(
    "intellifim_processing_seconds",
    "End-to-end processing latency per input message",
    ["service"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)
