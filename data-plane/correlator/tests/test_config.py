import pytest

from correlator.config import (
    INPUT_TOPIC,
    OUTPUT_TOPIC,
    CorrelatorConfig,
)


def test_input_topic_constant():
    assert INPUT_TOPIC == "events.normalized"


def test_output_topic_constant():
    assert OUTPUT_TOPIC == "events.correlated"


def test_from_env_with_defaults(monkeypatch):
    monkeypatch.delenv("KAFKA_BOOTSTRAP", raising=False)
    monkeypatch.delenv("CORRELATION_WINDOW_SECONDS", raising=False)
    monkeypatch.delenv("CONSUMER_GROUP", raising=False)
    cfg = CorrelatorConfig.from_env()
    assert cfg.bootstrap_servers == "kafka:9092"
    assert cfg.window_seconds == 60
    assert cfg.consumer_group == "correlation-engine"
    assert cfg.input_topic == "events.normalized"
    assert cfg.output_topic == "events.correlated"


def test_from_env_overrides(monkeypatch):
    monkeypatch.setenv("KAFKA_BOOTSTRAP", "kafka.example.com:19092")
    monkeypatch.setenv("CORRELATION_WINDOW_SECONDS", "120")
    monkeypatch.setenv("CONSUMER_GROUP", "correlator-staging")
    cfg = CorrelatorConfig.from_env()
    assert cfg.bootstrap_servers == "kafka.example.com:19092"
    assert cfg.window_seconds == 120
    assert cfg.consumer_group == "correlator-staging"


def test_from_env_rejects_invalid_window(monkeypatch):
    monkeypatch.setenv("CORRELATION_WINDOW_SECONDS", "0")
    with pytest.raises(ValueError, match="CORRELATION_WINDOW_SECONDS"):
        CorrelatorConfig.from_env()
