import pytest

from anomaly.config import INPUT_TOPIC, OUTPUT_TOPIC, AnomalyConfig


def test_input_topic_constant():
    assert INPUT_TOPIC == "events.normalized"


def test_output_topic_constant():
    assert OUTPUT_TOPIC == "events.scored"


def test_from_env_with_defaults(monkeypatch):
    monkeypatch.delenv("KAFKA_BOOTSTRAP", raising=False)
    monkeypatch.delenv("CONSUMER_GROUP", raising=False)
    monkeypatch.delenv("ANOMALY_THRESHOLD", raising=False)
    monkeypatch.delenv("MODEL_PATH", raising=False)
    cfg = AnomalyConfig.from_env()
    assert cfg.bootstrap_servers == "kafka:9092"
    assert cfg.consumer_group == "anomaly-detector"
    assert cfg.threshold == 0.5
    assert cfg.model_path == "/app/model.pkl"
    assert cfg.input_topic == "events.normalized"
    assert cfg.output_topic == "events.scored"


def test_from_env_overrides(monkeypatch):
    monkeypatch.setenv("KAFKA_BOOTSTRAP", "kafka.example.com:19092")
    monkeypatch.setenv("CONSUMER_GROUP", "anomaly-staging")
    monkeypatch.setenv("ANOMALY_THRESHOLD", "0.8")
    monkeypatch.setenv("MODEL_PATH", "/tmp/test-model.pkl")
    cfg = AnomalyConfig.from_env()
    assert cfg.bootstrap_servers == "kafka.example.com:19092"
    assert cfg.consumer_group == "anomaly-staging"
    assert cfg.threshold == 0.8
    assert cfg.model_path == "/tmp/test-model.pkl"


def test_from_env_rejects_threshold_out_of_range(monkeypatch):
    for bad in ("-0.1", "1.5", "abc"):
        monkeypatch.setenv("ANOMALY_THRESHOLD", bad)
        with pytest.raises(ValueError, match="ANOMALY_THRESHOLD"):
            AnomalyConfig.from_env()
