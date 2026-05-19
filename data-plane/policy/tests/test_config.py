import pytest

from policy.config import INPUT_TOPIC, OUTPUT_TOPIC, PolicyConfig


def test_input_topic_constant():
    assert INPUT_TOPIC == "events.scored"


def test_output_topic_constant():
    assert OUTPUT_TOPIC == "threat.scores"


def test_from_env_with_defaults(monkeypatch):
    for k in ("KAFKA_BOOTSTRAP", "CONSUMER_GROUP", "OPA_URL", "REDIS_URL", "THREAT_SCORE_WINDOW_SECONDS"):
        monkeypatch.delenv(k, raising=False)
    cfg = PolicyConfig.from_env()
    assert cfg.bootstrap_servers == "kafka:9092"
    assert cfg.consumer_group == "policy-engine"
    assert cfg.opa_url == "http://opa:8181"
    assert cfg.redis_url == "redis://redis:6379/0"
    assert cfg.window_seconds == 300
    assert cfg.input_topic == "events.scored"
    assert cfg.output_topic == "threat.scores"


def test_from_env_overrides(monkeypatch):
    monkeypatch.setenv("KAFKA_BOOTSTRAP", "kafka.example.com:19092")
    monkeypatch.setenv("CONSUMER_GROUP", "policy-staging")
    monkeypatch.setenv("OPA_URL", "http://opa.example.com:8181")
    monkeypatch.setenv("REDIS_URL", "redis://redis.example.com:6379/1")
    monkeypatch.setenv("THREAT_SCORE_WINDOW_SECONDS", "600")
    cfg = PolicyConfig.from_env()
    assert cfg.bootstrap_servers == "kafka.example.com:19092"
    assert cfg.consumer_group == "policy-staging"
    assert cfg.opa_url == "http://opa.example.com:8181"
    assert cfg.redis_url == "redis://redis.example.com:6379/1"
    assert cfg.window_seconds == 600


def test_from_env_rejects_invalid_window(monkeypatch):
    for bad in ("0", "-10", "abc"):
        monkeypatch.setenv("THREAT_SCORE_WINDOW_SECONDS", bad)
        with pytest.raises(ValueError, match="THREAT_SCORE_WINDOW_SECONDS"):
            PolicyConfig.from_env()
