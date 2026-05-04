import pytest

from normalizers.config import (
    OUTPUT_TOPIC,
    SOURCE_TO_INPUT_TOPIC,
    NormalizerConfig,
)


def test_from_env_with_valid_source(monkeypatch):
    monkeypatch.setenv("NORMALIZER_SOURCE", "wazuh.fim")
    monkeypatch.delenv("KAFKA_BOOTSTRAP", raising=False)
    cfg = NormalizerConfig.from_env()
    assert cfg.source == "wazuh.fim"
    assert cfg.input_topic == "wazuh.fim"
    assert cfg.output_topic == OUTPUT_TOPIC == "events.normalized"
    assert cfg.bootstrap_servers == "kafka:9092"  # default
    assert cfg.consumer_group == "normalizer-wazuh-fim"


def test_from_env_uses_custom_bootstrap(monkeypatch):
    monkeypatch.setenv("NORMALIZER_SOURCE", "zeek.conn")
    monkeypatch.setenv("KAFKA_BOOTSTRAP", "kafka.example.com:19092")
    cfg = NormalizerConfig.from_env()
    assert cfg.bootstrap_servers == "kafka.example.com:19092"


def test_from_env_rejects_unknown_source(monkeypatch):
    monkeypatch.setenv("NORMALIZER_SOURCE", "syslog.unknown")
    with pytest.raises(ValueError, match="NORMALIZER_SOURCE"):
        NormalizerConfig.from_env()


def test_from_env_requires_source(monkeypatch):
    monkeypatch.delenv("NORMALIZER_SOURCE", raising=False)
    with pytest.raises(KeyError):
        NormalizerConfig.from_env()


def test_consumer_group_per_source(monkeypatch):
    """Each source must get its own consumer group so they advance independently."""
    groups = set()
    for source in SOURCE_TO_INPUT_TOPIC:
        monkeypatch.setenv("NORMALIZER_SOURCE", source)
        groups.add(NormalizerConfig.from_env().consumer_group)
    assert len(groups) == 6  # one per source
