import pytest

from orchestrator.config import INPUT_TOPIC, OrchestratorConfig


def test_input_topic_constant():
    assert INPUT_TOPIC == "threat.scores"


_DEFAULT_PG = "postgresql://orchestrator:orch-pass@postgres:5432/orchestrator"


def test_from_env_with_defaults(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "test")
    monkeypatch.setenv("DATABASE_URL", _DEFAULT_PG)
    for k in (
        "KAFKA_BOOTSTRAP", "CONSUMER_GROUP",
        "API_HOST", "API_PORT",
        "WAZUH_MANAGER_URL", "WAZUH_API_USER", "WAZUH_API_PASSWORD",
        "TIER_LOW_THRESHOLD", "TIER_HIGH_THRESHOLD",
    ):
        monkeypatch.delenv(k, raising=False)
    cfg = OrchestratorConfig.from_env()
    assert cfg.bootstrap_servers == "kafka:9092"
    assert cfg.consumer_group == "response-orchestrator"
    assert cfg.input_topic == "threat.scores"
    assert cfg.database_url == _DEFAULT_PG
    assert cfg.api_host == "0.0.0.0"
    assert cfg.api_port == 8200
    assert cfg.wazuh_manager_url == "https://wazuh-manager:55000"
    assert cfg.wazuh_api_user == "wazuh"
    assert cfg.wazuh_api_password == "wazuh"
    assert cfg.tier_low_threshold == 30.0
    assert cfg.tier_high_threshold == 70.0
    assert cfg.jwt_secret == "test"


def test_from_env_overrides(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "prod-secret")
    monkeypatch.setenv("KAFKA_BOOTSTRAP", "kafka.example.com:19092")
    monkeypatch.setenv("CONSUMER_GROUP", "orch-staging")
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@pg.example.com:5432/orchestrator")
    monkeypatch.setenv("API_HOST", "127.0.0.1")
    monkeypatch.setenv("API_PORT", "9999")
    monkeypatch.setenv("WAZUH_MANAGER_URL", "https://mgr.example.com:55000")
    monkeypatch.setenv("WAZUH_API_USER", "alice")
    monkeypatch.setenv("WAZUH_API_PASSWORD", "s3cret")
    monkeypatch.setenv("TIER_LOW_THRESHOLD", "20")
    monkeypatch.setenv("TIER_HIGH_THRESHOLD", "80")
    cfg = OrchestratorConfig.from_env()
    assert cfg.bootstrap_servers == "kafka.example.com:19092"
    assert cfg.consumer_group == "orch-staging"
    assert cfg.database_url == "postgresql://u:p@pg.example.com:5432/orchestrator"
    assert cfg.api_host == "127.0.0.1"
    assert cfg.api_port == 9999
    assert cfg.wazuh_manager_url == "https://mgr.example.com:55000"
    assert cfg.wazuh_api_user == "alice"
    assert cfg.wazuh_api_password == "s3cret"
    assert cfg.tier_low_threshold == 20.0
    assert cfg.tier_high_threshold == 80.0
    assert cfg.jwt_secret == "prod-secret"


def test_from_env_rejects_invalid_port(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x")
    monkeypatch.setenv("DATABASE_URL", _DEFAULT_PG)
    for bad in ("0", "abc", "-1", "70000"):
        monkeypatch.setenv("API_PORT", bad)
        with pytest.raises(ValueError, match="API_PORT"):
            OrchestratorConfig.from_env()


def test_from_env_rejects_low_threshold_le_zero(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x")
    monkeypatch.setenv("DATABASE_URL", _DEFAULT_PG)
    monkeypatch.setenv("TIER_LOW_THRESHOLD", "0")
    with pytest.raises(ValueError, match="TIER_LOW_THRESHOLD"):
        OrchestratorConfig.from_env()
    monkeypatch.setenv("TIER_LOW_THRESHOLD", "-1")
    with pytest.raises(ValueError, match="TIER_LOW_THRESHOLD"):
        OrchestratorConfig.from_env()


def test_from_env_rejects_high_threshold_above_100(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x")
    monkeypatch.setenv("DATABASE_URL", _DEFAULT_PG)
    monkeypatch.setenv("TIER_HIGH_THRESHOLD", "101")
    with pytest.raises(ValueError, match="TIER_HIGH_THRESHOLD"):
        OrchestratorConfig.from_env()


def test_from_env_rejects_low_ge_high(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x")
    monkeypatch.setenv("DATABASE_URL", _DEFAULT_PG)
    monkeypatch.setenv("TIER_LOW_THRESHOLD", "70")
    monkeypatch.setenv("TIER_HIGH_THRESHOLD", "30")
    with pytest.raises(ValueError, match="TIER_LOW_THRESHOLD.*TIER_HIGH_THRESHOLD"):
        OrchestratorConfig.from_env()


def test_from_env_missing_jwt_secret_raises(monkeypatch):
    # Need other required vars set so we reach the JWT_SECRET check
    monkeypatch.delenv("JWT_SECRET", raising=False)
    monkeypatch.setenv("DATABASE_URL", _DEFAULT_PG)
    with pytest.raises(ValueError, match="JWT_SECRET"):
        OrchestratorConfig.from_env()


def test_from_env_missing_database_url_raises(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ValueError, match="DATABASE_URL"):
        OrchestratorConfig.from_env()


def test_from_env_jwt_secret_round_trips(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "round-trip-value")
    monkeypatch.setenv("DATABASE_URL", _DEFAULT_PG)
    cfg = OrchestratorConfig.from_env()
    assert cfg.jwt_secret == "round-trip-value"
