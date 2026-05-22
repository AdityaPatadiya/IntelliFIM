"""ReportingConfig env-var parsing tests."""
from __future__ import annotations

import pytest

from reporting.config import ReportingConfig, ReportingConfigError


def _set_required(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "secret")
    monkeypatch.setenv("KAFKA_BOOTSTRAP", "kafka:9092")
    monkeypatch.setenv("ORCHESTRATOR_URL", "http://response-orchestrator:8200")


def test_required_fields_have_no_defaults(monkeypatch):
    """JWT_SECRET, KAFKA_BOOTSTRAP, ORCHESTRATOR_URL are required."""
    for missing in ("JWT_SECRET", "KAFKA_BOOTSTRAP", "ORCHESTRATOR_URL"):
        _set_required(monkeypatch)
        monkeypatch.delenv(missing, raising=False)
        with pytest.raises(ReportingConfigError) as exc:
            ReportingConfig.from_env()
        assert missing in str(exc.value)


def test_defaults_applied_for_optional_fields(monkeypatch):
    _set_required(monkeypatch)
    cfg = ReportingConfig.from_env()
    assert cfg.jwt_secret == "secret"
    assert cfg.kafka_bootstrap == "kafka:9092"
    assert cfg.orchestrator_url == "http://response-orchestrator:8200"
    assert cfg.db_path == "/data/reporting.db"
    assert cfg.reports_dir == "/data/reports"
    assert cfg.bind_host == "0.0.0.0"
    assert cfg.port == 8300
    assert cfg.jwt_ttl_seconds == 8 * 60 * 60
    assert cfg.cors_origins == ("http://localhost:5173",)
    assert cfg.kafka_topic == "threat.scores"
    assert cfg.kafka_group_id == "intellifim-reporting"


def test_overrides_from_env(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("DB_PATH", "/tmp/reporting.db")
    monkeypatch.setenv("REPORTS_DIR", "/tmp/reports")
    monkeypatch.setenv("BIND_HOST", "127.0.0.1")
    monkeypatch.setenv("PORT", "9300")
    monkeypatch.setenv("JWT_TTL_SECONDS", "300")
    monkeypatch.setenv("CORS_ORIGINS", "http://a.example, http://b.example")
    cfg = ReportingConfig.from_env()
    assert cfg.db_path == "/tmp/reporting.db"
    assert cfg.reports_dir == "/tmp/reports"
    assert cfg.bind_host == "127.0.0.1"
    assert cfg.port == 9300
    assert cfg.jwt_ttl_seconds == 300
    assert cfg.cors_origins == ("http://a.example", "http://b.example")


def test_bad_orchestrator_url_rejected(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("ORCHESTRATOR_URL", "not-a-url")
    with pytest.raises(ReportingConfigError) as exc:
        ReportingConfig.from_env()
    assert "ORCHESTRATOR_URL" in str(exc.value)


def test_bad_int_env_rejected(monkeypatch):
    """PORT / JWT_TTL_SECONDS with non-integer value raise ReportingConfigError."""
    for var in ("PORT", "JWT_TTL_SECONDS"):
        _set_required(monkeypatch)
        monkeypatch.setenv(var, "garbage")
        with pytest.raises(ReportingConfigError) as exc:
            ReportingConfig.from_env()
        assert var in str(exc.value)
        assert "garbage" in str(exc.value)
        monkeypatch.delenv(var, raising=False)
