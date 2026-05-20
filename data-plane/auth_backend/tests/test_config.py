import pytest

from auth_backend.config import AuthBackendConfig


def test_from_env_with_defaults(monkeypatch):
    monkeypatch.delenv("DB_PATH", raising=False)
    monkeypatch.delenv("API_HOST", raising=False)
    monkeypatch.delenv("API_PORT", raising=False)
    monkeypatch.delenv("JWT_TTL_SECONDS", raising=False)
    monkeypatch.delenv("CORS_ORIGINS", raising=False)
    monkeypatch.delenv("ADMIN_USERNAME", raising=False)
    # Required vars
    monkeypatch.setenv("JWT_SECRET", "test-secret")
    monkeypatch.setenv("ADMIN_EMAIL", "admin@example.com")
    monkeypatch.setenv("ADMIN_PASSWORD", "secret")
    cfg = AuthBackendConfig.from_env()
    assert cfg.db_path == "/data/users.db"
    assert cfg.api_host == "0.0.0.0"
    assert cfg.api_port == 8000
    assert cfg.jwt_secret == "test-secret"
    assert cfg.jwt_ttl_seconds == 28800
    assert cfg.cors_origins == ["http://localhost:5173", "http://127.0.0.1:5173"]
    assert cfg.admin_username == "admin"
    assert cfg.admin_email == "admin@example.com"
    assert cfg.admin_password == "secret"


def test_from_env_overrides(monkeypatch):
    monkeypatch.setenv("DB_PATH", "/tmp/staging.db")
    monkeypatch.setenv("API_HOST", "127.0.0.1")
    monkeypatch.setenv("API_PORT", "9999")
    monkeypatch.setenv("JWT_SECRET", "prod-secret")
    monkeypatch.setenv("JWT_TTL_SECONDS", "3600")
    monkeypatch.setenv("CORS_ORIGINS", "https://a.example.com,https://b.example.com")
    monkeypatch.setenv("ADMIN_USERNAME", "root")
    monkeypatch.setenv("ADMIN_EMAIL", "root@example.com")
    monkeypatch.setenv("ADMIN_PASSWORD", "rootpw")
    cfg = AuthBackendConfig.from_env()
    assert cfg.db_path == "/tmp/staging.db"
    assert cfg.api_host == "127.0.0.1"
    assert cfg.api_port == 9999
    assert cfg.jwt_secret == "prod-secret"
    assert cfg.jwt_ttl_seconds == 3600
    assert cfg.cors_origins == ["https://a.example.com", "https://b.example.com"]
    assert cfg.admin_username == "root"
    assert cfg.admin_email == "root@example.com"
    assert cfg.admin_password == "rootpw"


def test_from_env_missing_jwt_secret_raises(monkeypatch):
    monkeypatch.delenv("JWT_SECRET", raising=False)
    monkeypatch.setenv("ADMIN_EMAIL", "x@y")
    monkeypatch.setenv("ADMIN_PASSWORD", "z")
    with pytest.raises(ValueError, match="JWT_SECRET"):
        AuthBackendConfig.from_env()


def test_from_env_missing_admin_fields_raises(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x")
    monkeypatch.delenv("ADMIN_EMAIL", raising=False)
    monkeypatch.setenv("ADMIN_PASSWORD", "z")
    with pytest.raises(ValueError, match="ADMIN_EMAIL"):
        AuthBackendConfig.from_env()
    monkeypatch.setenv("ADMIN_EMAIL", "x@y")
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    with pytest.raises(ValueError, match="ADMIN_PASSWORD"):
        AuthBackendConfig.from_env()
