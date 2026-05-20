from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from auth_backend.api import build_app
from auth_backend.jwt_helper import decode
from auth_backend.store import UsersStore


_T0 = datetime(2026, 5, 20, 12, 0, 0, tzinfo=timezone.utc)
_SECRET = "test-secret"


async def _store_for(path):
    store = UsersStore(path)
    await store.init_schema()
    return store


async def _client_for(tmp_db_path):
    store = await _store_for(tmp_db_path)
    app = build_app(store=store, jwt_secret=_SECRET, jwt_ttl_seconds=3600,
                    cors_origins=["http://localhost:5173"], now=lambda: _T0)
    return TestClient(app), store


async def test_healthz(tmp_db_path):
    client, store = await _client_for(tmp_db_path)
    try:
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}
    finally:
        await store.aclose()


async def test_register_happy_path(tmp_db_path):
    client, store = await _client_for(tmp_db_path)
    try:
        resp = client.post("/auth/register", json={
            "username": "alice", "email": "alice@example.com",
            "password": "secret", "role": "admin",
        })
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["username"] == "alice"
        assert body["email"] == "alice@example.com"
        assert body["role"] == "admin"
        assert "id" in body
        # No password field in response
        assert "password" not in body
        assert "password_hash" not in body
    finally:
        await store.aclose()


async def test_register_duplicate_returns_409(tmp_db_path):
    client, store = await _client_for(tmp_db_path)
    try:
        payload = {"username": "alice", "email": "a@b.io", "password": "x", "role": "admin"}
        first = client.post("/auth/register", json=payload)
        assert first.status_code == 201
        second = client.post("/auth/register", json=payload)
        assert second.status_code == 409
        assert "already exists" in second.json()["error"]
    finally:
        await store.aclose()


async def test_login_happy_returns_token(tmp_db_path):
    client, store = await _client_for(tmp_db_path)
    try:
        client.post("/auth/register", json={
            "username": "alice", "email": "alice@example.com",
            "password": "secret", "role": "admin",
        })
        resp = client.post("/auth/login", json={
            "email": "alice@example.com", "password": "secret",
        })
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert "access_token" in body
        assert body["token_type"] == "bearer"
        assert body["user"]["email"] == "alice@example.com"
        # Token decodes with the shared secret
        claims = decode(body["access_token"], secret=_SECRET, now=_T0)
        assert claims["email"] == "alice@example.com"
        assert claims["role"] == "admin"
    finally:
        await store.aclose()


async def test_login_wrong_password_returns_401(tmp_db_path):
    client, store = await _client_for(tmp_db_path)
    try:
        client.post("/auth/register", json={
            "username": "alice", "email": "a@b.io", "password": "secret", "role": "admin",
        })
        resp = client.post("/auth/login", json={
            "email": "a@b.io", "password": "wrong",
        })
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid credentials"
    finally:
        await store.aclose()


async def test_me_with_token_returns_user(tmp_db_path):
    client, store = await _client_for(tmp_db_path)
    try:
        client.post("/auth/register", json={
            "username": "alice", "email": "a@b.io", "password": "x", "role": "analyst",
        })
        login = client.post("/auth/login", json={"email": "a@b.io", "password": "x"})
        token = login.json()["access_token"]
        resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["email"] == "a@b.io"
        assert resp.json()["role"] == "analyst"
    finally:
        await store.aclose()


async def test_me_without_token_returns_401(tmp_db_path):
    client, store = await _client_for(tmp_db_path)
    try:
        resp = client.get("/auth/me")
        assert resp.status_code == 401
        assert resp.json()["error"] == "unauthorized"
    finally:
        await store.aclose()
