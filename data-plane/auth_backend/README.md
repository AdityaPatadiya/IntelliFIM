# intellifim-auth-backend

FastAPI service that issues HS256 JWTs for the IntelliFIM admin console
and validates them via shared secret with response-orchestrator. SQLite-
backed user store; bcrypt password hashing; seeds one admin user from
env on first start.

Install for development:

    pip install -e data-plane/auth_backend[dev]

Run Python tests:

    pytest --import-mode=importlib data-plane/auth_backend/tests

Endpoints:
- POST /auth/register
- POST /auth/login
- GET  /auth/me
- GET  /healthz
- GET  /docs  (Swagger UI; FastAPI built-in)
