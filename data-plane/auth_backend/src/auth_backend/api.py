"""FastAPI app for the auth-backend.

Built via build_app(store, jwt_secret, jwt_ttl_seconds, cors_origins, now)
so tests can inject fakes / fixed clock. Returns uniform JSON errors
{"error":"..."} via custom exception handlers.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator
from pydantic import BaseModel, ConfigDict, EmailStr, Field

from auth_backend.jwt_helper import JwtError, decode as jwt_decode, encode as jwt_encode
from auth_backend.metrics import (
    SERVICE_LABEL,
    errors_total,
    messages_processed_total,
    processing_seconds,
)
from auth_backend.store import DuplicateUserError, UsersStore


Role = Literal["admin", "analyst", "viewer"]


def _default_now() -> datetime:
    return datetime.now(tz=timezone.utc)


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1)
    email: EmailStr
    password: str = Field(min_length=1)
    role: Role


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    password: str = Field(min_length=1)


class UserPublic(BaseModel):
    id: str
    username: str
    email: str
    role: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserPublic


def build_app(
    *,
    store: UsersStore,
    jwt_secret: str,
    jwt_ttl_seconds: int,
    cors_origins: list[str],
    now: Callable[[], datetime] = _default_now,
) -> FastAPI:
    app = FastAPI(title="intellifim-auth-backend", docs_url="/docs", redoc_url=None)

    Instrumentator().instrument(app).expose(app)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    @app.exception_handler(DuplicateUserError)
    async def _dup_handler(_req: Request, exc: DuplicateUserError) -> JSONResponse:
        return JSONResponse(
            {"error": f"username or email already exists: {exc}"},
            status_code=status.HTTP_409_CONFLICT,
        )

    @app.exception_handler(HTTPException)
    async def _http_handler(_req: Request, exc: HTTPException) -> JSONResponse:
        # Normalize FastAPI's default {"detail": "..."} to {"error": "..."}
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)

    async def _current_user(
        authorization: str | None = Header(default=None),
    ) -> UserPublic:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="unauthorized")
        token = authorization[len("Bearer "):]
        try:
            claims = jwt_decode(token, secret=jwt_secret, now=now())
        except JwtError:
            raise HTTPException(status_code=401, detail="unauthorized")
        # Fetch fresh from DB so we don't trust stale role claims
        from uuid import UUID
        row = await store.get_by_id(UUID(claims["sub"]))
        if row is None:
            raise HTTPException(status_code=401, detail="unauthorized")
        return UserPublic(
            id=str(row.id), username=row.username, email=row.email, role=row.role,
        )

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok"}

    @app.post("/auth/register", status_code=201, response_model=UserPublic)
    async def register(body: RegisterRequest) -> UserPublic:
        with processing_seconds.labels(SERVICE_LABEL).time():
            try:
                row = await store.create_user(
                    username=body.username, email=body.email,
                    password=body.password, role=body.role, now=now(),
                )
                result = UserPublic(
                    id=str(row.id), username=row.username, email=row.email, role=row.role,
                )
                messages_processed_total.labels(SERVICE_LABEL).inc()
                return result
            except HTTPException:
                raise  # 4xx already counted by Instrumentator
            except DuplicateUserError:
                raise  # 409 already counted by Instrumentator
            except Exception as e:
                errors_total.labels(service=SERVICE_LABEL, kind=type(e).__name__).inc()
                raise

    @app.post("/auth/login", response_model=LoginResponse)
    async def login(body: LoginRequest) -> LoginResponse:
        with processing_seconds.labels(SERVICE_LABEL).time():
            try:
                row = await store.get_by_email(body.email)
                if row is None or not store.verify_password(body.password, row.password_hash):
                    raise HTTPException(status_code=401, detail="invalid credentials")
                token = jwt_encode(
                    user_id=row.id, username=row.username, email=row.email, role=row.role,
                    secret=jwt_secret, ttl_seconds=jwt_ttl_seconds, now=now(),
                )
                result = LoginResponse(
                    access_token=token,
                    user=UserPublic(
                        id=str(row.id), username=row.username, email=row.email, role=row.role,
                    ),
                )
                messages_processed_total.labels(SERVICE_LABEL).inc()
                return result
            except HTTPException:
                raise  # 4xx already counted by Instrumentator
            except Exception as e:
                errors_total.labels(service=SERVICE_LABEL, kind=type(e).__name__).inc()
                raise

    @app.get("/auth/me", response_model=UserPublic)
    async def me(user: UserPublic = Depends(_current_user)) -> UserPublic:
        return user

    return app


async def seed_admin_if_missing(
    *,
    store: UsersStore,
    username: str,
    email: str,
    password: str,
    now: Callable[[], datetime] = _default_now,
) -> None:
    """Called once at startup. Inserts the admin user if no admin exists yet."""
    import logging
    log = logging.getLogger("auth_backend")
    if await store.admin_exists():
        log.info("admin user already exists, skipping seed")
        return
    try:
        await store.create_user(
            username=username, email=email, password=password,
            role="admin", now=now(),
        )
        log.info("seeded admin user %s", username)
    except DuplicateUserError as exc:
        log.info("admin seed skipped (race): %s", exc)
