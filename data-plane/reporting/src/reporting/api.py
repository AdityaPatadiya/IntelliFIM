"""FastAPI app factory for the reporting service.

`build_app(...)` returns a configured FastAPI instance with all routes,
auth wiring, exception handlers, and CORS. `now` is threaded through to
the JWT decoder so tests share the fixed test clock (lesson from #6 Task 8).
"""
from __future__ import annotations

import base64
import logging
import os
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator
from pydantic import ValidationError

from reporting.auth import make_get_current_principal, require_roles
from reporting.metrics import (
    SERVICE_LABEL,
    errors_total,
    messages_processed_total,
    processing_seconds,
)
from reporting.models import (
    GenerateReportRequest,
    Principal,
    ReportListResponse,
    ReportMetadata,
)
from reporting.orchestrator_client import OrchestratorClient, OrchestratorError
from reporting.renderer import render_chart, render_html, render_pdf
from reporting.store import ReportingStore


logger = logging.getLogger(__name__)


def _default_now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _row_to_metadata(row) -> ReportMetadata:
    return ReportMetadata(
        id=row.id, name=row.name,
        range_start=row.range_start, range_end=row.range_end,
        generated_at=row.generated_at, generated_by=row.generated_by,
        size_bytes=row.size_bytes,
        approvals_count=row.approvals_count,
        scores_count=row.scores_count,
    )


def build_app(
    *,
    store: ReportingStore,
    orchestrator: OrchestratorClient,
    jwt_secret: str,
    jwt_ttl_seconds: int,
    cors_origins: tuple[str, ...],
    now: Callable[[], datetime] = _default_now,
) -> FastAPI:
    app = FastAPI(title="intellifim-reporting", default_response_class=JSONResponse)

    Instrumentator().instrument(app).expose(app)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(cors_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

    # --- exception handlers (uniform error envelope) ---
    @app.exception_handler(HTTPException)
    async def _http_exc(_: Request, exc: HTTPException):
        return JSONResponse(status_code=exc.status_code, content={"error": str(exc.detail)})

    @app.exception_handler(ValidationError)
    async def _validation_exc(_: Request, exc: ValidationError):
        return JSONResponse(status_code=400, content={"error": exc.errors()[0]["msg"]})

    @app.exception_handler(Exception)
    async def _unknown_exc(_: Request, exc: Exception):
        logger.exception("unhandled exception")
        return JSONResponse(status_code=500, content={"error": "internal server error"})

    # FastAPI's own RequestValidationError → 400
    from fastapi.exceptions import RequestValidationError

    @app.exception_handler(RequestValidationError)
    async def _request_validation_exc(_: Request, exc: RequestValidationError):
        msgs = exc.errors()
        first = msgs[0] if msgs else {"msg": "invalid request"}
        return JSONResponse(status_code=422, content={"error": first.get("msg", "invalid request")})

    # --- auth deps ---
    get_principal = make_get_current_principal(jwt_secret, now=now)
    require_admin_or_analyst = require_roles("admin", "analyst")
    require_admin = require_roles("admin")

    def admin_or_analyst_dep(p: Principal = Depends(get_principal)) -> Principal:
        return require_admin_or_analyst(p)

    def admin_dep(p: Principal = Depends(get_principal)) -> Principal:
        return require_admin(p)

    # --- routes ---
    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/reports/generate", status_code=201, response_model=ReportMetadata)
    async def generate(
        body: GenerateReportRequest,
        request: Request,
        principal: Principal = Depends(admin_or_analyst_dep),
    ) -> ReportMetadata:
        with processing_seconds.labels(SERVICE_LABEL).time():
            try:
                # Forward the caller's bearer token to the orchestrator
                auth_header = request.headers.get("authorization", "")
                jwt_token = auth_header.removeprefix("Bearer ").strip()

                try:
                    approvals = await orchestrator.list_approvals(jwt=jwt_token)
                except OrchestratorError as e:
                    raise HTTPException(status_code=e.status if e.status >= 500 else 502,
                                        detail=str(e)) from e

                # Filter approvals by date range client-side. Parse `created_at` to
                # a tz-aware datetime so the comparison is correct regardless of the
                # offset string format the orchestrator emits.
                approvals_in_range = []
                for a in approvals:
                    try:
                        created_at = datetime.fromisoformat(a["created_at"])
                    except (KeyError, ValueError):
                        continue   # skip malformed rows rather than crash the report
                    if body.range_start <= created_at < body.range_end:
                        approvals_in_range.append(a)

                scores = await store.query_scores(start=body.range_start, end=body.range_end)
                top = await store.top_hosts_by_max_score(
                    start=body.range_start, end=body.range_end, limit=10
                )

                # Summary stats
                by_state: dict[str, int] = {}
                by_priority: dict[str, int] = {}
                for a in approvals_in_range:
                    by_state[a["state"]] = by_state.get(a["state"], 0) + 1
                    by_priority[a["priority"]] = by_priority.get(a["priority"], 0) + 1
                unique_hosts = len({s.host_id for s in scores})

                # Chart → SVG → base64
                svg_bytes = render_chart(top, title="Top hosts by max threat score")
                chart_b64 = base64.b64encode(svg_bytes).decode("ascii")

                generated_at = now()
                rid = uuid4()
                context: dict[str, Any] = {
                    "title": body.name,
                    "range_start": body.range_start.isoformat(),
                    "range_end": body.range_end.isoformat(),
                    "generated_at": generated_at.isoformat(),
                    "generated_by": principal.username,
                    "stats": {
                        "approvals_total": len(approvals_in_range),
                        "approvals_by_state": by_state,
                        "approvals_by_priority": by_priority,
                        "scores_total": len(scores),
                        "unique_hosts": unique_hosts,
                    },
                    "chart_svg_b64": chart_b64,
                    "approvals": approvals_in_range,
                }

                html = render_html(context)
                pdf_bytes = render_pdf(html)

                date_part = generated_at.strftime("%Y-%m-%d")
                pdf_path = os.path.join(store.reports_dir, f"{date_part}-{rid}.pdf")
                with open(pdf_path, "wb") as f:
                    f.write(pdf_bytes)

                await store.insert_report(
                    id=rid, name=body.name,
                    range_start_iso=body.range_start.isoformat(),
                    range_end_iso=body.range_end.isoformat(),
                    generated_at_iso=generated_at.isoformat(),
                    generated_by=principal.username,
                    pdf_path=pdf_path, size_bytes=len(pdf_bytes),
                    approvals_count=len(approvals_in_range),
                    scores_count=len(scores),
                )

                result = ReportMetadata(
                    id=rid, name=body.name,
                    range_start=body.range_start, range_end=body.range_end,
                    generated_at=generated_at, generated_by=principal.username,
                    size_bytes=len(pdf_bytes),
                    approvals_count=len(approvals_in_range),
                    scores_count=len(scores),
                )
                messages_processed_total.labels(SERVICE_LABEL).inc()
                return result
            except HTTPException:
                raise   # 4xx/5xx already counted by Instrumentator
            except Exception as e:
                errors_total.labels(service=SERVICE_LABEL, kind=type(e).__name__).inc()
                raise

    @app.get("/reports", response_model=ReportListResponse)
    async def list_reports(
        limit: int = 50,
        offset: int = 0,
        principal: Principal = Depends(get_principal),
    ) -> ReportListResponse:
        if limit < 1 or limit > 200:
            raise HTTPException(status_code=400, detail="limit must be in [1, 200]")
        if offset < 0:
            raise HTTPException(status_code=400, detail="offset must be >= 0")
        rows, total = await store.list_reports(limit=limit, offset=offset)
        return ReportListResponse(
            reports=[_row_to_metadata(r) for r in rows], total=total
        )

    @app.get("/reports/{report_id}", response_model=ReportMetadata)
    async def get_one(
        report_id: UUID,
        principal: Principal = Depends(get_principal),
    ) -> ReportMetadata:
        row = await store.get_report(report_id)
        if row is None:
            raise HTTPException(status_code=404, detail="report not found")
        return _row_to_metadata(row)

    @app.get("/reports/{report_id}/download")
    async def download(
        report_id: UUID,
        principal: Principal = Depends(get_principal),
    ) -> Response:
        row = await store.get_report(report_id)
        if row is None:
            raise HTTPException(status_code=404, detail="report not found")
        try:
            with open(row.pdf_path, "rb") as f:
                data = f.read()
        except FileNotFoundError as e:
            raise HTTPException(status_code=500, detail="pdf file missing on disk") from e
        filename = f"{row.name.replace(' ', '_')}-{row.generated_at[:10]}.pdf"
        return Response(
            content=data,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(data)),
            },
        )

    @app.delete("/reports/{report_id}")
    async def delete_one(
        report_id: UUID,
        principal: Principal = Depends(admin_dep),
    ) -> dict[str, str]:
        removed = await store.delete_report(report_id)
        if not removed:
            raise HTTPException(status_code=404, detail="report not found")
        return {"status": "deleted"}

    return app
