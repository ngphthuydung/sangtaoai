"""
Main entry point for Lá Chắn Người Thân FastAPI application.
"""
import json
import logging
from time import perf_counter
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.v1 import api_v1_router
from app.core.request_diagnostics import (
    RequestDiagnostics,
    bind_diagnostics,
    reset_diagnostics,
)

logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Hệ thống AI đa tầng bảo vệ người dùng trước các nguy cơ lừa đảo trực tuyến tại Việt Nam.",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Cấu hình CORS để Frontend (React) có thể gọi API một cách an toàn
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=[
        "X-Request-ID",
        "X-Processing-Stage",
        "X-Error-Category",
        "X-Processing-Duration-Ms",
        "X-AI-Retry-Count",
        "X-Provider-Status",
    ],
)

# Gắn kết các router của API v1
app.include_router(api_v1_router)


def _log_request_diagnostics(
    request: Request,
    diagnostics: RequestDiagnostics,
    status_code: int,
    duration_ms: int,
) -> None:
    record = {
        "event": "request_diagnostic",
        "request_id": diagnostics.request_id,
        "stage": diagnostics.stage,
        "error_category": diagnostics.error_category,
        "http_status": status_code,
        "provider_status": diagnostics.provider_status,
        "duration_ms": duration_ms,
        "retry_count": diagnostics.retry_count,
        "method": request.method,
        "path": request.url.path,
    }
    logger.info("%s", json.dumps(record, separators=(",", ":"), sort_keys=True))


@app.middleware("http")
async def request_diagnostics(request: Request, call_next):
    diagnostics = RequestDiagnostics(request_id=uuid4().hex)
    request.state.diagnostics = diagnostics
    token = bind_diagnostics(diagnostics)
    started_at = perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        diagnostics.error_category = "internal_error"
        diagnostics.http_status = 500
        duration_ms = round((perf_counter() - started_at) * 1000)
        if request.url.path.startswith("/api/v1/scam-analysis"):
            _log_request_diagnostics(request, diagnostics, 500, duration_ms)
        raise
    finally:
        reset_diagnostics(token)

    duration_ms = round((perf_counter() - started_at) * 1000)
    status_code = response.status_code
    if status_code >= 400 and diagnostics.error_category == "none":
        diagnostics.error_category = {
            400: "invalid_request",
            401: "unauthorized",
            403: "consent_required",
            413: "payload_too_large",
            415: "unsupported_media_type",
            422: "invalid_request",
            429: "rate_limited",
            503: "service_unavailable",
        }.get(status_code, "http_error")
    diagnostics.http_status = status_code
    response.headers["X-Request-ID"] = diagnostics.request_id
    response.headers["X-Processing-Stage"] = diagnostics.stage
    response.headers["X-Error-Category"] = diagnostics.error_category
    response.headers["X-Processing-Duration-Ms"] = str(duration_ms)
    response.headers["X-AI-Retry-Count"] = str(diagnostics.retry_count)
    if diagnostics.provider_status is not None:
        response.headers["X-Provider-Status"] = str(diagnostics.provider_status)
    if request.url.path.startswith("/api/v1/scam-analysis"):
        _log_request_diagnostics(request, diagnostics, status_code, duration_ms)
    return response


@app.get("/", tags=["Trang chủ"])
async def root():
    """
    Endpoint mặc định chào mừng khi truy cập vào root URL của API.
    """
    return {
        "message": "Chào mừng bạn đến với Hệ thống API Lá Chắn Người Thân",
        "docs": "/docs",
        "health": "/api/v1/health",
        "version": settings.VERSION
    }
