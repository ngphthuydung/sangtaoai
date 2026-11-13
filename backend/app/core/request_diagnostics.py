"""Privacy-safe per-request diagnostic metadata."""

import contextvars
from dataclasses import dataclass


@dataclass
class RequestDiagnostics:
    request_id: str
    stage: str = "request_received"
    error_category: str = "none"
    http_status: int | None = None
    provider_status: int | None = None
    retry_count: int = 0


_current_diagnostics: contextvars.ContextVar[RequestDiagnostics | None] = (
    contextvars.ContextVar("request_diagnostics", default=None)
)


def bind_diagnostics(
    diagnostics: RequestDiagnostics,
) -> contextvars.Token[RequestDiagnostics | None]:
    return _current_diagnostics.set(diagnostics)


def reset_diagnostics(
    token: contextvars.Token[RequestDiagnostics | None],
) -> None:
    _current_diagnostics.reset(token)


def current_diagnostics() -> RequestDiagnostics | None:
    return _current_diagnostics.get()


def record_retry() -> None:
    diagnostics = current_diagnostics()
    if diagnostics is not None:
        diagnostics.retry_count += 1


def record_provider_failure(
    category: str,
    provider_status: int | None = None,
) -> None:
    diagnostics = current_diagnostics()
    if diagnostics is not None:
        diagnostics.error_category = category
        diagnostics.provider_status = provider_status
