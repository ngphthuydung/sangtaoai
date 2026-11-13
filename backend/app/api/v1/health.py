"""
Health check endpoint for Lá Chắn Người Thân Backend.
"""
from datetime import datetime, timezone
import os
import re

from fastapi import APIRouter

from app.core.config import settings

router = APIRouter(tags=["Hệ Thống / Health"])
_GIT_REVISION_PATTERN = re.compile(r"[0-9a-f]{40}", re.IGNORECASE)


def _render_revision() -> str | None:
    revision = os.getenv("RENDER_GIT_COMMIT", "")
    return revision if _GIT_REVISION_PATTERN.fullmatch(revision) else None


@router.get(
    "/health",
    summary="Kiểm tra trạng thái hoạt động của Backend",
    description="Endpoint dùng để kiểm tra hệ thống máy chủ có đang hoạt động bình thường hay không."
)
async def check_health():
    """
    Trả về thông tin trạng thái máy chủ, phiên bản và môi trường hoạt động.
    """
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "revision": _render_revision(),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
