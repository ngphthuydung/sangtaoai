"""
Health check endpoint for Lá Chắn Người Thân Backend.
"""
from datetime import datetime, timezone
from fastapi import APIRouter
from app.core.config import settings

router = APIRouter(tags=["Hệ Thống / Health"])


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
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
