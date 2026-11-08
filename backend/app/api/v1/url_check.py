
"""
URL safety check endpoint for Lá Chắn Người Thân.
"""

from urllib.parse import urlparse

from fastapi import APIRouter
from pydantic import BaseModel, HttpUrl

router = APIRouter(tags=["Kiểm tra đường link"])


class URLCheckRequest(BaseModel):
    url: HttpUrl


class URLCheckResponse(BaseModel):
    url: str
    status: str
    risk_level: str
    message: str


@router.post("/check", response_model=URLCheckResponse)
async def check_url(request: URLCheckRequest):
    """
    Kiểm tra định dạng URL và một số dấu hiệu đáng ngờ cơ bản.
    Không thay thế dịch vụ xác minh an toàn chuyên dụng.
    """

    url = str(request.url)
    parsed = urlparse(url)

    suspicious_signals = []

    if parsed.scheme != "https":
        suspicious_signals.append("Không sử dụng HTTPS")

    if parsed.username or parsed.password:
        suspicious_signals.append("URL chứa thông tin đăng nhập")

    if parsed.port and parsed.port not in (80, 443):
        suspicious_signals.append("Sử dụng cổng không phổ biến")

    if suspicious_signals:
        return URLCheckResponse(
            url=url,
            status="warning",
            risk_level="needs_review",
            message="Phát hiện dấu hiệu cần kiểm tra: "
            + ", ".join(suspicious_signals),
        )

    return URLCheckResponse(
        url=url,
        status="unchecked",
        risk_level="unknown",
        message="Chưa phát hiện dấu hiệu cơ bản đáng ngờ. "
        "Điều này không đảm bảo đường link an toàn.",
    )
