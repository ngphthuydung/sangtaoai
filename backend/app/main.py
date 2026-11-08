"""
Main entry point for Lá Chắn Người Thân FastAPI application.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.v1 import api_v1_router

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
)

# Gắn kết các router của API v1
app.include_router(api_v1_router)


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
