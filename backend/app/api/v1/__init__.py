"""
API v1 root router.
"""

from fastapi import APIRouter
from app.api.v1.health import router as health_router
from app.api.v1.scam_analysis import router as scam_analysis_router
from app.api.v1.url_check import router as url_check_router

api_v1_router = APIRouter(prefix="/api/v1")

api_v1_router.include_router(health_router)
api_v1_router.include_router(url_check_router)
api_v1_router.include_router(scam_analysis_router)