"""
Unit test for health check endpoint.
"""
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_root_endpoint():
    """Kiểm tra endpoint gốc GET /"""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert data["health"] == "/api/v1/health"


def test_health_check_endpoint():
    """Kiểm tra endpoint GET /api/v1/health theo yêu cầu của Milestone 1"""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "service" in data
    assert "version" in data
    assert "environment" in data
    assert "timestamp" in data
