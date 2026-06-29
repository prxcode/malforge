import pytest
from contextlib import asynccontextmanager
from fastapi.testclient import TestClient

from app.main import app

# Mock lifespan to prevent DB and MinIO connections during tests without a real backend
@asynccontextmanager
async def mock_lifespan(app):
    yield

app.router.lifespan_context = mock_lifespan
client = TestClient(app)

def test_health_check():
    """Test that the application health check works."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "MAP" in data["service"]

def test_api_docs():
    """Test that the API documentation is generated and accessible."""
    response = client.get("/api/v1/docs")
    assert response.status_code == 200
