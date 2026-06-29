import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.core.database import Base
from app.core.dependencies import get_db

# Basic test configuration for Pytest
# In a real scenario, this would configure an in-memory SQLite DB
# or a separate test PostgreSQL instance.

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
