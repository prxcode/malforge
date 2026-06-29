# Setup Guide

## Requirements
- Python 3.11+
- Docker & Docker Compose (for full stack)
- Node.js (for frontend development)

## Local Development (Without Docker)

1. **Create Virtual Environment**:
   ```bash
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

2. **Install Backend Dependencies**:
   ```bash
   cd backend
   pip install -e .[dev]
   ```

3. **Run Migrations**:
   ```bash
   alembic upgrade head
   ```

4. **Start API Server**:
   ```bash
   uvicorn app.main:app --reload
   ```

## Docker Deployment

To spin up the entire stack (API, PostgreSQL, Redis, MinIO, Celery):

```bash
docker-compose up -d
```

The API will be available at `http://localhost:8000/api/v1/docs`.
