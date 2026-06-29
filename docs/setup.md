# Setup Guide

## Prerequisites

- **Docker Desktop** — Required for the full stack (PostgreSQL, Redis, MinIO, API, Worker)
- **Python 3.11+** — Required only if running backend locally without Docker
- **Node.js 20+** — Required for frontend development
- **Git**

## Option 1: Docker (Recommended)

This is the easiest way to run the entire platform.

### 1. Clone and configure

```bash
git clone https://github.com/prxcode/malware-analysis-platform.git
cd malware-analysis-platform
cp .env.example .env
```

> **Note on Nginx:** You might notice an `nginx` folder in the repo. This is only used for the **Production** deployment (`docker-compose.prod.yml`). During development, we use Vite's dev server directly for hot-reloading.

### 2. Start Docker Desktop

Make sure Docker Desktop is running. You can verify with:

```bash
docker version
```

If you see an error about `dockerDesktopLinuxEngine`, open Docker Desktop from the Start Menu and wait for it to fully start.

### 3. Start all services

```bash
docker-compose up --build -d
```

This starts 7 containers:

| Container | Port | Purpose |
|-----------|------|---------|
| map-api | 8000 | FastAPI backend |
| map-worker | — | Celery worker (processes analysis tasks) |
| map-flower | 5555 | Celery task monitor dashboard |
| map-db | 5432 | PostgreSQL database |
| map-redis | 6379 | Redis (task broker + result backend) |
| map-minio | 9000, 9001 | MinIO object storage (samples) |
| map-minio-init | — | One-shot container to create the MinIO bucket |

### 4. Verify

```bash
# Check all containers are running
docker-compose ps

# Test the API
curl http://localhost:8000/health
```

### 5. Start the frontend

The frontend runs separately (not in Docker during development):

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173 in your browser.

## Option 2: Local Development (Without Docker)

Use this if you want to run the backend directly on your machine. You still need PostgreSQL and Redis running somewhere (you can use Docker just for those).

### 1. Start database services only

```bash
docker-compose up -d db redis minio minio-init
```

### 2. Set up Python environment

```bash
cd backend
python -m venv .venv

# Windows
.\.venv\Scripts\Activate.ps1

# macOS/Linux
source .venv/bin/activate

pip install -e .[dev]
```

### 3. Configure environment

Create a `.env` file in the project root. Use `.env.example` as a template, but change the host values for local development:

```
POSTGRES_HOST=localhost
REDIS_URL=redis://localhost:6379/0
MINIO_ENDPOINT=localhost:9000
```

### 4. Start the API server

```bash
uvicorn app.main:app --reload
```

The API will be available at http://localhost:8000/api/v1/docs

### 6. Start a Celery worker (separate terminal)

```bash
cd backend
celery -A app.worker worker --loglevel=info
```

### 7. Start the frontend (separate terminal)

```bash
cd frontend
npm install
npm run dev
```

## Troubleshooting

### Docker: "failed to connect to the docker API"

Docker Desktop is not running. Open it from the Start Menu and wait for the green icon in the system tray.

### Port 8000 already in use

Another process is using port 8000. Either stop that process or change the port:

```bash
uvicorn app.main:app --reload --port 8001
```

### Frontend: "Cannot find module" errors

Run `npm install` in the `frontend/` directory to install missing dependencies.

### Database connection errors

Make sure PostgreSQL is running and the connection string in `.env` matches your setup. For Docker, the host should be `db`. For local development, use `localhost`.

### MinIO: bucket not found

The `map-minio-init` container creates the bucket on first start. If it failed, create it manually:

```bash
docker-compose run --rm minio-init
```
