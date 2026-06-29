# MAP — Build Tasks

## Phase 1: Foundation & Infrastructure
- `[x]` Project root files (.gitignore, .env.example, docker-compose.yml)
- `[x]` Backend pyproject.toml & Dockerfile
- `[x]` Core: config.py, database.py, storage.py (MinIO), dependencies.py, security.py (JWT)
- `[x]` app/main.py — FastAPI entry point
- `[x]` app/worker.py — Celery configuration
- `[x]` Database models (all domains)
- `[x]` Alembic migrations setup
- `[x]` Docker Compose (PostgreSQL, Redis, MinIO, API, Worker)

## Phase 2: Sample Intake & Static Analysis
- `[x]` samples/ — router, schemas, service
- `[x]` analysis/pe_analyzer.py
- `[x]` analysis/string_extractor.py
- `[x]` analysis/heuristics.py
- `[x]` analysis/ — router, schemas, service, tasks
- `[x]` Synthetic test fixtures

## Phase 3: IOC Extraction & Detection Engineering
- `[x]` ioc/extractors.py
- `[x]` ioc/ — router, schemas, service
- `[x]` detection/yara_generator.py
- `[x]` detection/sigma_generator.py
- `[x]` detection/validator.py
- `[x]` detection/ — router, schemas, service, tasks

## Phase 4: Memory Analysis, Reports & Frontend
- `[x]` memory/vol3_adapter.py
- `[x]` memory/ — router, schemas, service, tasks
- `[x]` reports/generator.py
- `[x]` reports/ — router, schemas, service
- `[x]` Frontend scaffold (Vite + React + TS + shadcn/ui)
- `[x]` Layout & Navigation (dark theme, sidebar)
- `[x]` Dashboard page
- `[x]` Sample Explorer page
- `[x]` Static Analysis page
- `[x]` Memory Analysis page
- `[x]` Detection Rules page
- `[x]` IOC Explorer page
- `[x]` Threat Reports page

## Phase 5: CI/CD & Production Docker
- `[x]` .github/workflows/ci.yml
- `[x]` .github/workflows/lint.yml
- `[x]` docker/nginx/nginx.conf
- `[x]` Production docker-compose overrides

## Phase 6: Testing & Documentation
- `[x]` Backend test suite
- `[x]` README.md with architecture diagrams
