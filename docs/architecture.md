# Architecture

## Overview

MAP uses a decoupled architecture that separates the web API from heavy analysis work. FastAPI handles HTTP requests, Celery workers run the expensive analysis tasks asynchronously, and results are stored in PostgreSQL.

## System Diagram

```
                    ┌─────────────────────────────────────────────────┐
                    │                   Frontend                      │
                    │          React + TypeScript + Vite               │
                    │    (Dashboard, Explorer, Analysis Pages)         │
                    └──────────────────┬──────────────────────────────┘
                                       │ HTTP/JSON
                    ┌──────────────────▼──────────────────────────────┐
                    │                FastAPI Server                    │
                    │                                                  │
                    │  ┌──────────┐ ┌──────────┐ ┌──────────────────┐ │
                    │  │ Samples  │ │ Analysis │ │    Detection     │ │
                    │  │  Module  │ │  Module  │ │     Module       │ │
                    │  └──────────┘ └──────────┘ └──────────────────┘ │
                    │  ┌──────────┐ ┌──────────┐ ┌──────────────────┐ │
                    │  │ Memory   │ │   IOC    │ │    Reports       │ │
                    │  │  Module  │ │  Module  │ │     Module       │ │
                    │  └──────────┘ └──────────┘ └──────────────────┘ │
                    └───┬──────────────┬────────────────┬─────────────┘
                        │              │                │
              ┌─────────▼───┐  ┌───────▼────────┐  ┌───▼────────────┐
              │ PostgreSQL  │  │     Redis       │  │     MinIO      │
              │ (Metadata,  │  │ (Task Broker,   │  │ (Sample Files, │
              │  Results,   │  │  Result Store)  │  │  Memory Dumps) │
              │  Rules)     │  │                 │  │                │
              └─────────────┘  └───────┬─────────┘  └────────────────┘
                                       │
                               ┌───────▼─────────┐
                               │  Celery Worker   │
                               │                  │
                               │  - PE Analysis   │
                               │  - String Extract │
                               │  - Heuristics    │
                               │  - YARA Gen      │
                               │  - Sigma Gen     │
                               │  - Memory Analysis│
                               │  - Report Gen    │
                               └──────────────────┘
```

## Data Flow: Sample Upload to Report

1. **Upload**: User submits a file through the React frontend
2. **API receives**: FastAPI `/api/v1/samples/` endpoint accepts the file via multipart form
3. **Hash & Store**: The backend computes MD5/SHA1/SHA256 hashes and uploads the file to MinIO using the SHA256 as the storage key
4. **Database record**: A `Sample` row is created in PostgreSQL with metadata (filename, hashes, size, status=pending)
5. **Task dispatch**: The API sends a Celery task to the Redis broker
6. **Worker picks up**: A Celery worker pulls the task, downloads the sample from MinIO, and runs the analysis pipeline:
   - `pe_analyzer.py` — Parses PE headers, sections, imports, exports
   - `string_extractor.py` — Extracts printable strings, classifies them by type
   - `heuristics.py` — Scores behavioral indicators (packing, anti-debug, injection APIs)
   - `extractors.py` — Extracts IOCs (IPs, domains, URLs, file paths, registry keys)
   - `yara_generator.py` — Generates a YARA rule from unique strings and byte patterns
   - `sigma_generator.py` — Generates a Sigma rule from behavioral indicators
   - `generator.py` — Compiles everything into a threat intelligence report
7. **Results stored**: All results are written back to PostgreSQL
8. **Frontend polls**: The React frontend fetches results via the API and displays them

## Module Responsibilities

| Module | Directory | Purpose |
|--------|-----------|---------|
| Core | `app/core/` | Database connection, MinIO storage, JWT auth, config, dependency injection |
| Samples | `app/samples/` | File upload, hash computation, sample metadata CRUD |
| Analysis | `app/analysis/` | PE parsing, string extraction, heuristic scoring |
| Memory | `app/memory/` | Volatility 3 integration for memory dump analysis |
| IOC | `app/ioc/` | Network and file system indicator extraction |
| Detection | `app/detection/` | YARA and Sigma rule generation and validation |
| Reports | `app/reports/` | Threat intelligence report compilation |
| Orchestrator | `app/orchestrator/` | Pipeline coordination across all modules |
| Auth | `app/auth/` | JWT token generation and validation |

## Technology Choices

- **FastAPI** — Async Python framework, auto-generates OpenAPI docs, Pydantic validation
- **Celery + Redis** — Proven task queue for long-running analysis jobs. Redis is lightweight and acts as both broker and result backend
- **PostgreSQL** — Relational database for structured metadata, analysis results, and rules. Async via `asyncpg`
- **MinIO** — S3-compatible object storage. Keeps binary samples separate from the database. Files are stored by SHA256 hash to deduplicate
- **React + Vite** — Fast development experience with hot module reload. TypeScript for type safety
- **Tailwind CSS v4** — Utility-first CSS with CSS variable-based theming for dark/light mode support
