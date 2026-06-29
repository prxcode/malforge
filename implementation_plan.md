# MAP — Malware Analysis Platform: Implementation Plan

## Overview

Build a production-quality, modular malware analysis platform with a **FastAPI backend**, **Celery workers**, **PostgreSQL** database, and a **React + TypeScript + Vite** frontend. The platform automates static malware analysis, memory forensics, IOC extraction, detection rule generation (YARA/Sigma), and threat report generation.

> [!IMPORTANT]
> This is a large-scale, multi-module project. I propose a **6-phase build** (detailed below). Each phase produces a working, testable increment. I will build Phases 1–4 in this session, then 5–6 as follow-ups. **Please confirm before I begin coding.**

---

## User Review Required

> [!WARNING]
> **Scope Decision:** The full project includes 7 core modules, 7+ frontend pages, Docker orchestration, CI/CD, and comprehensive testing. Building everything in one pass would produce a fragile codebase. The phased approach below lets us validate each layer before building on top of it.

> [!IMPORTANT]
> **Tailwind CSS Version:** Your spec lists Tailwind CSS + shadcn/ui. shadcn/ui now requires **Tailwind CSS v4**. I'll use Tailwind v4 + shadcn/ui as specified. Please confirm this is acceptable.

> [!IMPORTANT]
> **Volatility 3 on Windows:** Volatility 3 has complex OS-specific dependencies and requires ISF symbol packs. The Memory Analysis Engine will be architected with a clean interface so it works when Volatility 3 is available, but gracefully degrades (with a "not configured" status) if the symbols/dependencies are missing. This keeps the rest of the platform functional during development.

---

## Open Questions

1. **Authentication:** You mention multi-user auth as a future enhancement. Should I scaffold a basic API key or JWT auth layer now, or leave it fully open for Phase 1–4?
2. **Object Storage:** The architecture mentions Object Storage for samples. Should I use local filesystem storage (with a `STORAGE_PATH` config) for now, or set up MinIO in Docker Compose from the start?
3. **FLOSS Integration:** FLOSS (FLARE Obfuscated String Solver) requires a separate binary. Should I include it as an optional analyzer that's skipped if the binary isn't found, or skip it entirely for now?
4. **Test Samples:** Do you have any PE test binaries or memory dumps to use during development, or should I create synthetic test fixtures?

---

## Proposed Changes

The project will be built inside `c:\Users\Priyanshu\Desktop\Career\2026\projects\map\` with the following structure:

```text
map/
├── backend/
│   ├── alembic/                    # Database migrations
│   ├── app/
│   │   ├── core/                   # Global config, security, database
│   │   │   ├── config.py           # Pydantic Settings
│   │   │   ├── database.py         # SQLAlchemy async engine + session
│   │   │   ├── dependencies.py     # FastAPI dependency injection
│   │   │   └── storage.py          # File storage abstraction
│   │   ├── samples/                # Domain: Sample Intake
│   │   │   ├── router.py
│   │   │   ├── schemas.py
│   │   │   ├── models.py
│   │   │   ├── service.py
│   │   │   └── exceptions.py
│   │   ├── analysis/               # Domain: Static Analysis
│   │   │   ├── router.py
│   │   │   ├── schemas.py
│   │   │   ├── models.py
│   │   │   ├── service.py
│   │   │   ├── pe_analyzer.py      # PE structure parsing (pefile)
│   │   │   ├── string_extractor.py # String extraction engine
│   │   │   ├── heuristics.py       # Suspicious pattern detection
│   │   │   └── tasks.py            # Celery tasks
│   │   ├── memory/                 # Domain: Memory Forensics
│   │   │   ├── router.py
│   │   │   ├── schemas.py
│   │   │   ├── models.py
│   │   │   ├── service.py
│   │   │   ├── vol3_adapter.py     # Volatility 3 integration
│   │   │   └── tasks.py
│   │   ├── ioc/                    # Domain: IOC Extraction
│   │   │   ├── router.py
│   │   │   ├── schemas.py
│   │   │   ├── models.py
│   │   │   ├── service.py
│   │   │   └── extractors.py       # Regex-based IOC extractors
│   │   ├── detection/              # Domain: Detection Engineering
│   │   │   ├── router.py
│   │   │   ├── schemas.py
│   │   │   ├── models.py
│   │   │   ├── service.py
│   │   │   ├── yara_generator.py   # Programmatic YARA generation
│   │   │   ├── sigma_generator.py  # Sigma rule generation
│   │   │   ├── validator.py        # Rule validation engine
│   │   │   └── tasks.py
│   │   ├── reports/                # Domain: Threat Reports
│   │   │   ├── router.py
│   │   │   ├── schemas.py
│   │   │   ├── models.py
│   │   │   ├── service.py
│   │   │   └── generator.py        # Report generation engine
│   │   ├── worker.py               # Celery app configuration
│   │   └── main.py                 # FastAPI entry point
│   ├── tests/
│   │   ├── conftest.py
│   │   ├── test_samples/
│   │   ├── test_analysis/
│   │   ├── test_ioc/
│   │   ├── test_detection/
│   │   └── test_reports/
│   ├── pyproject.toml
│   ├── Dockerfile
│   └── .env.example
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── ui/                 # shadcn/ui components
│   │   │   ├── layout/             # Shell, Sidebar, Header
│   │   │   ├── dashboard/          # Dashboard widgets
│   │   │   ├── samples/            # Sample explorer components
│   │   │   ├── analysis/           # Static analysis viewers
│   │   │   ├── memory/             # Memory analysis viewers
│   │   │   ├── detection/          # Rule viewers
│   │   │   ├── ioc/                # IOC explorer
│   │   │   └── reports/            # Report viewer
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── SampleExplorer.tsx
│   │   │   ├── StaticAnalysis.tsx
│   │   │   ├── MemoryAnalysis.tsx
│   │   │   ├── DetectionRules.tsx
│   │   │   ├── IOCExplorer.tsx
│   │   │   └── ThreatReports.tsx
│   │   ├── hooks/                  # React Query hooks
│   │   ├── lib/                    # API client, utilities
│   │   ├── types/                  # TypeScript interfaces
│   │   ├── App.tsx
│   │   ├── main.tsx
│   │   └── index.css
│   ├── index.html
│   ├── package.json
│   ├── tsconfig.json
│   ├── vite.config.ts
│   └── components.json            # shadcn/ui config
│
├── docker/
│   ├── nginx/
│   │   └── nginx.conf
│   └── postgres/
│       └── init.sql
│
├── scripts/
│   ├── seed_data.py
│   └── generate_test_samples.py
│
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── lint.yml
│
├── docker-compose.yml
├── docker-compose.dev.yml
├── .env.example
├── .gitignore
└── README.md
```

---

## Phase 1: Foundation & Infrastructure

> Build the project skeleton, Docker environment, database, and API framework.

### Backend Core

#### [NEW] [pyproject.toml](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/pyproject.toml)
- Python 3.12 project definition with all dependencies:
  - `fastapi`, `uvicorn`, `sqlalchemy[asyncio]`, `asyncpg`, `pydantic`, `pydantic-settings`
  - `celery[redis]`, `redis`, `alembic`
  - `pefile`, `lief`, `yara-python`, `capstone`
  - `python-multipart`, `aiofiles`
  - Dev: `pytest`, `pytest-asyncio`, `httpx`, `ruff`, `black`

#### [NEW] [app/core/config.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/core/config.py)
- Pydantic `Settings` class loading from `.env`
- Database URL, Redis URL, storage path, API prefix, CORS origins

#### [NEW] [app/core/database.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/core/database.py)
- Async SQLAlchemy engine with `asyncpg`
- Session factory with async context manager
- Base declarative model

#### [NEW] [app/core/storage.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/core/storage.py)
- Local filesystem storage abstraction
- `save_file()`, `get_file()`, `delete_file()`, `get_file_path()`
- Organized by SHA256 hash prefix for efficient disk access

#### [NEW] [app/core/dependencies.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/core/dependencies.py)
- `get_db()` — async database session dependency
- `get_storage()` — storage service dependency

#### [NEW] [app/main.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/main.py)
- FastAPI application factory
- CORS middleware
- Router registration for all domains
- Lifespan handler for startup/shutdown
- Health check endpoint

#### [NEW] [app/worker.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/worker.py)
- Celery app with Redis broker configuration
- Task autodiscovery from all domain modules

### Database Models

#### [NEW] [app/samples/models.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/samples/models.py)
- `Sample` model: id, filename, sha256, sha1, md5, entropy, size, file_type, mime_type, compiler_info, signature_status, upload_time, status

#### [NEW] [app/analysis/models.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/analysis/models.py)
- `StaticAnalysisResult` model: sample_id (FK), imports (JSON), exports (JSON), strings (JSON), sections (JSON), headers (JSON), compiler, entropy_score, suspicious_apis (JSON), heuristic_flags (JSON), completed_at

#### [NEW] [app/memory/models.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/memory/models.py)
- `MemoryAnalysisResult` model: sample_id (FK), processes (JSON), modules (JSON), registry (JSON), services (JSON), network_connections (JSON), injected_memory (JSON), timeline (JSON), completed_at

#### [NEW] [app/ioc/models.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/ioc/models.py)
- `IOCEntry` model: id, sample_id (FK), indicator_type (enum), value, confidence, source, first_seen, context

#### [NEW] [app/detection/models.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/detection/models.py)
- `DetectionRule` model: id, sample_id (FK), rule_type (YARA/SIGMA), rule_name, version, rule_text, metadata (JSON), created_at
- `ValidationResult` model: id, rule_id (FK), true_positive_rate, false_positive_rate, coverage, precision, recall, score, validated_at

#### [NEW] [app/reports/models.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/reports/models.py)
- `ThreatReport` model: id, sample_id (FK), executive_summary, file_metadata (JSON), malware_characteristics (JSON), attack_mapping (JSON), indicators (JSON), recommendations (JSON), detection_opportunities (JSON), generated_at

### Docker Infrastructure

#### [NEW] [docker-compose.yml](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/docker-compose.yml)
- `db`: PostgreSQL 16 Alpine with named volume
- `redis`: Redis 7 Alpine with persistence
- `api`: FastAPI with uvicorn (dev mode with reload)
- `worker`: Celery worker (same image, different command)
- `frontend`: Vite dev server
- `nginx`: Reverse proxy (production profile)

#### [NEW] [docker-compose.dev.yml](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/docker-compose.dev.yml)
- Override for local development with volume mounts and hot-reload

#### [NEW] [backend/Dockerfile](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/Dockerfile)
- Multi-stage build: builder + runtime
- Python 3.12-slim base
- Non-root user for security

### Alembic Migrations

#### [NEW] [alembic/](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/alembic/)
- `alembic.ini` — migration configuration
- `env.py` — async migration runner
- Initial migration creating all tables

---

## Phase 2: Sample Intake & Static Analysis Engine

> The core analysis pipeline — upload files, extract metadata, analyze PE structure.

### Sample Intake Service

#### [NEW] [app/samples/router.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/samples/router.py)
- `POST /api/v1/samples` — Upload file, compute hashes, detect duplicates, store
- `GET /api/v1/samples` — List with pagination, filtering, search
- `GET /api/v1/samples/{id}` — Full sample detail
- `DELETE /api/v1/samples/{id}` — Soft delete

#### [NEW] [app/samples/schemas.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/samples/schemas.py)
- `SampleCreate`, `SampleResponse`, `SampleListResponse`, `SampleFilter`

#### [NEW] [app/samples/service.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/samples/service.py)
- Hash computation (SHA256, SHA1, MD5)
- Entropy calculation
- MIME type detection
- Duplicate detection by SHA256
- File storage orchestration
- Auto-trigger analysis on upload

### Static Analysis Engine

#### [NEW] [app/analysis/pe_analyzer.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/analysis/pe_analyzer.py)
- Parse PE structure using `pefile`:
  - DOS Header, NT Header, Optional Header
  - Section table with entropy per section
  - Import table with DLL + function names
  - Export table
  - Resources
  - Entry point analysis
  - Timestamp extraction
  - Compiler detection heuristics

#### [NEW] [app/analysis/string_extractor.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/analysis/string_extractor.py)
- ASCII string extraction (min length configurable)
- Unicode string extraction
- URL/domain/IP regex matching
- Registry path detection
- File path detection
- Categorization: network, filesystem, registry, crypto, suspicious

#### [NEW] [app/analysis/heuristics.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/analysis/heuristics.py)
- Packed executable detection (entropy > 7.0 in code sections)
- Unusual section names (not .text, .data, .rsrc, .rdata, .reloc)
- Suspicious import combinations (e.g., VirtualAlloc + WriteProcessMemory + CreateRemoteThread)
- Anti-analysis API detection
- Debug artifact detection
- Overlay data detection
- Scoring system with weighted heuristic flags

#### [NEW] [app/analysis/router.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/analysis/router.py)
- `POST /api/v1/analysis/static/{sample_id}` — Trigger static analysis
- `GET /api/v1/analysis/static/{sample_id}` — Get results

#### [NEW] [app/analysis/service.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/analysis/service.py)
- Orchestrates pe_analyzer, string_extractor, heuristics
- Saves results to database
- Returns structured analysis results

#### [NEW] [app/analysis/tasks.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/analysis/tasks.py)
- Celery task: `run_static_analysis` — runs full analysis pipeline asynchronously

---

## Phase 3: IOC Extraction & Detection Engineering

> Extract IOCs from analysis results, generate YARA and Sigma rules.

### IOC Extraction Engine

#### [NEW] [app/ioc/extractors.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/ioc/extractors.py)
- Regex-based extractors for:
  - IPv4/IPv6 addresses
  - Domain names
  - URLs (http/https/ftp)
  - Email addresses
  - Registry keys (HKLM, HKCU, etc.)
  - Windows file paths
  - Mutex names
  - Service names
  - Scheduled task references
  - File hashes (MD5, SHA1, SHA256)
- Confidence scoring based on context
- Deduplication and normalization

#### [NEW] [app/ioc/router.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/ioc/router.py)
- `GET /api/v1/ioc/{sample_id}` — Get all IOCs for a sample
- `GET /api/v1/ioc` — Search across all IOCs

#### [NEW] [app/ioc/service.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/ioc/service.py)
- Run extractors against static analysis strings
- Aggregate from memory analysis artifacts
- Store and deduplicate

### Detection Engineering Engine

#### [NEW] [app/detection/yara_generator.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/detection/yara_generator.py)
- Programmatic YARA rule construction:
  - String-based rules (unique ASCII/Unicode strings)
  - Hex pattern rules (byte sequences from PE sections)
  - Import-based rules (suspicious API combinations)
  - PE metadata conditions (section characteristics, entropy)
  - Metadata generation (author, description, date, hash, threat_level)
  - Condition logic (e.g., `3 of ($s*) and pe.imports(...)`)

#### [NEW] [app/detection/sigma_generator.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/detection/sigma_generator.py)
- Generate Sigma rules for:
  - Process creation (Image, CommandLine, ParentImage)
  - Registry modifications (TargetObject, Details)
  - Service installation (ServiceName, ImagePath)
  - Scheduled tasks (TaskName)
  - Network connections (DestinationIp, DestinationPort)
  - PowerShell execution (ScriptBlockText)
- YAML-based rule output with proper Sigma schema

#### [NEW] [app/detection/validator.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/detection/validator.py)
- YARA rule compilation test (syntax validation)
- YARA rule execution against sample (true positive test)
- False positive estimation (configurable benign file set)
- Metrics: precision, recall, coverage, confidence score

#### [NEW] [app/detection/router.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/detection/router.py)
- `POST /api/v1/rules/generate` — Generate YARA + Sigma for a sample
- `GET /api/v1/rules/{sample_id}` — Get all rules for a sample
- `POST /api/v1/rules/validate` — Run validation pipeline

#### [NEW] [app/detection/service.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/detection/service.py)
- Orchestrate generation and validation
- Store rules with versioning

---

## Phase 4: Memory Analysis, Reports & Frontend

> Memory forensics engine, threat report generation, and the full React dashboard.

### Memory Analysis Engine

#### [NEW] [app/memory/vol3_adapter.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/memory/vol3_adapter.py)
- Volatility 3 integration adapter:
  - Process listing (pslist, psscan)
  - DLL listing (dlllist)
  - Network connections (netscan)
  - Registry hives (hivelist, printkey)
  - Service enumeration
  - Handle listing
  - Command history (cmdline, cmdscan)
  - Injected memory detection (malfind)
  - Process tree construction
- Graceful degradation if Volatility 3 is unavailable

#### [NEW] [app/memory/router.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/memory/router.py)
- `POST /api/v1/analysis/memory/{sample_id}` — Trigger memory analysis
- `GET /api/v1/analysis/memory/{sample_id}` — Get results

### Threat Report Generator

#### [NEW] [app/reports/generator.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/reports/generator.py)
- Aggregate data from: sample metadata, static analysis, memory analysis, IOCs, detection rules
- Generate structured sections:
  - Executive Summary (auto-generated prose)
  - File Metadata table
  - Malware Characteristics
  - MITRE ATT&CK Technique Mapping (based on detected APIs/behaviors)
  - Observed Indicators table
  - Detection Opportunities
  - Recommended Defensive Actions
  - IOC Summary
  - Rule References

#### [NEW] [app/reports/router.py](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/backend/app/reports/router.py)
- `POST /api/v1/reports/generate` — Generate report for a sample
- `GET /api/v1/reports/{sample_id}` — Get report

### Frontend (React + TypeScript + Vite + shadcn/ui)

#### [NEW] Frontend scaffold
- Vite + React + TypeScript project
- Tailwind CSS v4 + shadcn/ui initialization
- React Router for navigation
- React Query for API state management
- Recharts for data visualization

#### [NEW] Layout & Navigation
- Dark-themed application shell with sidebar navigation
- Glassmorphism design accents
- Responsive layout
- Route structure matching all 7 pages

#### [NEW] Dashboard Page
- Analysis statistics cards (total samples, analyses, rules generated)
- Recent uploads table
- Detection metrics (precision, recall charts)
- Queue status indicator
- Activity timeline

#### [NEW] Sample Explorer Page
- Upload dropzone with drag-and-drop
- Filterable/searchable sample table
- Sample detail panel (metadata, hashes, analysis status)

#### [NEW] Static Analysis Page
- PE structure viewer (collapsible sections)
- Import table with DLL grouping and suspicious API highlighting
- String viewer with category filtering
- Section entropy visualization (bar chart)
- Heuristic flags with severity badges

#### [NEW] Memory Analysis Page
- Process tree visualization (interactive)
- Network connections table
- DLL/Module listing
- Registry artifacts viewer
- Timeline visualization

#### [NEW] Detection Rules Page
- YARA rule viewer with syntax highlighting
- Sigma rule viewer with YAML highlighting
- Validation results (precision/recall gauges)
- Copy-to-clipboard and download buttons

#### [NEW] IOC Explorer Page
- Searchable IOC table with type filtering
- IOC type distribution chart
- Export to CSV/JSON
- Confidence indicators

#### [NEW] Threat Reports Page
- Report viewer with collapsible sections
- ATT&CK technique badges
- Print/export functionality
- IOC summary table

---

## Phase 5: CI/CD & Docker Production Setup

### GitHub Actions

#### [NEW] [.github/workflows/ci.yml](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/.github/workflows/ci.yml)
- Backend: lint (ruff), format check (black), pytest
- Frontend: lint (eslint), type check (tsc), build

#### [NEW] [.github/workflows/lint.yml](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/.github/workflows/lint.yml)
- Pre-commit hooks configuration
- Ruff + Black for Python
- ESLint + Prettier for TypeScript

### Production Docker

#### [NEW] [docker/nginx/nginx.conf](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/docker/nginx/nginx.conf)
- Reverse proxy: `/api` → FastAPI, `/` → React static build
- Gzip compression, security headers

---

## Phase 6: Testing & Documentation

### Tests

#### [NEW] Backend tests
- `test_samples/` — Upload, duplicate detection, hash computation
- `test_analysis/` — PE parsing, string extraction, heuristics
- `test_ioc/` — IOC extraction accuracy
- `test_detection/` — YARA/Sigma generation, validation
- `test_reports/` — Report generation

### Documentation

#### [NEW] [README.md](file:///c:/Users/Priyanshu/Desktop/Career/2026/projects/map/README.md)
- Project overview, architecture diagram, setup instructions
- API documentation links
- Contributing guide
- Screenshots

---

## Verification Plan

### Automated Tests
```bash
# Backend
cd backend && python -m pytest tests/ -v --tb=short

# Linting
ruff check app/
black --check app/

# Frontend
cd frontend && npm run lint && npm run build
```

### Manual Verification
- Upload a test PE binary through the frontend
- Verify static analysis produces correct PE structure, imports, strings
- Verify IOC extraction identifies embedded URLs/IPs
- Verify YARA rule generation produces compilable rules
- Verify Sigma rules follow valid schema
- Verify threat report aggregates all analysis data
- Verify all frontend pages render correctly with real data
- Test Docker Compose full stack deployment

---

## Execution Order Summary

| Phase | Scope | Key Deliverables |
|-------|-------|-----------------|
| **1** | Foundation | Project skeleton, Docker, DB, API framework |
| **2** | Intake & Analysis | File upload, PE analysis, string extraction, heuristics |
| **3** | IOC & Detection | IOC extraction, YARA generation, Sigma generation, validation |
| **4** | Memory, Reports & UI | Memory forensics, reports, full React dashboard |
| **5** | CI/CD | GitHub Actions, production Docker, NGINX |
| **6** | Testing & Docs | Unit tests, integration tests, README |
