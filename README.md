# MAP — Malware Analysis Platform

A cybersecurity-focused platform that automates static malware analysis, memory forensics, IOC extraction, and detection rule generation (YARA/Sigma). Built to resemble the internal tools used by SOC analysts and threat intelligence teams.

## What This Project Does

When a malware analyst receives a suspicious binary, they normally spend hours manually:
1. Inspecting PE headers, imports, and sections
2. Extracting strings and looking for C2 URLs, IP addresses, registry keys
3. Running heuristic checks for packing, anti-debug tricks, process injection
4. Analyzing memory dumps for hidden or injected processes
5. Writing YARA and Sigma rules to detect the malware across an enterprise
6. Compiling a threat report for the SOC team

**MAP automates this entire workflow.** Upload a file, and the platform runs the full analysis pipeline, extracts IOCs, generates detection rules, and produces a threat intelligence report — all through a web interface backed by async task processing.

## Features

### Currently Implemented
- **Static Analysis Engine** — Parse PE headers (DOS, NT, Optional), section tables, imports (detects suspicious APIs like `CreateRemoteThread`, `VirtualAllocEx`), exports, and calculate per-section entropy
- **String Extraction & Classification** — Extract ASCII/Unicode strings, classify URLs, IP addresses, domains, registry keys, file paths, mutex names, email addresses
- **Heuristic Scoring** — Rule-based behavioral detection: packing (high entropy), anti-debug APIs, process injection patterns, persistence mechanisms, crypto APIs
- **Memory Forensics** — Volatility 3 integration for process tree extraction, DLL injection detection, hidden/unlinked process identification, RWX memory regions
- **IOC Extraction** — Automated extraction of file hashes, network indicators, file system artifacts, registry keys
- **YARA Rule Generation** — Auto-generate YARA rules from static indicators (strings, imports, PE metadata, entropy) with proper metadata (author, date, hash, confidence)
- **Sigma Rule Generation** — Auto-generate Sigma rules from behavioral indicators for SIEM deployment
- **Threat Reports** — Compile executive summaries with risk scores, IOC counts, detection confidence
- **Dark/Light Theme** — System preference detection with localStorage persistence

### Planned (Future Scope)
- Dynamic analysis sandbox (Cuckoo/CAPEv2 integration)
- MITRE ATT&CK technique mapping
- Rule validation against known-good/known-bad sample sets
- PDF/HTML report export
- VirusTotal API correlation
- Packer identification (UPX, Themida, VMProtect)

## Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Backend API | Python 3.11+, FastAPI | Async framework with auto-generated OpenAPI docs |
| Task Queue | Celery + Redis | Handles heavy analysis tasks asynchronously |
| Database | PostgreSQL + SQLAlchemy (async) | Stores metadata, analysis results, rules |
| Object Storage | MinIO (S3-compatible) | Stores binary samples safely by SHA256 hash |
| Static Analysis | pefile, yara-python | Industry-standard PE parsing and YARA libraries |
| Memory Analysis | Volatility 3 | The standard tool for memory forensics |
| Frontend | React 18, TypeScript, Vite | Modern SPA with type safety |
| Styling | Tailwind CSS v4 | Utility-first CSS with dark/light theme via CSS variables |
| Icons | Lucide React | Consistent icon set |
| Deployment | Docker Compose | One command spins up 7 containers |

## Project Structure

```
map/
├── backend/
│   ├── app/
│   │   ├── core/           # Config, database, storage (MinIO), JWT auth, dependency injection
│   │   ├── samples/        # File upload, hash computation, sample metadata
│   │   ├── analysis/       # PE analyzer, string extractor, heuristic engine
│   │   │   ├── pe_analyzer.py        # Parses PE headers, sections, imports, exports
│   │   │   ├── string_extractor.py   # Extracts and classifies strings
│   │   │   └── heuristics.py         # Behavioral scoring rules
│   │   ├── memory/         # Volatility 3 adapter for memory dump analysis
│   │   ├── ioc/            # IOC extraction (IPs, domains, URLs, registry keys)
│   │   ├── detection/      # YARA and Sigma rule generators + validator
│   │   ├── reports/        # Threat intelligence report compiler
│   │   ├── orchestrator/   # Coordinates the full analysis pipeline
│   │   ├── auth/           # JWT token auth
│   │   ├── main.py         # FastAPI app entry point
│   │   └── worker.py       # Celery worker config
│   ├── alembic/            # Database migrations
│   ├── tests/              # pytest test suite
│   ├── Dockerfile
│   └── pyproject.toml
├── frontend/
│   ├── src/
│   │   ├── components/     # Layout (sidebar + header), ThemeToggle
│   │   ├── pages/          # Dashboard, SampleExplorer, StaticAnalysis,
│   │   │                   # MemoryAnalysis, DetectionRules, ThreatReports
│   │   ├── App.tsx         # Router
│   │   ├── main.tsx        # Entry point
│   │   └── index.css       # Tailwind theme config (dark/light CSS variables)
│   ├── index.html
│   ├── vite.config.ts
│   └── package.json
├── docs/                   # You're reading these
│   ├── architecture.md     # System design and data flow
│   ├── api.md              # Full API reference with examples
│   ├── setup.md            # Step-by-step setup guide
│   └── testing.md          # How to test + screenshot guide
├── scripts/
│   └── generate_test_samples.py   # Creates fake PE files for testing
├── docker/
│   ├── nginx/nginx.conf    # Production-only reverse proxy config
│   └── postgres/           # DB init scripts
├── .github/workflows/      # CI/CD (lint + test on push)
├── docker-compose.yml      # Development: 7 containers (no nginx)
├── docker-compose.prod.yml # Production: adds nginx, disables debug
├── .env.example            # Environment variable template
└── README.md
```

## Quick Start

### Prerequisites
- **Docker Desktop** — [Download here](https://www.docker.com/products/docker-desktop/). This is the only hard requirement.
- **Node.js 20+** — For the frontend dev server
- **Git**

### 1. Clone and configure

```bash
git clone https://github.com/prxcode/malware-analysis-platform.git
cd malware-analysis-platform
cp .env.example .env
```

### 2. Start the backend (Docker)

Make sure Docker Desktop is running (check the system tray icon), then:

```bash
docker-compose up --build -d
```

This starts **7 containers**. Wait about 30 seconds for everything to initialize.

```bash
# Verify all containers are running
docker-compose ps
```

You should see: `map-api`, `map-worker`, `map-flower`, `map-db`, `map-redis`, `map-minio`, `map-minio-init` (this one exits after creating the storage bucket).

### 3. Start the frontend

Open a **second terminal**:

```bash
cd frontend
npm install
npm run dev
```

### 4. Open the app

- **Frontend**: http://localhost:5173
- **API docs** (Swagger UI): http://localhost:8000/api/v1/docs
- **Flower** (task queue monitor): http://localhost:5555
- **MinIO console** (file storage): http://localhost:9001 (login: `map_minio_admin` / `map_minio_secret`)

### 5. Stop everything

```bash
# Stop backend containers
docker-compose down

# Stop frontend: Ctrl+C in the terminal running npm run dev
```

For detailed setup options (local dev without Docker, troubleshooting), see [docs/setup.md](docs/setup.md).

### FAQ: Why do I see Nginx in the codebase?
If you are running the project using `npm run dev` and `docker-compose.yml`, you are using the **Development Setup**. In development, we use Vite's dev server (`npm run dev`) for fast hot-reloading. 

The `docker/nginx` folder and `docker-compose.prod.yml` file are only used for the **Production Setup**, where the compiled React app is served by Nginx alongside the API in a single unified Docker network.

### FAQ: Where is PostgreSQL?
PostgreSQL is running inside the `map-db` container. It handles all metadata, analysis results, and generated rules. If you want to connect a GUI like DBeaver or pgAdmin, connect to `localhost:5432` with username `map_user` and password `map_secret_password`.

## How It Works

```
User uploads .exe ──▶ FastAPI receives file
                          │
                          ▼
                    Hash (MD5, SHA1, SHA256)
                    Store binary in MinIO
                    Save metadata to PostgreSQL
                          │
                          ▼
                    Dispatch Celery task ──▶ Redis broker
                                                │
                                                ▼
                                          Celery Worker
                                          ┌─────────────────────┐
                                          │ 1. PE Analysis       │
                                          │ 2. String Extraction │
                                          │ 3. Heuristic Scoring │
                                          │ 4. IOC Extraction    │
                                          │ 5. YARA Generation   │
                                          │ 6. Sigma Generation  │
                                          │ 7. Report Compilation│
                                          └─────────┬───────────┘
                                                    │
                                                    ▼
                                          Results ──▶ PostgreSQL
                                                    │
                                                    ▼
                                          Frontend fetches via API
```

## API Endpoints

| Method | Endpoint | What it does |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/api/v1/samples/` | Upload a sample file |
| GET | `/api/v1/samples/` | List all samples |
| POST | `/api/v1/analysis/static/{id}` | Run static analysis |
| GET | `/api/v1/analysis/static/{id}` | Get analysis results |
| POST | `/api/v1/memory/{id}` | Run memory analysis |
| GET | `/api/v1/ioc/{id}` | Get extracted IOCs |
| POST | `/api/v1/detection/generate-rule` | Generate YARA + Sigma rules |
| GET | `/api/v1/report/{hash}` | Get threat report |

Full reference: [docs/api.md](docs/api.md)

## Testing

```bash
# Backend tests
cd backend
pytest

# Frontend type-check + build
cd frontend
npm run build
```

### Generating Test Samples

You can generate safe, synthetic PE files that will trigger the heuristic rules without needing real malware:

```bash
cd backend
python ../scripts/generate_test_samples.py
```
This will create a `test_samples/` directory with `.exe` files you can safely upload via the UI.

For a complete manual testing walkthrough with screenshots, see [docs/testing.md](docs/testing.md).

## Architecture

See [docs/architecture.md](docs/architecture.md) for the full system design.

```
┌──────────┐     ┌──────────┐     ┌───────────┐
│ React UI │────▶│ FastAPI  │────▶│  Celery   │
│  (Vite)  │◀────│  Server  │◀────│  Worker   │
└──────────┘     └────┬─────┘     └─────┬─────┘
                      │                 │
                 ┌────▼─────┐     ┌─────▼─────┐
                 │PostgreSQL│     │   MinIO    │
                 │(metadata)│     │ (samples)  │
                 └──────────┘     └───────────┘
                      │
                 ┌────▼─────┐
                 │  Redis   │
                 │ (broker) │
                 └──────────┘
```

## Screenshots

When presenting this project, capture these:

| # | Page | What to show |
|---|------|-------------|
| 1 | Dashboard | Stat cards + recent submissions |
| 2 | Sample Explorer | File upload + scan result with classification |
| 3 | Static Analysis | PE headers, sections, heuristics, strings |
| 4 | Detection Rules | Generated YARA and Sigma rules |
| 5 | Theme (dark) | Any page in dark mode |
| 6 | Theme (light) | Same page in light mode |
| 7 | API Docs | Swagger UI at `/api/v1/docs` |
| 8 | Flower | Task queue dashboard at `:5555` |

Save in `screenshots/` and optionally embed in README.

## Known Limitations

- No dynamic analysis sandbox yet (planned: Cuckoo/CAPEv2)
- Volatility 3 requires correct symbol files for memory dump OS version
- Heuristics are rule-based — may false-positive on packed legitimate software
- No MITRE ATT&CK mapping yet (planned)
- No packer identification yet (planned: UPX, Themida, VMProtect detection)

## Future Roadmap

- [ ] Dynamic analysis sandbox with Sysmon logging
- [ ] MITRE ATT&CK technique mapping
- [ ] Packer identification (UPX, Themida, VMProtect)
- [ ] Rule validation against malware/benign datasets
- [ ] PDF/HTML report export
- [ ] VirusTotal/MISP threat intelligence correlation
- [ ] Process tree visualization (D3.js)
- [ ] Multi-user RBAC

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit changes (`git commit -m "Add your feature"`)
4. Push to branch (`git push origin feature/your-feature`)
5. Open a Pull Request

## License

MIT License

## Author

**Priyanshu** — [@prxcode](https://github.com/prxcode) · [LinkedIn](https://linkedin.com/in/prxcode)
