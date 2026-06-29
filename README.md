# MAP — Malware Analysis Platform
MAP is a modern, modular malware analysis platform designed to automate static analysis, memory forensics, IOC extraction, and detection rule generation (YARA and Sigma).

## Features

- **Sample Intake**: Upload and manage malware samples. Automatic hashing (MD5, SHA1, SHA256) and deduplication.
- **Static Analysis**: Deep PE structure parsing, string extraction, and heuristic analysis for suspicious behaviors.
- **Memory Forensics**: Volatility 3 integration for analyzing memory dumps, process trees, and network connections.
- **IOC Extraction**: Regex-based extraction of IPs, domains, URLs, and registry keys from static and memory artifacts.
- **Detection Engineering**: Programmatic generation of YARA rules based on PE characteristics, and Sigma rules for behavioral patterns.
- **Threat Reports**: Automated generation of comprehensive threat intelligence reports mapped to MITRE ATT&CK.

## Architecture

MAP uses a decoupled architecture:
- **Backend API**: FastAPI (Python 3.11+) with async PostgreSQL and SQLAlchemy.
- **Worker Node**: Celery with Redis for asynchronous analysis tasks.
- **Object Storage**: MinIO for storing malware samples securely.
- **Frontend**: React + Vite + TypeScript + Tailwind CSS v4 + shadcn/ui.

Please refer to the `docs/` folder for detailed documentation on architecture, API endpoints, and setup.

## Project Structure

```text
map/
├── .agents/                 # AI Agent instructions and global project rules
├── .github/                 # GitHub Actions CI/CD pipelines
├── backend/                 # FastAPI Backend & Celery Worker
│   ├── alembic/             # Database migrations
│   ├── app/                 # Application code (Domain-Driven Design)
│   │   ├── analysis/        # Static analysis, heuristics, string extraction
│   │   ├── core/            # Config, database, security, and storage core
│   │   ├── detection/       # YARA and Sigma rule generation
│   │   ├── ioc/             # Extractor regex for IPs, URLs, hashes
│   │   ├── memory/          # Volatility 3 memory forensics integration
│   │   ├── reports/         # Executive threat reports & MITRE ATT&CK
│   │   └── samples/         # File intake, deduplication, and hashing
│   ├── scripts/             # Utility scripts (e.g., Synthetic Data Seeder)
│   ├── tests/               # Pytest suite
│   ├── Dockerfile           # Backend container definition
│   └── pyproject.toml       # Python dependencies and metadata
├── docs/                    # Technical documentation
├── docker/                  # NGINX and PostgreSQL configuration files
├── frontend/                # React Vite Frontend (GitHub Dark Theme)
│   ├── public/              # Static assets
│   ├── src/                 # React components and pages
│   │   ├── components/      # Reusable UI (Layout, ThemeToggle)
│   │   ├── pages/           # Dashboard, SampleExplorer, StaticAnalysis, etc.
│   │   ├── App.tsx          # React Router configuration
│   │   └── index.css        # Tailwind v4 configuration and global styles
│   ├── package.json         # Node.js dependencies
│   └── vite.config.ts       # Vite bundler configuration
├── docker-compose.yml       # Development Docker stack
├── docker-compose.prod.yml  # Production overrides (NGINX proxy)
├── todo.md                  # Project tracking
└── README.md                # Project overview
```

## Getting Started

See `docs/setup.md` for detailed instructions on how to run MAP locally or via Docker Compose.
