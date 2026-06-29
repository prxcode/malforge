# Architecture

MAP follows a decoupled, service-oriented architecture designed for scalability and asynchronous processing of heavy analysis tasks.

## Components

1. **FastAPI Backend (`backend/app/main.py`)**: 
   - Handles REST API requests.
   - Domain-driven design (samples, analysis, memory, ioc, detection, reports).
   - Async PostgreSQL connection via SQLAlchemy and `asyncpg`.
   - Dependency injection for database sessions and storage.

2. **Celery Worker (`backend/app/worker.py`)**:
   - Executes heavy tasks (e.g., static analysis, YARA generation, report generation).
   - Redis acts as the message broker and result backend.

3. **Storage Layer**:
   - PostgreSQL: Stores relational metadata (hashes, rules, reports).
   - MinIO / Local FS: Stores the actual malware samples and memory dumps safely via SHA256-hashed filenames.

4. **Frontend**:
   - React application served via NGINX or Vite dev server.
   - Communicates with the FastAPI backend over HTTP/JSON.
