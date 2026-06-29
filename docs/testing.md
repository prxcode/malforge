# Testing Guide

## Backend Tests

### Running tests

```bash
cd backend
pytest
```

This runs the test suite in `backend/tests/`. The current tests cover:

- **Health check** (`GET /health`) — Verifies the API is running and returns the correct service name
- **API docs** (`GET /api/v1/docs`) — Verifies Swagger UI is generated and accessible

### Adding more tests

Tests live in `backend/tests/`. Follow the existing pattern in `test_main.py`:

```python
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_your_endpoint():
    response = client.get("/your-endpoint")
    assert response.status_code == 200
```

For tests that need a database, you would set up a test database or mock the `get_db` dependency.

## Frontend Build Check

The frontend does not have unit tests, but you can verify it compiles without errors:

```bash
cd frontend
npm run build
```

A successful build means:
- All TypeScript types are correct
- All imports resolve
- No unused variables flagged by the strict compiler
- Vite can bundle the output

## Manual Testing Walkthrough

Use this step-by-step flow to manually verify the full platform works end-to-end.

### Prerequisites

1. Docker Desktop is running
2. All containers are up: `docker-compose up --build -d`
3. Frontend dev server is running: `cd frontend && npm run dev`
4. Open http://localhost:5173 in your browser

### Step 1: Dashboard

**What to check:**
- The Dashboard page loads with four stat cards (Total Samples, IOCs Extracted, YARA Rules Generated, Pending Analysis)
- The "Recent Submissions" table shows either sample data or the empty state message
- The "Upload Sample" button links to the Sample Explorer page

**Screenshot:** `screenshots/01-dashboard.png`

### Step 2: Theme Toggle

**What to check:**
- Click the theme toggle icon in the top-right header bar
- The entire UI should smoothly transition between dark and light modes
- Refresh the page — your theme choice should persist
- All text should be readable in both themes (no white-on-white or invisible borders)

**Screenshots:**
- `screenshots/02-theme-dark.png`
- `screenshots/03-theme-light.png`

### Step 3: Upload a Sample

**What to check:**
- Navigate to Sample Explorer
- Click "Choose File" and select any `.exe` file (you can use the test sample generator)
- Click "Upload Sample"
- The scan result should appear showing classification (MALICIOUS/BENIGN), risk score, SHA256 hash, and YARA matches
- If the backend is not running, an error message should appear (not a blank page)

**Screenshot:** `screenshots/04-upload-result.png`

### Step 4: Generate a Test Sample

If you don't have a real PE file to test with, use the included test sample generator:

```bash
cd scripts
python generate_test_samples.py
```

This creates synthetic PE-like files in the `scripts/` directory that you can upload.

### Step 5: Static Analysis

**What to check:**
- Navigate to Static Analysis
- Enter a Sample UUID (from a previous upload)
- Click "Analyze"
- Results should show: PE Headers table, Sections table with entropy values, Heuristics panel, Extracted Strings

**Screenshot:** `screenshots/05-static-analysis.png`

### Step 6: Memory Analysis

**What to check:**
- Navigate to Memory Forensics
- Enter a Sample UUID
- Click "Analyze"
- If memory data exists: Process tree should render, injected processes should be highlighted in red
- If no memory data: "No process tree data available" message

**Screenshot:** `screenshots/06-memory-analysis.png`

### Step 7: Detection Rules

**What to check:**
- Navigate to Detection Rules
- Enter a Sample UUID
- Click "Generate Rules"
- Two code panels should appear: one with a YARA rule, one with a Sigma rule

**Screenshot:** `screenshots/07-detection-rules.png`

### Step 8: Threat Reports

**What to check:**
- Navigate to Threat Reports
- Enter a SHA256 hash
- Click "Fetch Report"
- A report card should appear with the executive summary, risk score, and classification

**Screenshot:** `screenshots/08-threat-report.png`

### Step 9: API Documentation

**What to check:**
- Open http://localhost:8000/api/v1/docs
- Verify all endpoints are listed and grouped by module
- Try executing a `GET /health` request directly from the Swagger UI

**Screenshot:** `screenshots/09-api-docs.png`

## Screenshot Naming Convention

Save all screenshots in a `screenshots/` folder at the project root:

```
screenshots/
├── 01-dashboard.png
├── 02-theme-dark.png
├── 03-theme-light.png
├── 04-upload-result.png
├── 05-static-analysis.png
├── 06-memory-analysis.png
├── 07-detection-rules.png
├── 08-threat-report.png
└── 09-api-docs.png
```

Add `screenshots/` to the repo so they show up on GitHub. You can reference them in the README if you want.

## CI/CD

The project includes GitHub Actions workflows in `.github/workflows/`:

- **CI** — Runs on push/PR, installs dependencies, runs `pytest`
- **Lint** — Runs ESLint on the frontend code

These run automatically when you push to GitHub.
