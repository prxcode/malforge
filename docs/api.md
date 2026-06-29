# API Reference

Base URL: `http://localhost:8000`

Interactive docs (Swagger UI): `http://localhost:8000/api/v1/docs`

## Health Check

### `GET /health`

Returns the API health status.

**Response:**
```json
{
  "status": "ok",
  "service": "MAP — Malware Analysis Platform"
}
```

## Samples

### `POST /api/v1/samples/`

Upload a new malware sample or memory dump.

**Request:**
```
Content-Type: multipart/form-data
file: <binary_file>
```

**Response (201):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "filename": "suspicious.exe",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb924...",
  "md5": "d41d8cd98f00b204e9800998ecf8427e",
  "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
  "file_size": 245760,
  "status": "pending",
  "created_at": "2026-06-29T12:00:00Z"
}
```

### `GET /api/v1/samples/`

List all uploaded samples with pagination.

**Query Parameters:**
- `skip` (int, default: 0) — Number of records to skip
- `limit` (int, default: 50) — Max records to return

**Response (200):**
```json
{
  "items": [
    {
      "id": "550e8400-...",
      "filename": "suspicious.exe",
      "sha256": "e3b0c44...",
      "status": "completed",
      "created_at": "2026-06-29T12:00:00Z"
    }
  ],
  "total": 1
}
```

### `GET /api/v1/samples/{id}`

Retrieve metadata for a specific sample by UUID.

**Response (200):** Same as single item from the list above.

## Static Analysis

### `POST /api/v1/analysis/static/{sample_id}`

Trigger static analysis for a sample. This dispatches a Celery task.

**Response (202):**
```json
{
  "task_id": "abc123",
  "status": "queued"
}
```

### `GET /api/v1/analysis/static/{sample_id}`

Get static analysis results.

**Response (200):**
```json
{
  "sample_id": "550e8400-...",
  "headers": {
    "machine": "AMD64",
    "timestamp": "2024-01-15 10:30:00",
    "entry_point": "0x1000",
    "image_base": "0x400000"
  },
  "sections": [
    {
      "name": ".text",
      "virtual_size": 4096,
      "entropy": 6.2
    },
    {
      "name": ".rsrc",
      "virtual_size": 8192,
      "entropy": 7.8
    }
  ],
  "strings": [
    "http://malicious-c2.com/beacon",
    "CreateRemoteThread",
    "VirtualAllocEx"
  ],
  "heuristics": [
    {
      "rule": "PROCESS_INJECTION",
      "description": "Uses CreateRemoteThread + VirtualAllocEx (process injection pattern)",
      "severity": "high"
    }
  ]
}
```

## Memory Analysis

### `POST /api/v1/memory/{sample_id}`

Trigger Volatility 3 memory analysis.

**Response (202):**
```json
{
  "task_id": "def456",
  "status": "queued"
}
```

### `GET /api/v1/memory/{sample_id}`

Get memory analysis results.

**Response (200):**
```json
{
  "sample_id": "550e8400-...",
  "processes": [
    { "pid": 4, "name": "System" },
    { "pid": 512, "name": "csrss.exe" },
    { "pid": 1234, "name": "svchost.exe" }
  ],
  "injected_processes": ["svchost.exe"],
  "network_connections": [
    {
      "pid": 1234,
      "local_addr": "192.168.1.5:49152",
      "remote_addr": "185.220.101.45:443",
      "state": "ESTABLISHED"
    }
  ]
}
```

## IOC Extraction

### `GET /api/v1/ioc/{sample_id}`

Get extracted Indicators of Compromise.

**Response (200):**
```json
{
  "sample_id": "550e8400-...",
  "iocs": {
    "ipv4": ["185.220.101.45", "10.0.0.1"],
    "domains": ["malicious-c2.com", "update.evil.net"],
    "urls": ["http://malicious-c2.com/beacon"],
    "emails": [],
    "file_paths": ["C:\\Windows\\Temp\\payload.dll"],
    "registry_keys": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]
  }
}
```

## Detection Rules

### `POST /api/v1/detection/generate-rule`

Generate YARA and Sigma rules from a sample's analysis results.

**Request:**
```json
{
  "sample_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response (200):**
```json
{
  "yara_rule": "rule suspicious_sample {\n  strings:\n    $s1 = \"CreateRemoteThread\"\n    $s2 = \"VirtualAllocEx\"\n  condition:\n    all of them\n}",
  "sigma_rule": "title: Suspicious Process Injection\nstatus: experimental\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains:\n      - 'CreateRemoteThread'\n  condition: selection"
}
```

## Reports

### `GET /api/v1/report/{hash}`

Get the full threat intelligence report for a sample by its SHA256 hash.

**Response (200):**
```json
{
  "sample_id": "550e8400-...",
  "overall_score": 85,
  "classification": "MALICIOUS",
  "summary": {
    "static_analysis": "High entropy sections detected, suspicious API imports found",
    "ioc_count": 15,
    "yara_matches": ["process_injection", "packed_binary"],
    "risk_factors": ["Process injection APIs", "Packed .text section", "C2 communication"]
  }
}
```

## Authentication

### `POST /api/v1/auth/login`

Get a JWT access token.

**Request:**
```json
{
  "username": "admin",
  "password": "password"
}
```

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer"
}
```

### `GET /api/v1/auth/me`

Get current authenticated user info. Requires `Authorization: Bearer <token>` header.

## Error Responses

All endpoints return errors in this format:

```json
{
  "detail": "Sample not found"
}
```

Common status codes:
- `400` — Bad request (invalid input)
- `404` — Resource not found
- `422` — Validation error (Pydantic)
- `500` — Internal server error
