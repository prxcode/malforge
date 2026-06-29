# API Reference

The full interactive API documentation is available at `/api/v1/docs` when the server is running.

## Domains

### Authentication (`/api/v1/auth`)
- `POST /login`: Get JWT access token
- `GET /me`: Get current user info

### Samples (`/api/v1/samples`)
- `GET /`: List samples
- `POST /`: Upload a new sample
- `GET /{id}`: Retrieve sample metadata

### Analysis (`/api/v1/analysis`)
- `POST /static/{sample_id}`: Trigger static analysis
- `GET /static/{sample_id}`: Retrieve static analysis results
- `POST /memory/{sample_id}`: Trigger memory analysis

### Detection & IOCs
- `GET /ioc/{sample_id}`: Retrieve extracted IOCs
- `POST /rules/generate`: Generate YARA/Sigma rules
