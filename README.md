# Sentinel SOC Lite

An educational defensive security analytics project for authentication telemetry, transparent threat detection and incident triage. This is not a production SIEM and does not automatically block accounts or IPs. Analyst review is required.

## Features
- Bounded parser and input validation for the sample auth.log format.
- Explicit UTC policy for legacy timestamps; timezone-required API events.
- Password-spraying and distributed-brute-force detection rules.
- MITRE ATT&CK technique references and evidence-bearing alerts.
- FastAPI ingestion, summary, alert and incident endpoints.
- SQLAlchemy persistence: PostgreSQL in Docker, SQLite for local development.
- React triage dashboard.
- CSV formula-injection mitigation and regression tests.
- GitHub Actions CI.

## Run locally
Python 3.10+:
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:DATABASE_URL="sqlite:///./sentinel.db"
uvicorn src.api:app --reload
```
API docs: http://localhost:8000/docs

In another terminal:
```powershell
cd frontend
npm install
npm run dev
```
Dashboard expects API at http://localhost:8000.

## Docker
Set a strong password first:
```powershell
$env:POSTGRES_PASSWORD="replace-with-a-long-random-secret"
docker compose up --build
```
Dashboard: http://localhost:5173 | API: http://localhost:8000

## Ingest example
```bash
curl -X POST http://localhost:8000/api/v1/events/ingest -H "Content-Type: application/json" -d '{"events":[{"timestamp":"2026-11-15T09:00:00Z","username":"alice","source_ip":"192.0.2.10","status":"FAILED"},{"timestamp":"2026-11-15T09:00:30Z","username":"bob","source_ip":"192.0.2.10","status":"FAILED"},{"timestamp":"2026-11-15T09:01:00Z","username":"carol","source_ip":"192.0.2.10","status":"FAILED"},{"timestamp":"2026-11-15T09:01:30Z","username":"dave","source_ip":"192.0.2.10","status":"FAILED"},{"timestamp":"2026-11-15T09:02:00Z","username":"erin","source_ip":"192.0.2.10","status":"FAILED"}]}'
```

## Endpoints
- GET /health
- GET /api/v1/summary
- POST /api/v1/events/ingest (maximum 5,000 events per request)
- GET /api/v1/alerts
- GET /api/v1/incidents
- PATCH /api/v1/incidents/{incident_id} (NEW, INVESTIGATING, ESCALATED, RESOLVED)

## Tests
```bash
python -m unittest discover -s tests -v
```

## Known limitations
The API currently has no authentication or role-based authorization. Do not expose it publicly. Schema creation is lightweight; add Alembic migrations before evolving production schemas. Detection evaluates each submitted batch; cross-batch rolling windows require a dedicated processor. Incident records are basic triage records, not mature multi-alert correlation. Add source adapters, pagination, retention, rate limits, audit trails, integration tests and labelled-dataset benchmarks before production use.

See docs/architecture.md and docs/detection-rules.md.
