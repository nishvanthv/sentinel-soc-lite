# Sentinel SOC Lite architecture

Authentication events -> bounded validation -> UTC normalization -> event persistence -> deterministic detection -> evidence-bearing alerts -> incident triage -> analyst disposition.

- src/log_parser.py: bounded parser for the legacy sample format.
- src/engine.py: password-spraying and distributed-brute-force rules.
- src/api.py: FastAPI ingestion, summary, alert and incident endpoints.
- src/models.py: SQLAlchemy event, alert and incident persistence.
- frontend/: React triage dashboard.

Legacy timestamps have no timezone field and are explicitly interpreted as UTC. API ingestion requires an explicit timezone offset.

This is an educational defensive analytics project, not a production SIEM. No automatic blocking or account disabling is performed. Production use requires authentication, authorization, migrations, retention, TLS, secrets management, rate limiting and audit controls.
