# Deployment

## Current state: local / trusted-network use only

ASIF is currently run locally (Streamlit dashboards on `localhost:8501`, FastAPI on `localhost:8000`) and hasn't been hardened for public deployment — see [SECURITY.md](SECURITY.md) for specifics. Named API keys now gate agent registration/scanning and production monitoring (both the dashboard's "Agent Operations" page and the 4 `/monitoring/*` API endpoints), but that's label-plus-secret access control, not RBAC or rate limiting, and CORS/error responses still need explicit configuration (`CORS_ALLOWED_ORIGINS`) before exposure beyond a trusted network. The threat catalog itself (`/threats`, `/stats`, Intelligence/Catalog dashboards) is intentionally public and unauthenticated.

## Running it today

```bash
# Dashboards
streamlit run dashboard/main.py

# API
python api/app.py   # or: uvicorn api.app:app --host 0.0.0.0 --port 8000

# Orchestrator (scheduled collection)
python orchestrator.py
```

If you expose any of these beyond your own machine, still put them behind a reverse proxy or VPN. The named API keys (see [SECURITY.md](SECURITY.md#authentication-named-api-keys)) protect agent registration/scanning and production monitoring, but there's no rate limiting and no key expiry, and the Streamlit gate doesn't re-check a key on every click within an already-unlocked session — treat network isolation as the primary defense and API keys as a second layer, not a replacement for one.

## Async scans have no job persistence across a restart

`POST /scan` runs the actual test in a background thread of the API's own process (FastAPI `BackgroundTasks`), not a real job queue — deliberate, not built for this project's scale (see `core/scan_store.py`). The dashboard's "Run Scan" button runs synchronously in the Streamlit process instead, with the same underlying limitation: neither survives a restart mid-scan.

**If the API/dashboard process restarts while a `scan_results` row is `status='running'`, that scan is lost silently** — the row stays stuck at `running` forever, with no automatic recovery or resumption, and no built-in staleness detection (a `running` scan doesn't "time out" on its own). If you gate CI/CD on `GET /scan/results/{id}`, treat a `running` scan noticeably older than the expected scan duration as effectively failed and re-trigger it yourself — see [API_DOCUMENTATION.md](API_DOCUMENTATION.md#scan-endpoints) for the full status/`vulnerability_score` semantics.

## Planned

Docker/Kubernetes packaging, RBAC, and encryption at rest are on the roadmap (see [ROADMAP.md](ROADMAP.md)) but not implemented yet.
