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

## Planned

Docker/Kubernetes packaging, RBAC, and encryption at rest are on the roadmap (see [ROADMAP.md](ROADMAP.md)) but not implemented yet.
