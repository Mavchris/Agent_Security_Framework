# Deployment

## Current state: local / trusted-network use only

ASIF is currently run locally (Streamlit dashboards on `localhost:8501`, FastAPI on `localhost:8000`) and hasn't been hardened for public deployment — see [SECURITY.md](SECURITY.md) for specifics (no auth; CORS and error responses are sanitized by default but still need explicit configuration - `CORS_ALLOWED_ORIGINS` - before exposure beyond a trusted network).

## Running it today

```bash
# Dashboards
streamlit run dashboard/main.py

# API
python api/app.py   # or: uvicorn api.app:app --host 0.0.0.0 --port 8000

# Orchestrator (scheduled collection)
python orchestrator.py
```

If you expose any of these beyond your own machine, put them behind a reverse proxy with authentication (e.g. Caddy/Nginx with basic auth, or a VPN) — there's nothing built in yet.

## Planned

Docker/Kubernetes packaging and an authentication layer are on the roadmap (see [ROADMAP.md](ROADMAP.md)) but not implemented yet.
