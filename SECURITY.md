# Security Policy

## Responsible disclosure

If you find a security issue in ASIF itself (not in the third-party threats it catalogs), please open a private [GitHub Security Advisory](https://github.com/Mavchris/Agent_Security_Framework/security/advisories) rather than a public issue. We'll acknowledge and address it as time allows — this is an academic/research project maintained outside a formal SLA.

## Current security posture

- SQL queries are parameterized throughout the codebase (`?` placeholders) — no known SQL injection vectors.
- No hardcoded secrets in the code or in git history; API keys are read from `config/.env.local` (git-ignored) via environment variables.
- No authentication or authorization on the FastAPI (`api/app.py`) or Streamlit layers — anyone who can reach the process can read/query the threat database and trigger a scan. Do not expose these outside a trusted network.
- CORS is configured via `CORSMiddleware`, restrictive by default: no origins are allowed unless the `CORS_ALLOWED_ORIGINS` environment variable is set (comma-separated list) — there is no `allow_origins=["*"]` anywhere. Review and set this explicitly before any deployment where a browser-based client on a different origin needs to call the API.
- API errors are handled by a global FastAPI exception handler: the real exception (with traceback) is logged server-side via `logging`, and the client only ever receives a generic `{"error": "Internal server error", "status": "error"}` with HTTP 500 — no internal detail (file paths, SQL structure) is exposed. `GET /health` is the one intentional exception: it still returns HTTP 200 with `{"status": "unhealthy", "error": "Internal server error"}` on failure, since a health check reporting itself degraded is a normal response for monitoring tools, not a server error.

## What's not covered

Authentication, RBAC, and encryption at rest are on the roadmap (see [ROADMAP.md](ROADMAP.md)) but not implemented yet. Treat this as a local/trusted-network tool for now, not a hardened production service.
