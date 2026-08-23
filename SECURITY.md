# Security Policy

## Responsible disclosure

If you find a security issue in ASIF itself (not in the third-party threats it catalogs), please open a private [GitHub Security Advisory](https://github.com/Mavchris/Agent_Security_Framework/security/advisories) rather than a public issue. We'll acknowledge and address it as time allows — this is an academic/research project maintained outside a formal SLA.

## Current security posture

- SQL queries are parameterized throughout the codebase (`?` placeholders) — no known SQL injection vectors.
- No hardcoded secrets in the code or in git history; API keys are read from `config/.env.local` (git-ignored) via environment variables.
- No authentication or authorization on the FastAPI (`api/app.py`) or Streamlit layers — anyone who can reach the process can read/query the threat database and trigger a scan. Do not expose these outside a trusted network.
- CORS is not configured on the API (no `CORSMiddleware`) — there's no explicit cross-origin policy either way.
- API error responses currently return raw exception text (`str(e)`) to the caller, which can leak internal details; avoid exposing the API publicly until this is tightened.

## What's not covered

Authentication, RBAC, and encryption at rest are on the roadmap (see [ROADMAP.md](ROADMAP.md)) but not implemented yet. Treat this as a local/trusted-network tool for now, not a hardened production service.
