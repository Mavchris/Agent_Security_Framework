# Roadmap

The full status breakdown (completed / in progress / planned) lives in the README's [Status & Roadmap](README.md#status-roadmap) section rather than being duplicated here — that's the single source of truth so the two don't drift apart.

## Near-term priorities

Derived from the [Known Limitations](README.md#known-limitations) audit:

1. Wire `misp_scraper.py` into `pipeline/process.py`, or drop it from the codebase if it won't be maintained.
2. Add retry/backoff for scraper HTTP calls (currently: log and skip on failure).
3. Get the orchestrator running unattended over an extended period to build a real reliability track record.
4. Review the 114 threats currently `threat_type=other, ai_relevant=true` (see README Known Limitations) as candidates for a future taxonomy refinement — they're confirmed AI-relevant but don't fit one of the 9 categories cleanly.

## Named API key follow-ups

Identified while shipping named API keys this session (see [SECURITY.md](SECURITY.md#authentication-named-api-keys)) but deliberately not addressed as part of that work:

1. Rate limiting on API keys — nothing currently stops a valid (or repeatedly-guessed) key from being hammered against `/monitoring/*`.
2. Automatic expiration of API keys — keys are active until manually deactivated via `scripts/maintenance/deactivate_api_key.py`; there's no TTL or forced rotation.

## Documentation debt

Identified while adding the `/scan` and `/agents` endpoints this session — same treatment as every other limitation found along the way, not skipped just because it surfaced near the end of the vague:

1. `API_DOCUMENTATION.md` needs a full audit. Most of its pre-existing response examples are fictional — a `{"data": ..., "status": ..., "message": ...}` response envelope no real endpoint actually returns, invented fields on `/health` (`uptime_seconds`, `cpu_usage`, ...), a "2.0" version that doesn't match the real root endpoint, nonexistent CLI flags (`--port`, `--debug`) — this goes well beyond the single decorative `/scan` mention in README's architecture diagram that was already fixed. A one-off ⚠️ warning was added inline (Response Format section) as a stopgap while writing this session's new endpoint sections with real, verified examples; the rest of the document still needs the same treatment.

## Future dedicated test vague

Current coverage is 36% overall (see README [Known Limitations](README.md#known-limitations) for the full by-module breakdown) and concentrated in the scrapers/classifier/`POST /monitoring/log-request` paths that already have tests. The following are still largely or entirely untested and, in order of volume/criticality, are the priority targets for a future vague focused specifically on tests:

1. `pipeline/process.py` — the ETL core, 212 lines at 0% coverage.
2. `api/app.py` — the public HTTP surface. `POST /monitoring/log-request` got a test in Vague 3c (30% coverage), but the `GET` endpoints (`/threats`, `/stats`, `/threat-types`, `/sources`, `/monitoring/stats/{agent}`, etc.) remain untested — a priority if the project is ever exposed beyond local use.
3. `orchestrator.py` — the scheduling/run-loop entry point.
4. `testing/` (`agent_scanner.py`, `agent_wrappers.py`, `cli.py`) — the agent-scanning toolchain itself.
5. `dashboard/pages/*` — structurally excluded from standard coverage tooling (Streamlit multipage files are launched by Streamlit's own runner, not imported as a Python package), so this would need a different measurement approach (e.g. `AppTest`-based tests) rather than plain `pytest --cov`.

## Longer-term (see README for full list)

Full user accounts/RBAC (named API keys for sensitive actions already ship — see [SECURITY.md](SECURITY.md#authentication-named-api-keys)), ML-based classification, Docker/Kubernetes packaging.
