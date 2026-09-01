# Roadmap

The full status breakdown (completed / in progress / planned) lives in the README's [Status & Roadmap](README.md#status-roadmap) section rather than being duplicated here — that's the single source of truth so the two don't drift apart.

## Near-term priorities

Derived from the [Known Limitations](README.md#known-limitations) audit:

1. Wire `misp_scraper.py` into `pipeline/process.py`, or drop it from the codebase if it won't be maintained.
2. Add retry/backoff for scraper HTTP calls (currently: log and skip on failure).
3. Get the orchestrator running unattended over an extended period to build a real reliability track record.
4. Review the 114 threats currently `threat_type=other, ai_relevant=true` (see README Known Limitations) as candidates for a future taxonomy refinement — they're confirmed AI-relevant but don't fit one of the 9 categories cleanly.

## Named API key follow-ups

Identified while shipping named API keys (see [SECURITY.md](SECURITY.md#authentication-named-api-keys)) but not addressed as part of that work at the time - both since done, in a later session:

1. ~~Rate limiting on API keys.~~ **Done**: per-key (not per-IP - see [SECURITY.md](SECURITY.md#rate-limiting) for why per-IP wasn't judged necessary against key brute-forcing given 256-bit key entropy), in-memory fixed-window counters in `core/rate_limit.py`, applied via a `rate_limited(category)` FastAPI dependency in `api/app.py`. Configurable thresholds per endpoint category (`scan`/`read`/`write`/`log_request`, the last unlimited by default) via `RATE_LIMIT_*` environment variables.
2. ~~Automatic expiration of API keys.~~ **Done**: `api_keys.expires_at` (nullable, `NULL` = never expires, backward compatible with every key issued before this column existed), settable via `create_api_key.py --expires-in-days N`, checked by `verify_key`. `scripts/maintenance/list_api_keys.py` added alongside it (previously no way to see what keys exist without querying `data/auth.db` directly).

## Documentation debt

Identified while adding the `/scan` and `/agents` endpoints this session — same treatment as every other limitation found along the way, not skipped just because it surfaced near the end of the vague:

1. ~~`API_DOCUMENTATION.md` needs a full audit.~~ **Done** (session following named API keys): every endpoint's request/response examples verified against a real running `uvicorn` server, the fictional `{"data": ..., "status": ..., "message": ...}` envelope removed throughout, `/health` and `/monitoring/health/{agent}` corrected to their real fields, version corrected to `1.0.0`, the nonexistent `--port`/`--debug` CLI flags replaced with the real fixed-port behavior, and the stopgap ⚠️ warning removed. Also fixed along the way: `GET /threat-types` was a hardcoded list that had silently drifted from `core/classifier.py`'s real taxonomy - it now reads `ImprovedThreatClassifier.categories` directly, with `tests/test_api.py::TestThreatTypesTaxonomyConsistency` guarding against future drift.

## Future dedicated test vague

Current coverage is 36% overall (see README [Known Limitations](README.md#known-limitations) for the full by-module breakdown) and concentrated in the scrapers/classifier/`POST /monitoring/log-request` paths that already have tests. The following are still largely or entirely untested and, in order of volume/criticality, are the priority targets for a future vague focused specifically on tests:

1. `pipeline/process.py` — the ETL core, 212 lines at 0% coverage.
2. `api/app.py` — the public HTTP surface. `POST /monitoring/log-request` got a test in Vague 3c (30% coverage), but the `GET` endpoints (`/threats`, `/stats`, `/threat-types`, `/sources`, `/monitoring/stats/{agent}`, etc.) remain untested — a priority if the project is ever exposed beyond local use.
3. `orchestrator.py` — the scheduling/run-loop entry point.
4. `testing/` (`agent_scanner.py`, `agent_wrappers.py`, `cli.py`) — the agent-scanning toolchain itself.
5. `dashboard/pages/*` — structurally excluded from standard coverage tooling (Streamlit multipage files are launched by Streamlit's own runner, not imported as a Python package), so this would need a different measurement approach (e.g. `AppTest`-based tests) rather than plain `pytest --cov`.

## Longer-term (see README for full list)

Full user accounts/RBAC (named API keys for sensitive actions already ship — see [SECURITY.md](SECURITY.md#authentication-named-api-keys)), ML-based classification, Docker/Kubernetes packaging.
