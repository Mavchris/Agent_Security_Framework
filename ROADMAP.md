# Roadmap

The full status breakdown (completed / in progress / planned) lives in the README's [Status & Roadmap](README.md#status-roadmap) section rather than being duplicated here — that's the single source of truth so the two don't drift apart.

## Near-term priorities

Derived from the [Known Limitations](README.md#known-limitations) audit:

1. Wire `misp_scraper.py` into `pipeline/process.py`, or drop it from the codebase if it won't be maintained.
2. Add retry/backoff for scraper HTTP calls (currently: log and skip on failure).
3. Get the orchestrator running unattended over an extended period to build a real reliability track record.
4. Review the 114 threats currently `threat_type=other, ai_relevant=true` (see README Known Limitations) as candidates for a future taxonomy refinement — they're confirmed AI-relevant but don't fit one of the 9 categories cleanly.
5. `dashboard/pages/operations.py`'s `get_all_threats()` runs `SELECT * FROM threats` just to compute `len(threats)` for the "Scanning agent X against N threats" status message — loads every column of every row into Python memory for what should be a `SELECT COUNT(*)`. Found during the index/cache vague, deliberately not fixed there to keep that vague's scope to indexing and caching.
6. `pipeline/process.py`'s `run_pipeline()` is a 260-line function mixing scrape/classify/store in one body (9 near-identical scraper blocks, then classification, then DB storage). Deliberately left unrefactored during the test-coverage vague that added `tests/test_pipeline.py`/`tests/test_orchestrator.py` (see that vague's checkpoint): refactoring and adding tests in the same pass is riskier than either alone, and this file has a real production incident history (the `UnicodeEncodeError` that crashed the orchestrator for 5 months). It's now covered by tests as-is with the 9 scrapers mocked, so a future refactor into separate scrape/classify/store functions has a safety net to refactor against - do it as its own, test-covered change, not bundled with unrelated work.

## Named API key follow-ups

Identified while shipping named API keys (see [SECURITY.md](SECURITY.md#authentication-named-api-keys)) but not addressed as part of that work at the time - both since done, in a later session:

1. ~~Rate limiting on API keys.~~ **Done**: per-key (not per-IP - see [SECURITY.md](SECURITY.md#rate-limiting) for why per-IP wasn't judged necessary against key brute-forcing given 256-bit key entropy), in-memory fixed-window counters in `core/rate_limit.py`, applied via a `rate_limited(category)` FastAPI dependency in `api/app.py`. Configurable thresholds per endpoint category (`scan`/`read`/`write`/`log_request`, the last unlimited by default) via `RATE_LIMIT_*` environment variables.
2. ~~Automatic expiration of API keys.~~ **Done**: `api_keys.expires_at` (nullable, `NULL` = never expires, backward compatible with every key issued before this column existed), settable via `create_api_key.py --expires-in-days N`, checked by `verify_key`. `scripts/maintenance/list_api_keys.py` added alongside it (previously no way to see what keys exist without querying `data/auth.db` directly).

## Documentation debt

Identified while adding the `/scan` and `/agents` endpoints this session — same treatment as every other limitation found along the way, not skipped just because it surfaced near the end of the vague:

1. ~~`API_DOCUMENTATION.md` needs a full audit.~~ **Done** (session following named API keys): every endpoint's request/response examples verified against a real running `uvicorn` server, the fictional `{"data": ..., "status": ..., "message": ...}` envelope removed throughout, `/health` and `/monitoring/health/{agent}` corrected to their real fields, version corrected to `1.0.0`, the nonexistent `--port`/`--debug` CLI flags replaced with the real fixed-port behavior, and the stopgap ⚠️ warning removed. Also fixed along the way: `GET /threat-types` was a hardcoded list that had silently drifted from `core/classifier.py`'s real taxonomy - it now reads `ImprovedThreatClassifier.categories` directly, with `tests/test_api.py::TestThreatTypesTaxonomyConsistency` guarding against future drift.

## Future dedicated test vague

Current coverage is **84% overall** (up from 36% - see README [Known Limitations](README.md#known-limitations) for the full by-module breakdown), after several vagues each closing out one gap from the list this section used to track:

1. ~~`pipeline/process.py` — the ETL core, 212 lines at 0% coverage.~~ **Done**: 88%. `run_pipeline()` (260 lines, 9 near-identical scrape blocks + classify + store inline) deliberately tested as-is rather than refactored in the same pass - see item 6 under Near-term priorities above for that refactor, tracked separately with this test file as its safety net.
2. ~~`api/app.py` — the public HTTP surface.~~ **Done**: 93%, across the named-API-key, rate-limiting, and doc-audit vagues - every endpoint, not just `POST /monitoring/log-request`.
3. ~~`orchestrator.py` — the scheduling/run-loop entry point.~~ **Done**: 87%. Also fixed along the way (found while writing these tests, not planned beforehand): `get_threat_count()` used to return `0` on a DB read failure (indistinguishable from a real empty table) instead of `None`; `run_weekly_pipeline()`'s 3 steps each swallowed their own exceptions with no way for the caller to know, so a run where all 3 failed still logged "✅ réussi" and updated no metric - both now surfaced correctly, and a resource leak (DB connections never closed on a query-error path in `get_threat_count`/`validate_data_quality`/`deduplicate_threats`/`generate_weekly_report`) found and fixed in the process.
4. `testing/` (`agent_scanner.py` 83%, `agent_wrappers.py` 49%, `cli.py` 0%) — the agent-scanning toolchain itself. Partially done; `cli.py` still entirely untested.
5. `dashboard/pages/*` — partially resolved: `AppTest`-based tests (`tests/test_operations_page.py`, `tests/test_main_page.py`) turned out to make `operations.py` (81%) and `main.py` (88%) visible to `pytest --cov` after all, contrary to what this item used to claim about Streamlit multipage files being structurally invisible to coverage tooling. `catalog.py` and `intelligence.py` still have no `AppTest`-based tests (only their `@st.cache_data` TTLs are tested, via an isolated subprocess that coverage.py can't see into - see `tests/test_dashboard_cache.py`) and so still don't appear in the report at all.

## Longer-term (see README for full list)

Full user accounts/RBAC (named API keys for sensitive actions already ship — see [SECURITY.md](SECURITY.md#authentication-named-api-keys)), ML-based classification, Docker/Kubernetes packaging.
