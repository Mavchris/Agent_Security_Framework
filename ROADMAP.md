# Roadmap

The full status breakdown (completed / in progress / planned) lives in the README's [Status & Roadmap](README.md#status-roadmap) section rather than being duplicated here — that's the single source of truth so the two don't drift apart.

## Near-term priorities

Derived from the [Known Limitations](README.md#known-limitations) audit:

1. Wire `misp_scraper.py` into `pipeline/process.py`, or drop it from the codebase if it won't be maintained.
2. Add retry/backoff for scraper HTTP calls (currently: log and skip on failure).
3. Move query parameters to a Pydantic request body on `POST /monitoring/log-request`.
4. Get the orchestrator running unattended over an extended period to build a real reliability track record.
5. Review the 114 threats currently `threat_type=other, ai_relevant=true` (see README Known Limitations) as candidates for a future taxonomy refinement — they're confirmed AI-relevant but don't fit one of the 9 categories cleanly.

## Future dedicated test vague

Current coverage is 30% overall (see README [Known Limitations](README.md#known-limitations) for the full by-module breakdown) and concentrated in the scrapers/classifier that already have tests. The following are untested (0%) and, in order of volume/criticality, are the priority targets for a future vague focused specifically on tests:

1. `pipeline/process.py` — the ETL core, 212 lines at 0% coverage.
2. `api/app.py` — the public HTTP surface, a priority if the project is ever exposed beyond local use.
3. `orchestrator.py` — the scheduling/run-loop entry point.
4. `testing/` (`agent_scanner.py`, `agent_wrappers.py`, `cli.py`) — the agent-scanning toolchain itself.
5. `dashboard/pages/*` — structurally excluded from standard coverage tooling (Streamlit multipage files are launched by Streamlit's own runner, not imported as a Python package), so this would need a different measurement approach (e.g. `AppTest`-based tests) rather than plain `pytest --cov`.

## Longer-term (see README for full list)

Authentication, ML-based classification, Docker/Kubernetes packaging.
