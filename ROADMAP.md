# Roadmap

The full status breakdown (completed / in progress / planned) lives in the README's [Status & Roadmap](README.md#status-roadmap) section rather than being duplicated here — that's the single source of truth so the two don't drift apart.

## Near-term priorities

Derived from the [Known Limitations](README.md#known-limitations) audit:

1. Wire `misp_scraper.py` into `pipeline/process.py`, or drop it from the codebase if it won't be maintained.
2. Add retry/backoff for scraper HTTP calls (currently: log and skip on failure).
3. Move query parameters to a Pydantic request body on `POST /monitoring/log-request`.
4. Get the orchestrator running unattended over an extended period to build a real reliability track record.
5. Review the 114 threats currently `threat_type=other, ai_relevant=true` (see README Known Limitations) as candidates for a future taxonomy refinement — they're confirmed AI-relevant but don't fit one of the 9 categories cleanly.

## Longer-term (see README for full list)

Authentication, ML-based classification, Docker/Kubernetes packaging.
