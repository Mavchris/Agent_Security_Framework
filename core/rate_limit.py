"""
Per-API-key rate limiting (see SECURITY.md, ROADMAP.md's named-API-key
follow-ups).

In-memory, fixed-window counters keyed by (key_label, category) - no new
dependency (no slowapi/redis). This project already avoids extra
infrastructure for OpenCTI, the database, and scan execution, and any
by-key limiter needs a custom key function anyway (rate-limiting
libraries key by client IP by default) - so hand-rolling the small
amount of actual logic here is simpler than gluing a library to a use
case it isn't built for.

State is process-local and does not survive a restart - the same
accepted tradeoff already made for scan_store's 'running' rows (see
DEPLOYMENT.md), appropriate at this project's single-process scale.

Deliberately per-key only, not per-IP: an unauthenticated guess at an
unknown key has no valid label to count against, so this does not (and
is not meant to) defend against key brute-forcing - see SECURITY.md's
authentication section for why that gap is judged acceptable (256-bit
key entropy already makes brute force infeasible regardless of any
request-rate limit).
"""

import os
import threading
import time
from typing import Dict, Tuple

from fastapi import HTTPException


def _category_from_env(env_prefix: str, default_max: int, default_window: int) -> Dict[str, int]:
    return {
        "max_requests": int(os.getenv(f"RATE_LIMIT_{env_prefix}_MAX_REQUESTS", default_max)),
        "window_seconds": int(os.getenv(f"RATE_LIMIT_{env_prefix}_WINDOW_SECONDS", default_window)),
    }


# A category with max_requests <= 0 is unlimited - used below for
# log_request by default (see SECURITY.md: rate-limiting the endpoint
# meant to receive every production agent interaction would risk
# silently dropping monitoring data exactly when an agent's behavior
# spikes, the scenario monitoring exists to catch).
CATEGORIES: Dict[str, Dict[str, int]] = {
    "scan": _category_from_env("SCAN", default_max=10, default_window=3600),
    "read": _category_from_env("READ", default_max=120, default_window=60),
    "write": _category_from_env("WRITE", default_max=20, default_window=60),
    "log_request": _category_from_env("LOG_REQUEST", default_max=0, default_window=60),
    # A single call to a real external agent/LLM API - unlike "read"
    # (local SQLite only), so not as free as 120/min, but 653x cheaper
    # than a full scan (1 call vs up to 653), so it doesn't need "scan"'s
    # tight hourly cap either. Same threshold as "write": both are
    # "costs something externally, still fine to hit often while
    # iterating" (a user tweaking agent config and re-testing).
    "test_connection": _category_from_env("TEST_CONNECTION", default_max=20, default_window=60),
}

_lock = threading.Lock()
# (key_label, category) -> (count_in_window, window_start_monotonic)
_counters: Dict[Tuple[str, str], Tuple[int, float]] = {}


def check_rate_limit(key_label: str, category: str) -> None:
    """Raise HTTPException(429) if key_label has exceeded its quota for
    category in the current fixed window; otherwise record this request
    and return. A category configured with max_requests <= 0 is
    unlimited and always passes without recording anything."""
    limits = CATEGORIES[category]
    max_requests = limits["max_requests"]
    if max_requests <= 0:
        return

    window_seconds = limits["window_seconds"]
    now = time.monotonic()
    counter_key = (key_label, category)

    with _lock:
        count, window_start = _counters.get(counter_key, (0, now))
        if now - window_start >= window_seconds:
            count, window_start = 0, now

        if count >= max_requests:
            retry_after = max(1, int(window_start + window_seconds - now + 0.999))
            raise HTTPException(
                status_code=429,
                detail=(
                    f"Rate limit exceeded for this API key. "
                    f"Retry after {retry_after} second(s)."
                ),
                headers={"Retry-After": str(retry_after)},
            )

        _counters[counter_key] = (count + 1, window_start)


def reset() -> None:
    """Test-only: clear every counter so tests don't leak rate-limit
    state into each other via a shared key label or process-wide state."""
    with _lock:
        _counters.clear()
