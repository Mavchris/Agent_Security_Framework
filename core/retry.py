"""
Shared retry-with-exponential-backoff helper.

Originally scrapers-only (scrapers/base_scraper.py); generalized to live
here once testing/agent_scanner.py needed the same retry loop for
agent.query() calls (transient network/rate-limit failures during a
scan must not be silently miscounted as "agent resisted the attack" -
see testing/agent_wrappers.py's TransientAgentError). The function itself
was always call-shape-agnostic (any zero-arg callable, any exception
tuple) - only the module's location and its scraper-flavored default
were specific to one caller.
"""

import logging
import time

import requests

logger = logging.getLogger(__name__)

DEFAULT_RETRYABLE_EXCEPTIONS = (requests.exceptions.RequestException,)


def request_with_retry(request_fn, retries=3, base_delay=2, retry_on=DEFAULT_RETRYABLE_EXCEPTIONS):
    """
    Call request_fn() and retry on failure with exponential backoff.

    Args:
        request_fn: zero-arg callable that performs the call and returns
            its result (e.g. lambda: requests.get(url, timeout=10), or
            lambda: agent.query(prompt)).
        retries: number of attempts before giving up (default 3).
        base_delay: seconds to wait before the first retry; doubles each
            subsequent attempt (e.g. 2s, 4s, 8s for base_delay=2).
        retry_on: exception type(s) considered transient/retryable.
            Defaults to requests.exceptions.RequestException (timeouts,
            connection errors, DNS failures, etc) - pass a different
            tuple for a non-HTTP caller (e.g. testing.agent_wrappers.
            TransientAgentError for LLM/agent queries).

    Returns:
        Whatever request_fn() returns on the attempt that succeeds.

    Raises:
        The last exception if every attempt fails.
    """
    last_exc = None

    for attempt in range(1, retries + 1):
        try:
            return request_fn()
        except retry_on as e:
            last_exc = e
            if attempt < retries:
                delay = base_delay * (2 ** (attempt - 1))
                logger.warning(
                    "Attempt %d/%d failed (%s) - retrying in %ds",
                    attempt, retries, e, delay,
                )
                time.sleep(delay)
            else:
                logger.error("All %d attempts failed: %s", retries, e)

    raise last_exc
