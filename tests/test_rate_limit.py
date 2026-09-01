"""
Unit tests for core/rate_limit.py (per-API-key rate limiting, see
SECURITY.md) and integration tests for the rate_limited() dependency
api/app.py applies per endpoint category.

Every test that touches core.rate_limit.CATEGORIES saves and restores it
in setUp/tearDown, and calls core.rate_limit.reset() - this module-level
state is shared across the whole test process (other test files exercise
the real endpoints under the real default thresholds), so a test here
must never leave an overridden threshold or a stale counter behind for
an unrelated test to trip over.
"""

import sqlite3
import unittest
import uuid
from unittest import mock

from fastapi import HTTPException
from fastapi.testclient import TestClient

import core.rate_limit as rate_limit
from api.app import app
from core.auth import deactivate_key, generate_key

AUTH_DB_PATH = "data/auth.db"
THREATS_DB_PATH = "data/threats.db"
MONITORING_DB_PATH = "data/monitoring.db"


class TestCheckRateLimitUnit(unittest.TestCase):
    """core.rate_limit.check_rate_limit() directly, no HTTP involved."""

    def setUp(self):
        self._orig_categories = dict(rate_limit.CATEGORIES)
        rate_limit.CATEGORIES["unit_a"] = {"max_requests": 3, "window_seconds": 60}
        rate_limit.CATEGORIES["unit_b"] = {"max_requests": 1, "window_seconds": 60}
        rate_limit.CATEGORIES["unit_unlimited"] = {"max_requests": 0, "window_seconds": 60}
        rate_limit.reset()

    def tearDown(self):
        rate_limit.CATEGORIES.clear()
        rate_limit.CATEGORIES.update(self._orig_categories)
        rate_limit.reset()

    def test_allows_up_to_the_limit_then_blocks(self):
        for _ in range(3):
            rate_limit.check_rate_limit("label-1", "unit_a")  # must not raise

        with self.assertRaises(HTTPException) as ctx:
            rate_limit.check_rate_limit("label-1", "unit_a")
        self.assertEqual(ctx.exception.status_code, 429)

    def test_429_includes_a_useful_retry_after(self):
        rate_limit.check_rate_limit("label-2", "unit_b")
        with self.assertRaises(HTTPException) as ctx:
            rate_limit.check_rate_limit("label-2", "unit_b")

        exc = ctx.exception
        self.assertIn("Retry-After", exc.headers)
        retry_after = int(exc.headers["Retry-After"])
        self.assertGreater(retry_after, 0)
        self.assertLessEqual(retry_after, 60)
        self.assertIn("Retry after", exc.detail)
        # Generic, not internal detail (no thresholds/category names leaked)
        self.assertNotIn("unit_b", exc.detail)

    def test_categories_have_independent_counters_for_the_same_label(self):
        rate_limit.check_rate_limit("label-3", "unit_b")  # exhausts unit_b (max 1)
        with self.assertRaises(HTTPException):
            rate_limit.check_rate_limit("label-3", "unit_b")

        # unit_a (max 3) is untouched by unit_b being exhausted
        rate_limit.check_rate_limit("label-3", "unit_a")
        rate_limit.check_rate_limit("label-3", "unit_a")
        rate_limit.check_rate_limit("label-3", "unit_a")
        with self.assertRaises(HTTPException):
            rate_limit.check_rate_limit("label-3", "unit_a")

    def test_labels_have_independent_counters_for_the_same_category(self):
        rate_limit.check_rate_limit("label-a", "unit_b")
        with self.assertRaises(HTTPException):
            rate_limit.check_rate_limit("label-a", "unit_b")

        rate_limit.check_rate_limit("label-b", "unit_b")  # different label, own quota

    def test_window_resets_after_it_elapses(self):
        rate_limit.CATEGORIES["unit_b"] = {"max_requests": 1, "window_seconds": 5}
        with mock.patch("core.rate_limit.time.monotonic") as mock_monotonic:
            mock_monotonic.return_value = 1000.0
            rate_limit.check_rate_limit("label-reset", "unit_b")
            with self.assertRaises(HTTPException):
                rate_limit.check_rate_limit("label-reset", "unit_b")

            mock_monotonic.return_value = 1005.1  # just past the 5s window
            rate_limit.check_rate_limit("label-reset", "unit_b")  # allowed again

    def test_zero_max_requests_is_unlimited(self):
        for _ in range(50):
            rate_limit.check_rate_limit("label-unlimited", "unit_unlimited")  # never raises


class TestRateLimitedDependencyIntegration(unittest.TestCase):
    """Through real HTTP endpoints via TestClient, not the bare function -
    covers the actual dependency wiring in api/app.py (rate_limited())."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def setUp(self):
        self._orig_categories = dict(rate_limit.CATEGORIES)
        rate_limit.reset()
        self.label = f"ratelimit-test-{uuid.uuid4().hex[:8]}"
        self.raw_key = generate_key(self.label, db_path=AUTH_DB_PATH)
        self.headers = {"X-API-Key": self.raw_key}
        self.agent_name = f"ratelimit-agent-{uuid.uuid4().hex[:8]}"

    def tearDown(self):
        rate_limit.CATEGORIES.clear()
        rate_limit.CATEGORIES.update(self._orig_categories)
        rate_limit.reset()

        deactivate_key(self.label, db_path=AUTH_DB_PATH)
        conn = sqlite3.connect(AUTH_DB_PATH)
        conn.execute("DELETE FROM api_keys WHERE label = ?", (self.label,))
        conn.commit()
        conn.close()

        conn = sqlite3.connect(THREATS_DB_PATH)
        conn.execute("DELETE FROM registered_agents WHERE name = ?", (self.agent_name,))
        conn.execute("DELETE FROM scan_results WHERE agent_name = ?", (self.agent_name,))
        conn.commit()
        conn.close()

        conn = sqlite3.connect(MONITORING_DB_PATH)
        conn.execute("DELETE FROM monitoring_alerts WHERE agent_name = ?", (self.agent_name,))
        conn.execute("DELETE FROM monitoring_logs WHERE agent_name = ?", (self.agent_name,))
        conn.commit()
        conn.close()

    def test_exceeding_read_limit_returns_429_with_retry_after(self):
        rate_limit.CATEGORIES["read"] = {"max_requests": 2, "window_seconds": 60}

        for _ in range(2):
            self.assertEqual(self.client.get("/agents", headers=self.headers).status_code, 200)

        response = self.client.get("/agents", headers=self.headers)
        self.assertEqual(response.status_code, 429)
        self.assertIn("Retry-After", response.headers)
        self.assertIn("Rate limit exceeded", response.json()["detail"])

    def test_different_categories_are_independent_on_the_same_key(self):
        rate_limit.CATEGORIES["read"] = {"max_requests": 1, "window_seconds": 60}
        rate_limit.CATEGORIES["write"] = {"max_requests": 5, "window_seconds": 60}

        self.assertEqual(self.client.get("/agents", headers=self.headers).status_code, 200)
        self.assertEqual(self.client.get("/agents", headers=self.headers).status_code, 429)

        # write has its own, unexhausted quota despite read being blocked
        response = self.client.post(
            "/agents",
            json={"name": self.agent_name, "agent_type": "mock"},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)

    def test_log_request_is_unlimited_by_default(self):
        for _ in range(25):
            response = self.client.post(
                "/monitoring/log-request",
                json={"agent_name": self.agent_name, "prompt": "hi", "response": "hi"},
                headers=self.headers,
            )
            self.assertEqual(response.status_code, 200)

    def test_invalid_key_never_consumes_or_is_blocked_by_a_valid_keys_quota(self):
        rate_limit.CATEGORIES["read"] = {"max_requests": 1, "window_seconds": 60}

        for _ in range(5):
            response = self.client.get("/agents", headers={"X-API-Key": "not-a-real-key"})
            self.assertEqual(response.status_code, 401)

        # The valid key's quota (max 1) is untouched by those 401s
        self.assertEqual(self.client.get("/agents", headers=self.headers).status_code, 200)

    def test_scan_endpoint_uses_its_own_category(self):
        rate_limit.CATEGORIES["scan"] = {"max_requests": 1, "window_seconds": 3600}

        first = self.client.post(
            "/scan",
            json={"agent_type": "mock", "agent_name": self.agent_name, "limit": 1},
            headers=self.headers,
        )
        self.assertEqual(first.status_code, 200)

        second = self.client.post(
            "/scan",
            json={"agent_type": "mock", "agent_name": self.agent_name, "limit": 1},
            headers=self.headers,
        )
        self.assertEqual(second.status_code, 429)


if __name__ == "__main__":
    unittest.main()
