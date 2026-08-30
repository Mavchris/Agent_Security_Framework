"""
Unit tests for core/auth.py (named API keys, see SECURITY.md) and
integration tests for the X-API-Key protection api/app.py applies to its
4 /monitoring/* endpoints via the require_api_key dependency.
"""

import os
import sqlite3
import tempfile
import unittest
import uuid

from fastapi.testclient import TestClient

from api.app import app
from core.auth import deactivate_key, generate_key, verify_key

AUTH_DB_PATH = "data/auth.db"
MONITORING_DB_PATH = "data/monitoring.db"


class TestCoreAuth(unittest.TestCase):
    """core/auth.py in isolation, against a throwaway temp db - never
    touches data/auth.db (see TestMonitoringEndpointsRequireApiKey below
    for the real-file integration tests api/app.py's dependency needs,
    since it has no db_path override of its own)."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)

    def tearDown(self):
        os.remove(self.db_path)

    def test_generate_key_returns_high_entropy_key_and_stores_only_its_hash(self):
        raw_key = generate_key("alice", db_path=self.db_path)
        self.assertTrue(raw_key.startswith("asif_"))
        self.assertGreater(len(raw_key), 32)

        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            "SELECT key_hash FROM api_keys WHERE label = ?", ("alice",)
        ).fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertNotEqual(row[0], raw_key)

    def test_generate_key_rejects_duplicate_label(self):
        generate_key("bob", db_path=self.db_path)
        with self.assertRaises(ValueError):
            generate_key("bob", db_path=self.db_path)

    def test_verify_key_returns_label_for_a_valid_active_key(self):
        raw_key = generate_key("carol", db_path=self.db_path)
        self.assertEqual(verify_key(raw_key, db_path=self.db_path), "carol")

    def test_verify_key_returns_none_for_unknown_key(self):
        self.assertIsNone(verify_key("not-a-real-key", db_path=self.db_path))

    def test_verify_key_returns_none_for_empty_or_missing_key(self):
        self.assertIsNone(verify_key("", db_path=self.db_path))
        self.assertIsNone(verify_key(None, db_path=self.db_path))

    def test_verify_key_stamps_last_used_at_only_on_success(self):
        raw_key = generate_key("dave", db_path=self.db_path)
        conn = sqlite3.connect(self.db_path)
        before = conn.execute(
            "SELECT last_used_at FROM api_keys WHERE label = ?", ("dave",)
        ).fetchone()[0]
        conn.close()
        self.assertIsNone(before)

        verify_key(raw_key, db_path=self.db_path)

        conn = sqlite3.connect(self.db_path)
        after = conn.execute(
            "SELECT last_used_at FROM api_keys WHERE label = ?", ("dave",)
        ).fetchone()[0]
        conn.close()
        self.assertIsNotNone(after)

    def test_deactivate_key_blocks_future_verification_but_keeps_the_row(self):
        raw_key = generate_key("erin", db_path=self.db_path)
        self.assertTrue(deactivate_key("erin", db_path=self.db_path))
        self.assertIsNone(verify_key(raw_key, db_path=self.db_path))

        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            "SELECT is_active FROM api_keys WHERE label = ?", ("erin",)
        ).fetchone()
        conn.close()
        self.assertEqual(row[0], 0)

    def test_deactivate_unknown_label_returns_false(self):
        self.assertFalse(deactivate_key("nobody", db_path=self.db_path))


class TestMonitoringEndpointsRequireApiKey(unittest.TestCase):
    """api/app.py's require_api_key dependency has no db_path override
    (it always checks the real data/auth.db), so this class - unlike
    TestCoreAuth above - creates and cleans up real keys there. Covers
    all 4 protected endpoints at once per case (absent/invalid/inactive/
    valid key) rather than one test per endpoint, since they all share
    the exact same dependency."""

    ENDPOINTS = [
        ("get", "/monitoring/stats/AuthTestAgent"),
        ("get", "/monitoring/alerts/AuthTestAgent"),
        ("get", "/monitoring/health/AuthTestAgent"),
        ("post", "/monitoring/log-request"),
    ]

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.label = f"api-test-{uuid.uuid4().hex[:8]}"
        cls.raw_key = generate_key(cls.label, db_path=AUTH_DB_PATH)

    @classmethod
    def tearDownClass(cls):
        conn = sqlite3.connect(AUTH_DB_PATH)
        conn.execute("DELETE FROM api_keys WHERE label = ?", (cls.label,))
        conn.commit()
        conn.close()

    def tearDown(self):
        conn = sqlite3.connect(MONITORING_DB_PATH)
        conn.execute("DELETE FROM monitoring_alerts WHERE agent_name = 'AuthTestAgent'")
        conn.execute("DELETE FROM monitoring_logs WHERE agent_name = 'AuthTestAgent'")
        conn.commit()
        conn.close()

    def _call(self, method, path, headers=None):
        if method == "post":
            body = {"agent_name": "AuthTestAgent", "prompt": "hi", "response": "hi"}
            return self.client.post(path, headers=headers or {}, json=body)
        return self.client.get(path, headers=headers or {})

    def test_absent_key_returns_401_on_every_endpoint(self):
        for method, path in self.ENDPOINTS:
            with self.subTest(path=path):
                response = self._call(method, path)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.json(), {"detail": "Invalid or missing API key"})

    def test_invalid_key_returns_401_on_every_endpoint(self):
        for method, path in self.ENDPOINTS:
            with self.subTest(path=path):
                response = self._call(method, path, headers={"X-API-Key": "not-a-real-key"})
                self.assertEqual(response.status_code, 401)

    def test_inactive_key_returns_401_on_every_endpoint(self):
        label = f"inactive-{uuid.uuid4().hex[:8]}"
        raw_key = generate_key(label, db_path=AUTH_DB_PATH)
        deactivate_key(label, db_path=AUTH_DB_PATH)
        try:
            for method, path in self.ENDPOINTS:
                with self.subTest(path=path):
                    response = self._call(method, path, headers={"X-API-Key": raw_key})
                    self.assertEqual(response.status_code, 401)
        finally:
            conn = sqlite3.connect(AUTH_DB_PATH)
            conn.execute("DELETE FROM api_keys WHERE label = ?", (label,))
            conn.commit()
            conn.close()

    def test_valid_key_returns_200_on_every_endpoint(self):
        for method, path in self.ENDPOINTS:
            with self.subTest(path=path):
                response = self._call(method, path, headers={"X-API-Key": self.raw_key})
                self.assertEqual(response.status_code, 200)

    def test_valid_key_attributes_the_log_it_writes_to_its_own_label(self):
        response = self.client.post(
            "/monitoring/log-request",
            headers={"X-API-Key": self.raw_key},
            json={"agent_name": "AuthTestAgent", "prompt": "hi", "response": "hi"},
        )
        self.assertEqual(response.status_code, 200)

        conn = sqlite3.connect(MONITORING_DB_PATH)
        row = conn.execute(
            "SELECT created_by_key_label FROM monitoring_logs "
            "WHERE agent_name = 'AuthTestAgent' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        conn.close()

        self.assertEqual(row[0], self.label)

    def test_public_catalog_endpoints_unaffected(self):
        for path in ["/", "/health", "/threats", "/stats", "/threat-types", "/sources"]:
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 200)


if __name__ == "__main__":
    unittest.main()
