"""
Integration tests for POST /test-connection (api/app.py) - the fast,
synchronous pre-flight check, distinct from POST /scan (async, can take
11-45 minutes). Covers the require_api_key gate, agent_id XOR agent_type
validation (same shape as test_scan_api.py's TestScanRequestValidation),
and that a real query against a Mock agent round-trips correctly.
"""

import sqlite3
import unittest
import uuid

from fastapi.testclient import TestClient

from api.app import app
from core.agent_registry import deactivate_agent, register_agent
from core.auth import deactivate_key, generate_key

THREATS_DB_PATH = "data/threats.db"
AUTH_DB_PATH = "data/auth.db"


class TestConnectionEndpointRequiresApiKey(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_absent_key_returns_401(self):
        response = self.client.post("/test-connection", json={"agent_type": "mock"})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Invalid or missing API key"})

    def test_invalid_key_returns_401(self):
        response = self.client.post(
            "/test-connection",
            json={"agent_type": "mock"},
            headers={"X-API-Key": "not-a-real-key"},
        )
        self.assertEqual(response.status_code, 401)


class TestConnectionRequestValidation(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.label = f"test-connection-validation-{uuid.uuid4().hex[:8]}"
        cls.raw_key = generate_key(cls.label, db_path=AUTH_DB_PATH)
        cls.headers = {"X-API-Key": cls.raw_key}

    @classmethod
    def tearDownClass(cls):
        deactivate_key(cls.label, db_path=AUTH_DB_PATH)
        conn = sqlite3.connect(AUTH_DB_PATH)
        conn.execute("DELETE FROM api_keys WHERE label = ?", (cls.label,))
        conn.commit()
        conn.close()

    def test_neither_agent_id_nor_agent_type_returns_400(self):
        response = self.client.post("/test-connection", json={}, headers=self.headers)
        self.assertEqual(response.status_code, 400)

    def test_both_agent_id_and_agent_type_returns_400(self):
        response = self.client.post(
            "/test-connection",
            json={"agent_id": 1, "agent_type": "mock"},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 400)

    def test_unknown_agent_type_returns_400(self):
        response = self.client.post(
            "/test-connection", json={"agent_type": "not_a_real_type"}, headers=self.headers
        )
        self.assertEqual(response.status_code, 400)

    def test_unknown_agent_id_returns_404(self):
        response = self.client.post(
            "/test-connection", json={"agent_id": 999999999}, headers=self.headers
        )
        self.assertEqual(response.status_code, 404)


class TestConnectionQuickType(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.label = f"test-connection-quick-{uuid.uuid4().hex[:8]}"
        cls.raw_key = generate_key(cls.label, db_path=AUTH_DB_PATH)
        cls.headers = {"X-API-Key": cls.raw_key}

    @classmethod
    def tearDownClass(cls):
        deactivate_key(cls.label, db_path=AUTH_DB_PATH)
        conn = sqlite3.connect(AUTH_DB_PATH)
        conn.execute("DELETE FROM api_keys WHERE label = ?", (cls.label,))
        conn.commit()
        conn.close()

    def test_mock_agent_succeeds_synchronously_with_no_scan_id(self):
        response = self.client.post(
            "/test-connection", json={"agent_type": "mock"}, headers=self.headers
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()

        self.assertTrue(body["success"])
        self.assertIsNone(body["error_category"])
        self.assertIsInstance(body["latency_ms"], float)
        self.assertIsInstance(body["response"], str)
        self.assertIn("ms", body["message"])
        # Synchronous: no scan id/status field, unlike POST /scan's response
        self.assertNotIn("id", body)
        self.assertNotIn("status", body)

    def test_bad_agent_config_returns_configuration_error_not_500(self):
        response = self.client.post(
            "/test-connection",
            json={"agent_type": "remote_http", "agent_config": {"endpoint_url": "http://127.0.0.1:1/nope"}},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()

        self.assertFalse(body["success"])
        self.assertIn(body["error_category"], ("transient", "configuration"))


class TestConnectionRegisteredAgent(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.label = f"test-connection-registered-{uuid.uuid4().hex[:8]}"
        cls.raw_key = generate_key(cls.label, db_path=AUTH_DB_PATH)
        cls.headers = {"X-API-Key": cls.raw_key}

    @classmethod
    def tearDownClass(cls):
        deactivate_key(cls.label, db_path=AUTH_DB_PATH)
        conn = sqlite3.connect(AUTH_DB_PATH)
        conn.execute("DELETE FROM api_keys WHERE label = ?", (cls.label,))
        conn.commit()
        conn.close()

    def setUp(self):
        self.agent_name = f"test-connection-agent-{uuid.uuid4().hex[:8]}"

    def test_registered_mock_agent_succeeds(self):
        agent = register_agent(self.agent_name, "mock")
        try:
            response = self.client.post(
                "/test-connection", json={"agent_id": agent["id"]}, headers=self.headers
            )
            self.assertEqual(response.status_code, 200)
            body = response.json()
            self.assertTrue(body["success"])
        finally:
            deactivate_agent(agent["id"])
            conn = sqlite3.connect(THREATS_DB_PATH)
            conn.execute("DELETE FROM registered_agents WHERE id = ?", (agent["id"],))
            conn.commit()
            conn.close()

    def test_deactivated_registered_agent_returns_404(self):
        agent = register_agent(self.agent_name, "mock")
        deactivate_agent(agent["id"])
        try:
            response = self.client.post(
                "/test-connection", json={"agent_id": agent["id"]}, headers=self.headers
            )
            self.assertEqual(response.status_code, 404)
        finally:
            conn = sqlite3.connect(THREATS_DB_PATH)
            conn.execute("DELETE FROM registered_agents WHERE id = ?", (agent["id"],))
            conn.commit()
            conn.close()


if __name__ == "__main__":
    unittest.main()
