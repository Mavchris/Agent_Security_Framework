"""
Integration tests for the /agents API endpoints (api/app.py) - a thin
HTTP layer over core/agent_registry.py, see SECURITY.md. Covers the
require_api_key gate on all 4 endpoints, the CRUD cycle, and the 400/404
cases already verified manually when these endpoints were added.
"""

import sqlite3
import unittest
import uuid

from fastapi.testclient import TestClient

from api.app import app
from core.auth import deactivate_key, generate_key

THREATS_DB_PATH = "data/threats.db"
AUTH_DB_PATH = "data/auth.db"


class TestAgentsEndpointsRequireApiKey(unittest.TestCase):
    """Same shape as test_auth.py's TestMonitoringEndpointsRequireApiKey -
    all 4 endpoints share the exact same require_api_key dependency."""

    ENDPOINTS = [
        ("get", "/agents"),
        ("post", "/agents"),
        ("get", "/agents/1"),
        ("post", "/agents/1/deactivate"),
    ]

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def _call(self, method, path):
        if method == "post":
            return self.client.post(path, json={"name": "x", "agent_type": "mock"})
        return self.client.get(path)

    def test_absent_key_returns_401_on_every_endpoint(self):
        for method, path in self.ENDPOINTS:
            with self.subTest(path=path):
                response = self._call(method, path)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.json(), {"detail": "Invalid or missing API key"})

    def test_invalid_key_returns_401_on_every_endpoint(self):
        headers = {"X-API-Key": "not-a-real-key"}
        for method, path in self.ENDPOINTS:
            with self.subTest(path=path):
                if method == "post":
                    response = self.client.post(path, json={"name": "x", "agent_type": "mock"}, headers=headers)
                else:
                    response = self.client.get(path, headers=headers)
                self.assertEqual(response.status_code, 401)


class TestAgentsCRUD(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.label = f"agents-api-test-{uuid.uuid4().hex[:8]}"
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
        self.agent_name = f"api-test-agent-{uuid.uuid4().hex[:8]}"

    def tearDown(self):
        conn = sqlite3.connect(THREATS_DB_PATH)
        conn.execute("DELETE FROM registered_agents WHERE name = ?", (self.agent_name,))
        conn.commit()
        conn.close()

    def test_register_list_get_deactivate_full_cycle(self):
        # Create
        response = self.client.post(
            "/agents",
            json={"name": self.agent_name, "agent_type": "mock"},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        agent = response.json()
        self.assertEqual(agent["name"], self.agent_name)
        self.assertEqual(agent["agent_type"], "mock")
        self.assertTrue(agent["is_active"])
        self.assertEqual(agent["created_by_key_label"], self.label)
        self.assertIsNone(agent["deactivated_by_key_label"])
        agent_id = agent["id"]

        # List includes it
        listed = self.client.get("/agents", headers=self.headers).json()["agents"]
        self.assertTrue(any(a["name"] == self.agent_name for a in listed))

        # Get by id
        fetched = self.client.get(f"/agents/{agent_id}", headers=self.headers)
        self.assertEqual(fetched.status_code, 200)
        self.assertEqual(fetched.json()["name"], self.agent_name)

        # Deactivate
        deactivated = self.client.post(f"/agents/{agent_id}/deactivate", headers=self.headers)
        self.assertEqual(deactivated.status_code, 200)
        self.assertEqual(deactivated.json(), {"id": agent_id, "status": "deactivated"})

        # get_agent_config still returns a deactivated agent (soft-delete) -
        # same contract as core.agent_registry.get_agent_config()
        after = self.client.get(f"/agents/{agent_id}", headers=self.headers).json()
        self.assertFalse(after["is_active"])
        self.assertEqual(after["deactivated_by_key_label"], self.label)

        # Excluded from the default (active_only=true) listing, present
        # when explicitly asked for inactive agents too
        active_only = self.client.get("/agents", headers=self.headers).json()["agents"]
        self.assertFalse(any(a["name"] == self.agent_name for a in active_only))
        all_agents = self.client.get("/agents?active_only=false", headers=self.headers).json()["agents"]
        self.assertTrue(any(a["name"] == self.agent_name for a in all_agents))

    def test_register_config_and_environment_stored(self):
        response = self.client.post(
            "/agents",
            json={
                "name": self.agent_name,
                "agent_type": "remote_http",
                "config": {"endpoint_url": "http://agent.internal/query"},
                "environment": "staging",
            },
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        agent = response.json()
        self.assertEqual(agent["environment"], "staging")
        self.assertEqual(agent["config"]["endpoint_url"], "http://agent.internal/query")

    def test_register_duplicate_name_returns_400(self):
        body = {"name": self.agent_name, "agent_type": "mock"}
        first = self.client.post("/agents", json=body, headers=self.headers)
        self.assertEqual(first.status_code, 200)

        second = self.client.post("/agents", json=body, headers=self.headers)
        self.assertEqual(second.status_code, 400)

    def test_register_invalid_agent_type_returns_400(self):
        response = self.client.post(
            "/agents",
            json={"name": self.agent_name, "agent_type": "not_a_real_type"},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Unknown agent_type", response.json()["detail"])

    def test_get_nonexistent_agent_returns_404(self):
        response = self.client.get("/agents/999999999", headers=self.headers)
        self.assertEqual(response.status_code, 404)

    def test_deactivate_nonexistent_agent_returns_404(self):
        response = self.client.post("/agents/999999999/deactivate", headers=self.headers)
        self.assertEqual(response.status_code, 404)

    def test_public_catalog_endpoints_still_unaffected(self):
        self.assertEqual(self.client.get("/threats?limit=1").status_code, 200)


if __name__ == "__main__":
    unittest.main()
