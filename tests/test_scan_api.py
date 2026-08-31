"""
Integration tests for POST /scan and GET /scan/results/{id} (api/app.py),
backed by core/scan_store.py (data/threats.db's scan_results table).

Non-blocking-under-load (a real uvicorn server stays responsive while a
scan runs) is NOT re-verified here - it can't be, with TestClient. See
TestScanAsyncCycle's docstring for what was checked empirically instead
and why an automated test here wouldn't prove it either way.
"""

import sqlite3
import time
import unittest
import uuid

from fastapi.testclient import TestClient

from api.app import app
from core.agent_registry import deactivate_agent, register_agent
from core.auth import deactivate_key, generate_key
from testing.agent_scanner import AgentVulnerabilityScanner
from testing.agent_wrappers import get_agent_wrapper

THREATS_DB_PATH = "data/threats.db"
AUTH_DB_PATH = "data/auth.db"


class TestScanEndpointsRequireApiKey(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_post_scan_absent_key_returns_401(self):
        response = self.client.post("/scan", json={"agent_type": "mock", "agent_name": "x"})
        self.assertEqual(response.status_code, 401)

    def test_get_scan_results_absent_key_returns_401(self):
        response = self.client.get("/scan/results/1")
        self.assertEqual(response.status_code, 401)


class TestScanRequestValidation(unittest.TestCase):
    """400/404 cases already checked manually when POST /scan was added -
    formalized here."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.label = f"scan-validation-test-{uuid.uuid4().hex[:8]}"
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
        response = self.client.post("/scan", json={}, headers=self.headers)
        self.assertEqual(response.status_code, 400)

    def test_both_agent_id_and_agent_type_returns_400(self):
        response = self.client.post(
            "/scan", json={"agent_id": 1, "agent_type": "mock"}, headers=self.headers
        )
        self.assertEqual(response.status_code, 400)

    def test_unknown_agent_type_returns_400(self):
        response = self.client.post(
            "/scan", json={"agent_type": "not_a_real_type", "agent_name": "x"}, headers=self.headers
        )
        self.assertEqual(response.status_code, 400)

    def test_unknown_agent_id_returns_404(self):
        response = self.client.post("/scan", json={"agent_id": 999999999}, headers=self.headers)
        self.assertEqual(response.status_code, 404)

    def test_unknown_scan_id_returns_404(self):
        response = self.client.get("/scan/results/999999999", headers=self.headers)
        self.assertEqual(response.status_code, 404)


class TestScanAsyncCycle(unittest.TestCase):
    """POST /scan -> GET /scan/results/{id} full cycle, MockAgent (fast,
    no real network - fits in a normal test run).

    Confirmed empirically before writing this test: FastAPI's TestClient
    (httpx's ASGI transport) runs a BackgroundTask synchronously as part
    of the request/response cycle it drives - immediately after
    client.post('/scan', ...) returns, with no sleep at all, GET
    /scan/results/{id} already reports 'completed'. That is NOT how a
    real uvicorn server behaves (there, the same code runs in an actual
    background thread while the process keeps serving other requests
    concurrently) - so this test proves the async plumbing is
    functionally correct (status transitions, persisted result matches
    an independent direct scan) but does NOT prove the server stays
    responsive under load. That was verified manually instead, against a
    real uvicorn server plus a synthetic slow remote_http agent
    (2s/threat, ~37s total scan) confirming GET /health and GET /threats
    both answered in ~20-25ms while the scan was still running - see the
    scan-persistence vague's étape 3 checkpoint. Not automated here since
    TestClient cannot exercise real inter-request concurrency.
    """

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.label = f"scan-cycle-test-{uuid.uuid4().hex[:8]}"
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
        self.agent_name = f"scan-cycle-agent-{uuid.uuid4().hex[:8]}"

    def tearDown(self):
        conn = sqlite3.connect(THREATS_DB_PATH)
        conn.execute("DELETE FROM scan_results WHERE agent_name = ?", (self.agent_name,))
        conn.commit()
        conn.close()

    def _poll_until_done(self, scan_id, timeout=10):
        deadline = time.time() + timeout
        result = None
        while time.time() < deadline:
            poll = self.client.get(f"/scan/results/{scan_id}", headers=self.headers)
            self.assertEqual(poll.status_code, 200)
            result = poll.json()
            if result["status"] in ("completed", "failed"):
                return result
            time.sleep(0.1)
        self.fail(f"scan {scan_id} did not reach a final status within {timeout}s")

    def test_quick_type_scan_completes_and_matches_independent_scan(self):
        limit = 20

        response = self.client.post(
            "/scan",
            json={"agent_type": "mock", "agent_name": self.agent_name, "limit": limit},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        # Whatever TestClient's exact timing, the response returned by the
        # endpoint itself must reflect the just-created row, not a
        # already-finished one.
        self.assertEqual(body["status"], "pending")
        self.assertEqual(body["agent_name"], self.agent_name)
        scan_id = body["id"]

        final = self._poll_until_done(scan_id)
        self.assertEqual(final["status"], "completed")
        self.assertEqual(final["agent_id"], None)
        self.assertEqual(final["triggered_by_key_label"], self.label)
        self.assertIsNotNone(final["started_at"])
        self.assertIsNotNone(final["completed_at"])

        # Cross-check against an independent direct scan (same principle
        # as test_operations_page.py's test_score_matches_independent_scan)
        agent = get_agent_wrapper(agent_type="mock")
        scanner = AgentVulnerabilityScanner(agent, db_path=THREATS_DB_PATH)
        expected = scanner.scan_all_threats(verbose=False, limit=limit)

        self.assertEqual(final["total_tested"], expected["total_threats"])
        self.assertEqual(final["vulnerabilities_found"], len(expected["vulnerabilities"]))
        self.assertEqual(final["safe_threats"], len(expected["safe_threats"]))
        self.assertEqual(final["technical_errors"], 0)
        self.assertAlmostEqual(final["vulnerability_score"], expected["vulnerability_score"], places=1)
        self.assertEqual(final["report"]["total_threats"], expected["total_threats"])

    def test_registered_agent_scan_stores_real_agent_id(self):
        agent = register_agent(self.agent_name, "mock")
        try:
            response = self.client.post(
                "/scan", json={"agent_id": agent["id"], "limit": 5}, headers=self.headers
            )
            self.assertEqual(response.status_code, 200)
            scan_id = response.json()["id"]

            final = self._poll_until_done(scan_id)
            self.assertEqual(final["status"], "completed")
            self.assertEqual(final["agent_id"], agent["id"])
            self.assertEqual(final["agent_name"], self.agent_name)
        finally:
            deactivate_agent(agent["id"])
            conn = sqlite3.connect(THREATS_DB_PATH)
            conn.execute("DELETE FROM registered_agents WHERE id = ?", (agent["id"],))
            conn.commit()
            conn.close()


if __name__ == "__main__":
    unittest.main()
