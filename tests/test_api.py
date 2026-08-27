"""
Unit tests for the FastAPI REST API.

POST /monitoring/log-request used to accept agent_name/prompt/response as
required query params despite its docstring showing a JSON body example
(see README Known Limitations, Vague 3c). Now that the endpoint takes a
real Pydantic body, these tests cover both the happy path and the
request-validation behavior (missing/invalid fields -> 422).

Also covers the Vague 3c-security fix: endpoints used to return the raw
str(e) of any exception straight to the client (potential internal-detail
leak - file paths, SQL structure). They now go through a global
exception_handler that logs server-side and returns a generic 500, plus
a restrictive-by-default CORS policy (no allow_origins=["*"]).
"""

import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from api.app import app


class TestLogRequestEndpoint(unittest.TestCase):
    """Test suite for POST /monitoring/log-request"""

    def setUp(self):
        self.client = TestClient(app)

    def test_log_request_valid_body(self):
        response = self.client.post(
            "/monitoring/log-request",
            json={
                "agent_name": "TestAgent",
                "prompt": "What is the weather today?",
                "response": "I don't have real-time weather data.",
            },
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "logged")
        self.assertEqual(body["agent_name"], "TestAgent")
        self.assertIn("alert_triggered", body)
        self.assertIn("risk_level", body)
        self.assertIn("detected_threats", body)

    def test_log_request_with_optional_fields(self):
        response = self.client.post(
            "/monitoring/log-request",
            json={
                "agent_name": "TestAgent",
                "prompt": "Hello",
                "response": "Hi there",
                "user_id": "user123",
                "session_id": "session456",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "logged")

    def test_log_request_missing_required_field(self):
        response = self.client.post(
            "/monitoring/log-request",
            json={
                "agent_name": "TestAgent",
                "prompt": "Hello",
                # "response" missing
            },
        )
        self.assertEqual(response.status_code, 422)

    def test_log_request_rejects_query_params(self):
        """The old query-param calling convention must no longer work."""
        response = self.client.post(
            "/monitoring/log-request"
            "?agent_name=TestAgent&prompt=Hello&response=Hi"
        )
        self.assertEqual(response.status_code, 422)


# A fake path that would only appear in the response if the raw exception
# text leaked through - used below to prove it doesn't.
_SENSITIVE_DB_ERROR = "unable to open database file 'C:/secret/internal/threats.db'"


class TestExceptionLeakFix(unittest.TestCase):
    """Endpoints must never return str(e) to the client (see SECURITY.md)"""

    def setUp(self):
        self.client = TestClient(app, raise_server_exceptions=False)

    @patch("api.app.get_db_connection", side_effect=Exception(_SENSITIVE_DB_ERROR))
    def test_threats_endpoint_hides_exception_detail(self, _mock_conn):
        response = self.client.get("/threats")
        self.assertEqual(response.status_code, 500)
        body = response.json()
        self.assertEqual(body, {"error": "Internal server error", "status": "error"})
        self.assertNotIn("secret", response.text)

    @patch("api.app.get_db_connection", side_effect=Exception(_SENSITIVE_DB_ERROR))
    def test_stats_endpoint_hides_exception_detail(self, _mock_conn):
        response = self.client.get("/stats")
        self.assertEqual(response.status_code, 500)
        self.assertNotIn("secret", response.text)

    @patch("api.app.get_db_connection", side_effect=Exception(_SENSITIVE_DB_ERROR))
    def test_sources_endpoint_hides_exception_detail(self, _mock_conn):
        response = self.client.get("/sources")
        self.assertEqual(response.status_code, 500)
        self.assertNotIn("secret", response.text)

    @patch("api.app.AgentMonitor", side_effect=Exception(_SENSITIVE_DB_ERROR))
    def test_monitoring_stats_endpoint_hides_exception_detail(self, _mock_monitor):
        response = self.client.get("/monitoring/stats/SomeAgent")
        self.assertEqual(response.status_code, 500)
        self.assertNotIn("secret", response.text)

    @patch("api.app.get_db_connection", side_effect=Exception(_SENSITIVE_DB_ERROR))
    def test_health_endpoint_hides_exception_but_stays_200(self, _mock_conn):
        """/health is the deliberate exception: still 200 + status=unhealthy
        (monitoring-tool convention), just with the message sanitized."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body, {"status": "unhealthy", "error": "Internal server error"})
        self.assertNotIn("secret", response.text)

    def test_success_paths_still_work(self):
        """Removing the try/except blocks must not affect normal behavior."""
        self.assertEqual(self.client.get("/threats").status_code, 200)
        self.assertEqual(self.client.get("/stats").status_code, 200)
        self.assertEqual(self.client.get("/sources").status_code, 200)
        self.assertEqual(self.client.get("/health").status_code, 200)


class TestThreatNotFound(unittest.TestCase):
    """GET /threats/{threat_id} with an unknown ID must return a real 404,
    not a 200 with an error-shaped body (see API_DOCUMENTATION.md)."""

    def setUp(self):
        self.client = TestClient(app)

    def test_unknown_threat_id_returns_404(self):
        response = self.client.get("/threats/nonexistent-id")
        self.assertEqual(response.status_code, 404)
        body = response.json()
        self.assertEqual(body["status"], "not_found")
        self.assertIn("nonexistent-id", body["error"])

    def test_known_threat_id_still_returns_200(self):
        # Any real threat_id from the DB should still resolve normally.
        threats = self.client.get("/threats?limit=1").json()["threats"]
        if not threats:
            self.skipTest("no threats in the DB to look up")
        threat_id = threats[0]["threat_id"]
        response = self.client.get(f"/threats/{threat_id}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["threat_id"], threat_id)


class TestCORSPolicy(unittest.TestCase):
    """No permissive allow_origins=['*'] - restrictive by default (see SECURITY.md)"""

    def setUp(self):
        self.client = TestClient(app)

    def test_default_denies_unlisted_origin(self):
        response = self.client.get(
            "/threat-types", headers={"Origin": "http://evil.example"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("access-control-allow-origin", response.headers)


if __name__ == "__main__":
    unittest.main()
