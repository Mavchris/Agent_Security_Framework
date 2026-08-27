"""
Unit tests for the FastAPI REST API.

POST /monitoring/log-request used to accept agent_name/prompt/response as
required query params despite its docstring showing a JSON body example
(see README Known Limitations, Vague 3c). Now that the endpoint takes a
real Pydantic body, these tests cover both the happy path and the
request-validation behavior (missing/invalid fields -> 422).
"""

import unittest

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


if __name__ == "__main__":
    unittest.main()
