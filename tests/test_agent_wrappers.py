"""
Unit tests for RemoteHTTPAgentWrapper (testing/agent_wrappers.py).

Network calls are mocked - no real HTTP server involved. Covers the
happy path (custom field names honored), the error paths (each must
raise a clear exception, never crash silently or return an error
description as if it were the agent's actual answer) and the TLS
verify= wiring (default True, ca_cert_path passed through, verify_ssl=
False logged loudly rather than silently accepted).

Errors split into two exception types (see TransientAgentError's
docstring and testing/agent_scanner.py, which retries only the first
kind): timeout/connection failure/5xx raise TransientAgentError (worth
retrying); a malformed response or a 4xx raise plain RuntimeError (won't
be fixed by retrying the identical request).
"""

import logging
import unittest
from unittest.mock import MagicMock, patch

import requests

from testing.agent_wrappers import RemoteHTTPAgentWrapper, TransientAgentError, get_agent_wrapper


def _mock_response(json_data=None, json_error=False, status=200):
    """Build a MagicMock standing in for a requests.Response"""
    resp = MagicMock()
    resp.status_code = status
    if json_error:
        resp.json.side_effect = ValueError("not JSON")
    else:
        resp.json.return_value = json_data
    resp.raise_for_status = MagicMock()
    return resp


class TestRemoteHTTPAgentWrapperHappyPath(unittest.TestCase):

    @patch("testing.agent_wrappers.requests.post")
    def test_sends_prompt_and_extracts_response(self, mock_post):
        mock_post.return_value = _mock_response({"response": "Hello back"})
        agent = RemoteHTTPAgentWrapper(endpoint_url="http://agent.internal/query")

        result = agent.query("Hello")

        self.assertEqual(result, "Hello back")
        _, call_kwargs = mock_post.call_args
        self.assertEqual(call_kwargs["json"], {"prompt": "Hello"})
        self.assertEqual(call_kwargs["verify"], True)

    @patch("testing.agent_wrappers.requests.post")
    def test_custom_field_names_honored(self, mock_post):
        mock_post.return_value = _mock_response({"answer": "42"})
        agent = RemoteHTTPAgentWrapper(
            endpoint_url="http://agent.internal/query",
            request_field="question",
            response_field="answer",
        )

        result = agent.query("What is the answer?")

        self.assertEqual(result, "42")
        _, call_kwargs = mock_post.call_args
        self.assertEqual(call_kwargs["json"], {"question": "What is the answer?"})

    @patch.dict("os.environ", {"MY_AGENT_TOKEN": "secret-token-value"})
    @patch("testing.agent_wrappers.requests.post")
    def test_auth_env_var_read_at_call_time(self, mock_post):
        mock_post.return_value = _mock_response({"response": "ok"})
        agent = RemoteHTTPAgentWrapper(
            endpoint_url="http://agent.internal/query",
            auth_env_var="MY_AGENT_TOKEN",
        )
        # The token must not be read/stored until query() actually runs.
        self.assertFalse(hasattr(agent, "token"))

        agent.query("Hello")

        _, call_kwargs = mock_post.call_args
        self.assertEqual(call_kwargs["headers"]["Authorization"], "Bearer secret-token-value")

    @patch("testing.agent_wrappers.requests.post")
    def test_missing_auth_env_var_warns_and_still_calls(self, mock_post):
        mock_post.return_value = _mock_response({"response": "ok"})
        agent = RemoteHTTPAgentWrapper(
            endpoint_url="http://agent.internal/query",
            auth_env_var="NON_EXISTENT_TOKEN_VAR",
        )

        with self.assertLogs("testing.agent_wrappers", level="WARNING") as cm:
            result = agent.query("Hello")

        self.assertEqual(result, "ok")
        self.assertTrue(any("NON_EXISTENT_TOKEN_VAR" in msg for msg in cm.output))
        _, call_kwargs = mock_post.call_args
        self.assertNotIn("Authorization", call_kwargs["headers"])

    @patch("testing.agent_wrappers.requests.post")
    def test_dispatched_via_get_agent_wrapper(self, mock_post):
        mock_post.return_value = _mock_response({"response": "via factory"})
        agent = get_agent_wrapper("remote_http", endpoint_url="http://agent.internal/query")

        self.assertIsInstance(agent, RemoteHTTPAgentWrapper)
        self.assertEqual(agent.query("Hi"), "via factory")


class TestRemoteHTTPAgentWrapperErrors(unittest.TestCase):

    @patch("testing.agent_wrappers.requests.post")
    def test_timeout_raises_transient_error(self, mock_post):
        mock_post.side_effect = requests.exceptions.Timeout()
        agent = RemoteHTTPAgentWrapper(endpoint_url="http://agent.internal/query", timeout=5)

        with self.assertRaises(TransientAgentError) as ctx:
            agent.query("Hello")
        self.assertIn("did not respond", str(ctx.exception))
        self.assertIn("5s", str(ctx.exception))

    @patch("testing.agent_wrappers.requests.post")
    def test_connection_error_raises_transient_error(self, mock_post):
        mock_post.side_effect = requests.exceptions.ConnectionError("refused")
        agent = RemoteHTTPAgentWrapper(endpoint_url="http://agent.internal/query")

        with self.assertRaises(TransientAgentError) as ctx:
            agent.query("Hello")
        self.assertIn("Could not connect", str(ctx.exception))

    def _http_error_response(self, status):
        """A response whose raise_for_status() raises a real HTTPError
        with .response attached (as requests itself does) - status is
        what query()'s except-block inspects to decide transient vs not."""
        resp = _mock_response(status=status)
        error = requests.exceptions.HTTPError(f"{status} Error", response=resp)
        resp.raise_for_status.side_effect = error
        return resp

    @patch("testing.agent_wrappers.requests.post")
    def test_5xx_status_raises_transient_error(self, mock_post):
        mock_post.return_value = self._http_error_response(500)
        agent = RemoteHTTPAgentWrapper(endpoint_url="http://agent.internal/query")

        with self.assertRaises(TransientAgentError) as ctx:
            agent.query("Hello")
        self.assertIn("returned an error", str(ctx.exception))

    @patch("testing.agent_wrappers.requests.post")
    def test_429_status_raises_transient_error(self, mock_post):
        mock_post.return_value = self._http_error_response(429)
        agent = RemoteHTTPAgentWrapper(endpoint_url="http://agent.internal/query")

        with self.assertRaises(TransientAgentError):
            agent.query("Hello")

    @patch("testing.agent_wrappers.requests.post")
    def test_4xx_status_raises_plain_runtime_error(self, mock_post):
        mock_post.return_value = self._http_error_response(400)
        agent = RemoteHTTPAgentWrapper(endpoint_url="http://agent.internal/query")

        with self.assertRaises(RuntimeError) as ctx:
            agent.query("Hello")
        self.assertNotIsInstance(ctx.exception, TransientAgentError)
        self.assertIn("returned an error", str(ctx.exception))

    @patch("testing.agent_wrappers.requests.post")
    def test_non_json_response_raises_clear_error(self, mock_post):
        mock_post.return_value = _mock_response(json_error=True)
        agent = RemoteHTTPAgentWrapper(endpoint_url="http://agent.internal/query")

        with self.assertRaises(RuntimeError) as ctx:
            agent.query("Hello")
        self.assertIn("did not return valid JSON", str(ctx.exception))

    @patch("testing.agent_wrappers.requests.post")
    def test_missing_response_field_raises_clear_error(self, mock_post):
        mock_post.return_value = _mock_response({"unexpected_key": "value"})
        agent = RemoteHTTPAgentWrapper(endpoint_url="http://agent.internal/query")

        with self.assertRaises(RuntimeError) as ctx:
            agent.query("Hello")
        self.assertIn("response", str(ctx.exception))


class TestRemoteHTTPAgentWrapperTLS(unittest.TestCase):

    @patch("testing.agent_wrappers.requests.post")
    def test_verify_defaults_to_true(self, mock_post):
        mock_post.return_value = _mock_response({"response": "ok"})
        agent = RemoteHTTPAgentWrapper(endpoint_url="http://agent.internal/query")

        agent.query("Hello")

        self.assertEqual(mock_post.call_args.kwargs["verify"], True)

    @patch("testing.agent_wrappers.requests.post")
    def test_ca_cert_path_passed_through(self, mock_post):
        mock_post.return_value = _mock_response({"response": "ok"})
        agent = RemoteHTTPAgentWrapper(
            endpoint_url="http://agent.internal/query",
            ca_cert_path="/etc/ssl/internal-ca.pem",
        )

        agent.query("Hello")

        self.assertEqual(mock_post.call_args.kwargs["verify"], "/etc/ssl/internal-ca.pem")

    @patch("testing.agent_wrappers.requests.post")
    def test_verify_ssl_false_logs_warning_every_call(self, mock_post):
        mock_post.return_value = _mock_response({"response": "ok"})
        agent = RemoteHTTPAgentWrapper(
            endpoint_url="http://agent.internal/query",
            verify_ssl=False,
        )

        for _ in range(2):
            with self.assertLogs("testing.agent_wrappers", level="WARNING") as cm:
                agent.query("Hello")
            self.assertTrue(any("DISABLED" in msg for msg in cm.output))

        self.assertEqual(mock_post.call_args.kwargs["verify"], False)


if __name__ == "__main__":
    unittest.main()
