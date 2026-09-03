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

from testing.agent_wrappers import (
    BaseAgentWrapper,
    CONNECTION_TEST_PROMPT,
    RemoteHTTPAgentWrapper,
    TransientAgentError,
    get_agent_wrapper,
    # Aliased: pytest collects any module-level `test_`-prefixed name as
    # a test function, and this one takes a required `agent` argument -
    # left as `test_agent_connection` it gets picked up and fails
    # collection with "fixture 'agent' not found".
    test_agent_connection as check_agent_connection,
)


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


class _FakeAgent(BaseAgentWrapper):
    """Minimal agent double for test_agent_connection() tests - query()
    does whatever fn returns/raises, so one small class covers the
    success and both failure paths without a mock framework."""

    def __init__(self, fn):
        self._fn = fn
        self.received_prompt = None

    def query(self, prompt):
        self.received_prompt = prompt
        return self._fn()


class TestAgentConnection(unittest.TestCase):
    """Unit tests for testing.agent_wrappers.test_agent_connection() - the
    single-call pre-flight check used by both the dashboard's "Test
    Connection" button and POST /test-connection (api/app.py)."""

    def test_success_reports_latency_and_response(self):
        agent = _FakeAgent(lambda: "PONG, connection confirmed")

        result = check_agent_connection(agent)

        self.assertTrue(result["success"])
        self.assertIsNone(result["error_category"])
        self.assertEqual(result["response"], "PONG, connection confirmed")
        self.assertIsInstance(result["latency_ms"], float)
        self.assertGreaterEqual(result["latency_ms"], 0)
        self.assertIn("ms", result["message"])
        self.assertEqual(agent.received_prompt, CONNECTION_TEST_PROMPT)

    def test_transient_error_is_categorized_as_transient(self):
        def _raise():
            raise TransientAgentError("Ollama not running - start with: ollama serve")

        agent = _FakeAgent(_raise)

        result = check_agent_connection(agent)

        self.assertFalse(result["success"])
        self.assertEqual(result["error_category"], "transient")
        self.assertIsNone(result["response"])
        self.assertIn("retrying will probably work", result["message"])
        self.assertIn("Ollama not running", result["message"])

    def test_non_transient_error_is_categorized_as_configuration(self):
        def _raise():
            raise RuntimeError("Remote agent response is missing expected field 'response'")

        agent = _FakeAgent(_raise)

        result = check_agent_connection(agent)

        self.assertFalse(result["success"])
        self.assertEqual(result["error_category"], "configuration")
        self.assertIsNone(result["response"])
        self.assertIn("won't be fixed by retrying", result["message"])

    def test_uses_custom_prompt_when_given(self):
        agent = _FakeAgent(lambda: "ok")

        check_agent_connection(agent, prompt="custom probe")

        self.assertEqual(agent.received_prompt, "custom probe")

    def test_latency_is_measured_even_on_failure(self):
        def _raise():
            raise TransientAgentError("timeout")

        agent = _FakeAgent(_raise)

        result = check_agent_connection(agent)

        self.assertIsInstance(result["latency_ms"], float)
        self.assertGreaterEqual(result["latency_ms"], 0)

    def test_does_not_retry_on_transient_failure(self):
        """Deliberately a single attempt (see test_agent_connection's
        docstring) - a caller wanting retry semantics should route through
        core.retry.request_with_retry itself, not get it silently baked
        in here."""
        call_count = 0

        def _raise():
            nonlocal call_count
            call_count += 1
            raise TransientAgentError("blip")

        agent = _FakeAgent(_raise)

        check_agent_connection(agent)

        self.assertEqual(call_count, 1)


class TestHuggingFaceRemovedFromFactory(unittest.TestCase):
    """get_agent_wrapper('huggingface'/'hf') used to build an in-process
    HuggingFaceAgentWrapper - removed (not just renamed) because torch and
    pandas/pyarrow crash when loaded into the same process on this
    project's Windows environment (see HuggingFaceAgentWrapper's
    docstring). Both names must raise a specific, actionable ValueError -
    never a KeyError, and never silently fall through to the generic
    "unknown agent type" message, which wouldn't explain why or what to
    do instead."""

    def test_huggingface_raises_specific_error(self):
        with self.assertRaises(ValueError) as ctx:
            get_agent_wrapper('huggingface')
        message = str(ctx.exception)
        self.assertIn('remote_http', message)
        self.assertIn('docs/examples/huggingface_agent_server.py', message)

    def test_hf_alias_raises_the_same_specific_error(self):
        with self.assertRaises(ValueError) as ctx:
            get_agent_wrapper('hf')
        self.assertIn('remote_http', str(ctx.exception))

    def test_case_insensitive(self):
        with self.assertRaises(ValueError) as ctx:
            get_agent_wrapper('HuggingFace')
        self.assertIn('remote_http', str(ctx.exception))

    def test_huggingface_wrapper_class_still_importable_directly(self):
        """Not reachable via the factory, but still needed as the model-
        loading logic reused (not duplicated) by
        docs/examples/huggingface_agent_server.py."""
        from testing.agent_wrappers import HuggingFaceAgentWrapper
        self.assertTrue(issubclass(HuggingFaceAgentWrapper, BaseAgentWrapper))


if __name__ == "__main__":
    unittest.main()
