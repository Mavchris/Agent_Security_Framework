"""
Tests for docs/examples/huggingface_agent_server.py - the isolated-process
HuggingFace agent, exposed as a remote_http-compatible HTTP endpoint (see
its module docstring for why it needs its own process at all: a torch/
pandas-pyarrow DLL conflict on this project's Windows environment).

HuggingFaceAgentWrapper itself (real model loading) is mocked throughout -
no real HuggingFace model is downloaded/loaded in this suite, per the
same reasoning docs/examples/local_agent_http_wrapper.py's simplicity
already avoided needing a dedicated test at all. This file only tests the
HTTP/wiring layer this script adds on top of that wrapper.
"""

import importlib
import os
import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

import docs.examples.huggingface_agent_server as hf_server


class TestHuggingFaceAgentServerQuery(unittest.TestCase):

    def setUp(self):
        # Each test gets a fresh module state (fresh `_agent = None`) so
        # the lifespan hook's model-loading is re-exercised every time,
        # not just observed once for the whole suite.
        importlib.reload(hf_server)

    def test_query_returns_wrapped_agents_response(self):
        fake_agent = MagicMock()
        fake_agent.query.return_value = "PONG"

        with patch.object(hf_server, "HuggingFaceAgentWrapper", return_value=fake_agent):
            with TestClient(hf_server.app) as client:
                response = client.post("/query", json={"prompt": "hi"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"response": "PONG"})
        fake_agent.query.assert_called_once_with("hi")

    def test_lifespan_loads_default_model_when_env_var_unset(self):
        fake_wrapper_cls = MagicMock(return_value=MagicMock())

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(hf_server.MODEL_ENV_VAR, None)
            with patch.object(hf_server, "HuggingFaceAgentWrapper", fake_wrapper_cls):
                with TestClient(hf_server.app):
                    pass

        fake_wrapper_cls.assert_called_once_with(model_name=hf_server.DEFAULT_MODEL)

    def test_lifespan_honors_model_env_var(self):
        fake_wrapper_cls = MagicMock(return_value=MagicMock())
        custom_model = "org/some-other-model"

        with patch.dict(os.environ, {hf_server.MODEL_ENV_VAR: custom_model}):
            with patch.object(hf_server, "HuggingFaceAgentWrapper", fake_wrapper_cls):
                with TestClient(hf_server.app):
                    pass

        fake_wrapper_cls.assert_called_once_with(model_name=custom_model)

    def test_query_before_model_ready_returns_503_not_a_crash(self):
        """_agent stays None until the lifespan hook finishes loading the
        model - a request that lands in that window must get a clear 503,
        not an AttributeError on None."""
        with patch.object(hf_server, "HuggingFaceAgentWrapper", return_value=MagicMock()):
            with TestClient(hf_server.app) as client:
                hf_server._agent = None  # simulate "still loading"
                response = client.post("/query", json={"prompt": "hi"})

        self.assertEqual(response.status_code, 503)


if __name__ == "__main__":
    unittest.main()
