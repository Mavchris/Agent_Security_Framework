"""
Unit tests for core/agent_registry.py.

Uses a throwaway temp SQLite file with the real registered_agents schema
(imported straight from the migration script, so the test can't drift
from what actually gets created) - never touches data/threats.db.
"""

import os
import sqlite3
import tempfile
import unittest

from core.agent_registry import (
    build_wrapper,
    deactivate_agent,
    get_agent_config,
    list_agents,
    register_agent,
)
from scripts.maintenance.create_registered_agents_table import CREATE_TABLE_SQL
from testing.agent_wrappers import MockAgentWrapper


class TestAgentRegistry(unittest.TestCase):

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        conn = sqlite3.connect(self.db_path)
        conn.execute(CREATE_TABLE_SQL)
        conn.commit()
        conn.close()

    def tearDown(self):
        os.remove(self.db_path)

    def test_register_and_get(self):
        agent = register_agent(
            "CI Mock", "mock", config={}, environment="test", db_path=self.db_path
        )
        self.assertEqual(agent["name"], "CI Mock")
        self.assertEqual(agent["agent_type"], "mock")
        self.assertTrue(agent["is_active"])

        fetched = get_agent_config(agent["id"], db_path=self.db_path)
        self.assertEqual(fetched, agent)

    def test_get_unknown_id_returns_none(self):
        self.assertIsNone(get_agent_config(9999, db_path=self.db_path))

    def test_register_rejects_unknown_agent_type(self):
        with self.assertRaises(ValueError):
            register_agent("Bad", "not_a_real_type", db_path=self.db_path)

    def test_register_rejects_duplicate_name(self):
        register_agent("Dup", "mock", db_path=self.db_path)
        with self.assertRaises(ValueError):
            register_agent("Dup", "mock", db_path=self.db_path)

    def test_config_round_trips_through_json(self):
        config = {"endpoint_url": "http://agent.internal/query", "verify_ssl": False}
        agent = register_agent(
            "Remote", "remote_http", config=config, db_path=self.db_path
        )
        self.assertEqual(agent["config"], config)

    def test_list_agents_filters_by_environment_and_active(self):
        register_agent("Prod Agent", "mock", environment="production", db_path=self.db_path)
        register_agent("Staging Agent", "mock", environment="staging", db_path=self.db_path)

        prod = list_agents(environment="production", db_path=self.db_path)
        self.assertEqual([a["name"] for a in prod], ["Prod Agent"])

        everyone = list_agents(environment=None, db_path=self.db_path)
        self.assertEqual(len(everyone), 2)

    def test_deactivate_agent_hides_it_from_active_only_list(self):
        agent = register_agent("To Deactivate", "mock", db_path=self.db_path)

        self.assertTrue(deactivate_agent(agent["id"], db_path=self.db_path))

        active = list_agents(db_path=self.db_path)
        self.assertEqual(active, [])

        everyone = list_agents(active_only=False, db_path=self.db_path)
        self.assertEqual(len(everyone), 1)
        self.assertFalse(everyone[0]["is_active"])

    def test_deactivate_unknown_id_returns_false(self):
        self.assertFalse(deactivate_agent(9999, db_path=self.db_path))

    def test_build_wrapper_returns_working_wrapper(self):
        agent = register_agent("Mock For Wrapper", "mock", config={}, db_path=self.db_path)
        wrapper = build_wrapper(agent)
        self.assertIsInstance(wrapper, MockAgentWrapper)
        self.assertIsInstance(wrapper.query("hello"), str)


if __name__ == "__main__":
    unittest.main()
