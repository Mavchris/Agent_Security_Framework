"""
AppTest regression guard for dashboard/pages/operations.py's "Run Scan"
flow (Mock agent). This is the button that already broke silently once
(a stale `type` vs `agent_type` key mismatch in agent_config) - dashboard
pages otherwise sit at 0% coverage (see README Known Limitations), since
Streamlit's multipage runner launches them directly rather than
importing them as a package. This is a first, targeted test on the
single most critical/already-broken-once interaction, not a full page
test suite.
"""

import re
import sqlite3
import unittest
import uuid
from pathlib import Path

from streamlit.testing.v1 import AppTest

from core.agent_registry import get_agent_by_name
from testing.agent_scanner import AgentVulnerabilityScanner
from testing.agent_wrappers import get_agent_wrapper

OPERATIONS_PAGE = str(
    Path(__file__).resolve().parent.parent / "dashboard" / "pages" / "operations.py"
)
DB_PATH = "data/threats.db"


def _click_run_scan(at):
    run_scan = next(b for b in at.button if b.label == "Run Scan")
    return run_scan.click().run()


class TestOperationsRunScan(unittest.TestCase):
    """Simulate a full Mock-agent scan through the real Streamlit page"""

    def setUp(self):
        self.at = AppTest.from_file(OPERATIONS_PAGE, default_timeout=30)
        self.at.run()

    def test_mock_scan_runs_without_exception(self):
        _click_run_scan(self.at)

        self.assertEqual(
            [str(e) for e in self.at.exception], [],
            "Run Scan raised an unhandled exception",
        )
        self.assertEqual(
            [e.value for e in self.at.error], [],
            "Run Scan produced an st.error banner",
        )

    def test_score_matches_independent_scan(self):
        _click_run_scan(self.at)

        # Independently reproduce what the page's scan should have
        # computed, using the same MockAgent and the same DB, to catch
        # the page silently rendering a stale/disconnected score.
        agent = get_agent_wrapper(agent_type="mock")
        scanner = AgentVulnerabilityScanner(agent, db_path=DB_PATH)
        expected = scanner.scan_all_threats(verbose=False)

        conn = sqlite3.connect(DB_PATH)
        total_in_db = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
        conn.close()
        self.assertEqual(expected["total_threats"], total_in_db)

        score_markdown = next(
            (
                m.value for m in self.at.markdown
                if "kpi-soft-" in m.value and "Vulnerability Score" in m.value
            ),
            None,
        )
        self.assertIsNotNone(score_markdown, "Vulnerability score card not rendered")

        match = re.search(r'class="kpi-value">([\d.]+)%', score_markdown)
        self.assertIsNotNone(match, "Score value not found in rendered card")
        displayed_score = float(match.group(1))

        self.assertAlmostEqual(displayed_score, expected["vulnerability_score"], places=1)


class TestAgentRegistryEndToEnd(unittest.TestCase):
    """Full path through the real dashboard: register an agent via the
    "Register a new agent" form (in the "Test Agent" tab), confirm it
    appears in the registered-agent selector, then run a real scan on it
    - not just isolated unit tests.

    The form has two explicit entry paths (see the Vague that split
    "Agent Type" into "My own agent" vs "Reference baseline model", to
    stop users registering a raw Claude/GPT-4 thinking it was their own
    agent) - one test per path. Widget keys are prefixed "test_agent_"
    since the same form is also rendered (prefixed "monitor_") in the
    "Monitor Production" tab - see TestMonitorProductionRegistration."""

    def setUp(self):
        self.agent_name = f"E2E Test Agent {uuid.uuid4().hex[:8]}"
        self.at = AppTest.from_file(OPERATIONS_PAGE, default_timeout=30)
        self.at.run()

    def tearDown(self):
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM registered_agents WHERE name = ?", (self.agent_name,))
        conn.commit()
        conn.close()

    def test_reference_baseline_path_registers_and_scans(self):
        at = self.at

        # "Reference baseline model" path -> the 6-type selectbox appears
        at = at.radio(key="test_agent_register_agent_path").set_value("Reference baseline model").run()
        at.selectbox(key="test_agent_register_agent_type").set_value("Mock").run()
        at.text_input(key="test_agent_reg_name").set_value(self.agent_name).run()

        submit = at.button(key="test_agent_register_submit")
        at = submit.click().run()

        self.assertEqual([str(e) for e in at.exception], [])
        self.assertTrue(
            any(self.agent_name in s.value for s in at.success),
            "No success message after registering the agent",
        )

        registered = get_agent_by_name(self.agent_name)
        self.assertIsNotNone(registered)
        self.assertEqual(registered["agent_type"], "mock")

        # Switch to "Registered agent" mode and confirm it's listed
        at = at.radio(key="agent_source").set_value("Registered agent").run()

        select = at.selectbox(key="registered_agent_select")
        matching_options = [o for o in select.options if self.agent_name in o]
        self.assertTrue(
            matching_options,
            "Newly registered agent not found in the registered-agent selector",
        )
        at = select.set_value(matching_options[0]).run()

        # Run a scan on it
        run_scan = at.button(key="run_test_registered")
        at = run_scan.click().run()

        self.assertEqual(
            [str(e) for e in at.exception], [],
            "Scanning the registered agent raised an unhandled exception",
        )
        score_markdown = next(
            (
                m.value for m in at.markdown
                if "kpi-soft-" in m.value and "Vulnerability Score" in m.value
            ),
            None,
        )
        self.assertIsNotNone(
            score_markdown, "Vulnerability score card not rendered for the registered agent"
        )

    def test_my_own_agent_path_registers_as_remote_http(self):
        at = self.at

        # Default radio value - no type selectbox should appear at all,
        # since "My own agent" locks the type to remote_http directly.
        self.assertEqual(
            at.radio(key="test_agent_register_agent_path").value, "My own agent"
        )
        with self.assertRaises(KeyError):
            at.selectbox(key="test_agent_register_agent_type")

        at.text_input(key="test_agent_reg_name").set_value(self.agent_name).run()
        at = at.text_input(key="test_agent_reg_endpoint_url").set_value(
            "http://localhost:8500/query"
        ).run()

        submit = at.button(key="test_agent_register_submit")
        at = submit.click().run()

        self.assertEqual([str(e) for e in at.exception], [])
        self.assertTrue(
            any(self.agent_name in s.value for s in at.success),
            "No success message after registering the agent",
        )

        registered = get_agent_by_name(self.agent_name)
        self.assertIsNotNone(registered)
        self.assertEqual(registered["agent_type"], "remote_http")
        self.assertEqual(registered["config"]["endpoint_url"], "http://localhost:8500/query")

        # Confirm it's listed under "Registered agent" mode too.
        at = at.radio(key="agent_source").set_value("Registered agent").run()
        select = at.selectbox(key="registered_agent_select")
        self.assertTrue(
            any(self.agent_name in o and "remote_http" in o for o in select.options),
            "Newly registered remote_http agent not found (or mislabeled) in the selector",
        )


class TestMonitorProductionRegistration(unittest.TestCase):
    """Same shared registration form, now also reachable from "Monitor
    Production" (previously that tab only pointed users back to "Test
    Agent" to register - see the Vague that added a registration button
    there directly). Uses the "monitor_"-prefixed widget keys."""

    def setUp(self):
        self.agent_name = f"E2E Monitor Agent {uuid.uuid4().hex[:8]}"
        self.at = AppTest.from_file(OPERATIONS_PAGE, default_timeout=30)
        self.at.run()

    def tearDown(self):
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM registered_agents WHERE name = ?", (self.agent_name,))
        conn.commit()
        conn.close()

    def test_register_from_monitor_production_tab_appears_in_its_own_list(self):
        at = self.at

        at = at.radio(key="monitor_register_agent_path").set_value("Reference baseline model").run()
        at.selectbox(key="monitor_register_agent_type").set_value("Mock").run()
        at.text_input(key="monitor_reg_name").set_value(self.agent_name).run()

        submit = at.button(key="monitor_register_submit")
        at = submit.click().run()

        self.assertEqual([str(e) for e in at.exception], [])

        registered = get_agent_by_name(self.agent_name)
        self.assertIsNotNone(registered)
        self.assertEqual(registered["agent_type"], "mock")

        # It must show up in Monitor Production's own agent list (health
        # status cards / agent-actions selector), the whole point of
        # having the form there instead of only in "Test Agent".
        action_select = at.selectbox(key="monitor_action_agent")
        self.assertIn(self.agent_name, action_select.options)


if __name__ == "__main__":
    unittest.main()
