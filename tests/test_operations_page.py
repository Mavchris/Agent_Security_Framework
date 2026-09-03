"""
AppTest regression guard for dashboard/pages/operations.py's "Run Scan"
flow (Mock agent). This is the button that already broke silently once
(a stale `type` vs `agent_type` key mismatch in agent_config) - dashboard
pages otherwise sit at 0% coverage (see README Known Limitations), since
Streamlit's multipage runner launches them directly rather than
importing them as a package. This is a first, targeted test on the
single most critical/already-broken-once interaction, not a full page
test suite.

operations.py gates its entire body behind a named-API-key check
(st.session_state["api_key_label"], see core/auth.py and SECURITY.md)
before rendering any tab content. Every test below that isn't itself
about the gate uses _authed_app_test() to seed a session_state label
directly and skip past it - the gate only checks the label's presence
once, at the top of the script, so this exercises the exact same
post-gate code path a real unlocked session would hit without needing a
real key in data/auth.db for every unrelated test. TestApiKeyGate below
covers the gate itself, with a real generated key.
"""

import re
import sqlite3
import unittest
import uuid
from pathlib import Path

import streamlit as st
from streamlit.testing.v1 import AppTest

from core.agent_registry import deactivate_agent, get_agent_by_name, register_agent
from core.auth import generate_key
from testing.agent_scanner import AgentVulnerabilityScanner
from testing.agent_wrappers import get_agent_wrapper

OPERATIONS_PAGE = str(
    Path(__file__).resolve().parent.parent / "dashboard" / "pages" / "operations.py"
)
DB_PATH = "data/threats.db"
AUTH_DB_PATH = "data/auth.db"


def _authed_app_test():
    """A fresh AppTest for operations.py with the API-key gate already
    passed - see the module docstring for why this doesn't need a real key."""
    at = AppTest.from_file(OPERATIONS_PAGE, default_timeout=30)
    at.session_state["api_key_label"] = "test-suite"
    at.run()
    return at


def _click_run_scan(at):
    run_scan = next(b for b in at.button if b.label == "Run Scan")
    return run_scan.click().run()


def _click_unlock(at):
    unlock = next(b for b in at.button if b.label == "Unlock")
    return unlock.click().run()


def _click_register(at, tab_index):
    """Click "Register Agent" in a specific tab. Both tabs render a
    same-labeled button (render_registration_form is shared, see
    dashboard/pages/operations.py) with no explicit key - a form has only
    one submit button, already disambiguated by its enclosing form's
    unique name, so at.tabs[i] scoping (not a key=) is what tells them
    apart here."""
    submit = next(b for b in at.tabs[tab_index].button if b.label == "Register Agent")
    return submit.click().run()


def _gate_label(at):
    """at.session_state has no .get() (it's Streamlit's real SessionState,
    not a plain dict - .get would be looked up as a session key named
    "get" and raise) - returns the api_key_label value, or None if unset."""
    return at.session_state["api_key_label"] if "api_key_label" in at.session_state else None


class TestOperationsRunScan(unittest.TestCase):
    """Simulate a full Mock-agent scan through the real Streamlit page"""

    def setUp(self):
        self.at = _authed_app_test()

    def tearDown(self):
        # "Run Scan" now persists to scan_results (see the scan-
        # persistence vague's étape 4) - clean up what these tests wrote,
        # scoped to the fake test label so a real 'my_agent' scan history
        # is never at risk of being swept up by this.
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "DELETE FROM scan_results WHERE agent_name = 'my_agent' "
            "AND triggered_by_key_label = 'test-suite'"
        )
        conn.commit()
        conn.close()

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
        self.at = _authed_app_test()

    def tearDown(self):
        # test_reference_baseline_path_registers_and_scans also runs a
        # real scan on the registered agent, persisted to scan_results -
        # the agent_name is unique per test run (uuid-suffixed) so this
        # can't collide with anything real.
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM scan_results WHERE agent_name = ?", (self.agent_name,))
        conn.execute("DELETE FROM registered_agents WHERE name = ?", (self.agent_name,))
        conn.commit()
        conn.close()

    def test_reference_baseline_path_registers_and_scans(self):
        at = self.at

        # "Reference baseline model" path -> the 6-type selectbox appears
        at = at.radio(key="test_agent_register_agent_path").set_value("Reference baseline model").run()
        at.selectbox(key="test_agent_register_agent_type").set_value("Mock").run()
        at.text_input(key="test_agent_reg_name").set_value(self.agent_name).run()

        at = _click_register(at, 0)

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

        at = _click_register(at, 0)

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
        self.at = _authed_app_test()

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

        at = _click_register(at, 1)

        self.assertEqual([str(e) for e in at.exception], [])

        registered = get_agent_by_name(self.agent_name)
        self.assertIsNotNone(registered)
        self.assertEqual(registered["agent_type"], "mock")

        # It must show up in Monitor Production's own agent list (health
        # status cards / agent-actions selector), the whole point of
        # having the form there instead of only in "Test Agent".
        action_select = at.selectbox(key="monitor_action_agent")
        self.assertIn(self.agent_name, action_select.options)


class TestOperationsTestConnection(unittest.TestCase):
    """AppTest coverage for the "Test Connection" button on both entry
    paths - Quick type (Mock, no registration) and a Registered agent -
    plus the requirement that a failed test never blocks Run Scan."""

    def setUp(self):
        self.at = _authed_app_test()

    def test_quick_type_mock_agent_shows_success_badge(self):
        at = self.at
        # Quick type + Mock (Demo) is the default selection already - no
        # need to touch the (unkeyed) agent-type selectbox.
        at = at.button(key="test_connection_quick").click().run()

        self.assertEqual(
            [str(e) for e in at.exception], [],
            "Test Connection raised an unhandled exception",
        )
        self.assertTrue(
            any("badge-low" in m.value and "Connected" in m.value for m in at.markdown),
            "Success badge not rendered for the Mock agent connection test",
        )
        # A connection test must never run a full scan - no vulnerability
        # score card should appear as a side effect of clicking it.
        self.assertFalse(
            any("Vulnerability Score" in m.value for m in at.markdown),
            "Test Connection unexpectedly triggered a full scan",
        )

    def test_registered_agent_shows_success_badge(self):
        agent_name = f"conn-test-ok-{uuid.uuid4().hex[:8]}"
        agent = register_agent(agent_name, "mock")
        # Registered directly via core.agent_registry, bypassing the
        # dashboard's own registration form (which clears this cache
        # itself on submit - see render_registration_form) - clear it
        # here too, or _cached_list_agents' 60s TTL can serve a stale
        # list that doesn't include this agent yet.
        st.cache_data.clear()
        try:
            at = self.at
            at = at.radio(key="agent_source").set_value("Registered agent").run()
            select = at.selectbox(key="registered_agent_select")
            matching = [o for o in select.options if agent_name in o]
            self.assertTrue(matching, "Registered agent not found in the selector")
            at = select.set_value(matching[0]).run()

            at = at.button(key="test_connection_registered").click().run()

            self.assertEqual([str(e) for e in at.exception], [])
            self.assertTrue(
                any("badge-low" in m.value and "Connected" in m.value for m in at.markdown),
                "Success badge not rendered for the registered agent connection test",
            )
        finally:
            deactivate_agent(agent["id"])
            conn = sqlite3.connect(DB_PATH)
            conn.execute("DELETE FROM registered_agents WHERE id = ?", (agent["id"],))
            conn.commit()
            conn.close()

    def test_failed_connection_shows_error_badge_and_does_not_block_run_scan(self):
        agent_name = f"conn-test-fail-{uuid.uuid4().hex[:8]}"
        # Port 1 (reserved, nothing listens there) - refuses the
        # connection immediately, no timeout to wait out.
        agent = register_agent(
            agent_name, "remote_http", config={"endpoint_url": "http://127.0.0.1:1/nope"}
        )
        st.cache_data.clear()  # see test_registered_agent_shows_success_badge
        try:
            at = self.at
            at = at.radio(key="agent_source").set_value("Registered agent").run()
            select = at.selectbox(key="registered_agent_select")
            matching = [o for o in select.options if agent_name in o]
            self.assertTrue(matching, "Registered agent not found in the selector")
            at = select.set_value(matching[0]).run()

            at = at.button(key="test_connection_registered").click().run()

            self.assertEqual([str(e) for e in at.exception], [])
            self.assertTrue(
                any("Connection test failed" in m.value for m in at.markdown),
                "Failure badge not rendered for an unreachable agent",
            )
            self.assertTrue(
                any(b.label == "Run Scan" for b in at.button),
                "A failed connection test must not remove/block the Run Scan button",
            )
        finally:
            deactivate_agent(agent["id"])
            conn = sqlite3.connect(DB_PATH)
            conn.execute("DELETE FROM registered_agents WHERE id = ?", (agent["id"],))
            conn.commit()
            conn.close()


class TestApiKeyGate(unittest.TestCase):
    """The gate itself (see the module docstring) - a real generated key,
    not the session_state shortcut _authed_app_test() uses for the other
    test classes above."""

    def setUp(self):
        self.label = f"gate-test-{uuid.uuid4().hex[:8]}"
        self.raw_key = generate_key(self.label, db_path=AUTH_DB_PATH)

    def tearDown(self):
        conn = sqlite3.connect(AUTH_DB_PATH)
        conn.execute("DELETE FROM api_keys WHERE label = ?", (self.label,))
        conn.commit()
        conn.close()

    def test_blocked_without_key(self):
        at = AppTest.from_file(OPERATIONS_PAGE, default_timeout=30)
        at.run()

        self.assertEqual([str(e) for e in at.exception], [])
        self.assertIsNone(_gate_label(at))
        self.assertFalse(
            any(b.label == "Run Scan" for b in at.button),
            "Run Scan button rendered despite no API key in session",
        )
        self.assertTrue(
            any(ti.label == "API key" for ti in at.text_input),
            "Gate's API key input not shown when locked",
        )

    def test_invalid_key_stays_blocked_with_error(self):
        at = AppTest.from_file(OPERATIONS_PAGE, default_timeout=30)
        at.run()

        at.text_input(key="api_key_gate_input").set_value("not-a-real-key")
        at = _click_unlock(at)

        self.assertEqual([str(e) for e in at.exception], [])
        self.assertIsNone(_gate_label(at))
        self.assertTrue(
            any("Invalid or inactive API key" in e.value for e in at.error),
            "Expected an error banner for an invalid key",
        )
        self.assertFalse(any(b.label == "Run Scan" for b in at.button))

    def test_inactive_key_stays_blocked(self):
        from core.auth import deactivate_key
        deactivate_key(self.label, db_path=AUTH_DB_PATH)

        at = AppTest.from_file(OPERATIONS_PAGE, default_timeout=30)
        at.run()
        at.text_input(key="api_key_gate_input").set_value(self.raw_key)
        at = _click_unlock(at)

        self.assertIsNone(_gate_label(at))
        self.assertTrue(any("Invalid or inactive API key" in e.value for e in at.error))

    def test_valid_key_unlocks_the_page(self):
        at = AppTest.from_file(OPERATIONS_PAGE, default_timeout=30)
        at.run()

        at.text_input(key="api_key_gate_input").set_value(self.raw_key)
        at = _click_unlock(at)

        self.assertEqual([str(e) for e in at.exception], [])
        self.assertEqual(_gate_label(at), self.label)
        self.assertTrue(
            any(b.label == "Run Scan" for b in at.button),
            "Page did not render its normal content after a valid key",
        )


if __name__ == "__main__":
    unittest.main()
