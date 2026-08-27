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
from pathlib import Path

from streamlit.testing.v1 import AppTest

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


if __name__ == "__main__":
    unittest.main()
