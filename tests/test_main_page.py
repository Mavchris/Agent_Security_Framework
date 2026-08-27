"""
AppTest regression guard for dashboard/main.py's "Platform Statistics"
section, which used to be hardcoded (226 threats, 8 types, 7 sources,
46%/93% - all stale, none tied to the real data). Confirms the displayed
KPI cards match the real data/threats.db counts, so they can't silently
drift out of date again.
"""

import sqlite3
import unittest
from pathlib import Path

from streamlit.testing.v1 import AppTest

MAIN_PAGE = str(Path(__file__).resolve().parent.parent / "dashboard" / "main.py")
DB_PATH = "data/threats.db"


class TestMainPageStatistics(unittest.TestCase):

    def setUp(self):
        self.at = AppTest.from_file(MAIN_PAGE, default_timeout=30)
        self.at.run()

    def test_loads_without_exception(self):
        self.assertEqual([str(e) for e in self.at.exception], [])

    def test_kpi_cards_match_real_database_counts(self):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM threats")
        expected_total = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(DISTINCT threat_type) FROM threats")
        expected_types = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(DISTINCT source) FROM threats")
        expected_sources = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM registered_agents WHERE is_active = 1")
        expected_agents = cursor.fetchone()[0]
        conn.close()

        kpi_cards = {}
        for m in self.at.markdown:
            if 'class="kpi-label"' in m.value and 'class="kpi-value"' in m.value:
                label = m.value.split('class="kpi-label">', 1)[1].split("<", 1)[0]
                value = m.value.split('class="kpi-value">', 1)[1].split("<", 1)[0]
                kpi_cards[label] = value

        self.assertEqual(kpi_cards.get("Total Threats"), str(expected_total))
        self.assertEqual(kpi_cards.get("Threat Categories"), str(expected_types))
        self.assertEqual(kpi_cards.get("Intelligence Sources"), str(expected_sources))
        self.assertEqual(kpi_cards.get("Registered Agents"), str(expected_agents))

    def test_documentation_links_point_to_github_not_broken_relative_paths(self):
        found = False
        for m in self.at.markdown:
            if "README" in m.value and "github.com" in m.value:
                found = True
                self.assertNotIn("../README.md", m.value)
                self.assertNotIn("docs/architecture.md", m.value)
        self.assertTrue(found, "Documentation quick links section not found")


if __name__ == "__main__":
    unittest.main()
