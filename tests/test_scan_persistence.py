"""
Cross-path consistency for scan_results: a scan triggered from the
dashboard (dashboard/pages/operations.py's "Run Scan" button, via
AppTest) must be readable through the API's GET /scan/results/{id} - no
Python object shared between the two. Same principle as
test_monitoring_persistence.py for monitoring logs, now that both
surfaces converge on the same core/scan_store.py persistence (see the
scan-persistence vague's étape 4).
"""

import re
import sqlite3
import unittest
import uuid
from pathlib import Path

from fastapi.testclient import TestClient
from streamlit.testing.v1 import AppTest

from api.app import app
from core.auth import deactivate_key, generate_key

OPERATIONS_PAGE = str(
    Path(__file__).resolve().parent.parent / "dashboard" / "pages" / "operations.py"
)
THREATS_DB_PATH = "data/threats.db"
AUTH_DB_PATH = "data/auth.db"


class TestScanCrossPathConsistency(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.label = f"scan-xpath-test-{uuid.uuid4().hex[:8]}"
        cls.raw_key = generate_key(cls.label, db_path=AUTH_DB_PATH)

    @classmethod
    def tearDownClass(cls):
        deactivate_key(cls.label, db_path=AUTH_DB_PATH)
        conn = sqlite3.connect(AUTH_DB_PATH)
        conn.execute("DELETE FROM api_keys WHERE label = ?", (cls.label,))
        conn.commit()
        conn.close()

    def tearDown(self):
        conn = sqlite3.connect(THREATS_DB_PATH)
        conn.execute(
            "DELETE FROM scan_results WHERE triggered_by_key_label = ?", (self.label,)
        )
        conn.commit()
        conn.close()

    def test_scan_triggered_from_dashboard_is_readable_via_api(self):
        # Write path: what a human actually does - unlock the gated
        # dashboard page and click "Run Scan" (default selection: Quick
        # type / Mock, no interaction needed beyond the click).
        at = AppTest.from_file(OPERATIONS_PAGE, default_timeout=30)
        at.session_state["api_key_label"] = self.label
        at.run()

        run_scan = next(b for b in at.button if b.label == "Run Scan")
        at = run_scan.click().run()
        self.assertEqual([str(e) for e in at.exception], [])

        scan_complete_markdown = next(
            (m.value for m in at.markdown if "Scan complete" in m.value), None
        )
        self.assertIsNotNone(scan_complete_markdown, "dashboard did not report scan completion")
        match = re.search(r"Scan complete \(#(\d+)\)", scan_complete_markdown)
        self.assertIsNotNone(match, "scan id not found in the completion badge")
        scan_id = int(match.group(1))

        # Read path: the API's GET /scan/results/{id} - no object shared
        # with the Streamlit process that wrote it, just the same
        # data/threats.db file.
        response = self.client.get(
            f"/scan/results/{scan_id}", headers={"X-API-Key": self.raw_key}
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()

        self.assertEqual(body["status"], "completed")
        self.assertEqual(body["triggered_by_key_label"], self.label)
        self.assertEqual(body["agent_name"], "my_agent")
        self.assertEqual(body["total_tested"], 653)
        self.assertIsNotNone(body["completed_at"])
        self.assertIsNotNone(body["report"])
        self.assertEqual(body["report"]["total_threats"], 653)


if __name__ == "__main__":
    unittest.main()
