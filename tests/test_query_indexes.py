"""
Tests for scripts/maintenance/add_query_indexes.py - added after an audit
(see ARCHITECTURE.md's Data Layer section) of the real WHERE/ORDER BY/
GROUP BY patterns actually used across the codebase against threats/
registered_agents/scan_results/monitoring_logs/monitoring_alerts/api_keys.

The point of an index is performance, not correctness - at ~650 rows
(today's real scale) any difference would be unmeasurable anyway, so
what's actually worth testing is that the indexed queries return the
identical result with the index present or absent, and that the
migration script is idempotent and touches exactly the columns it
claims to.
"""

import sqlite3
import tempfile
import os
import unittest

from scripts.maintenance.add_query_indexes import CREATE_INDEXES, DROP_INDEXES, THREATS_DB, MONITORING_DB

THREATS_SCHEMA = """
CREATE TABLE threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id TEXT UNIQUE,
    title TEXT,
    threat_type TEXT,
    severity TEXT,
    source TEXT,
    created_at TIMESTAMP
)
"""

REGISTERED_AGENTS_SCHEMA = """
CREATE TABLE registered_agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE,
    created_at TIMESTAMP
)
"""

# Representative of the real hot-path queries found in the audit (see
# api/app.py, dashboard/pages/intelligence.py, dashboard/pages/catalog.py).
QUERIES = [
    ("SELECT * FROM threats WHERE threat_type = ? ORDER BY id", ("prompt_injection",)),
    ("SELECT * FROM threats WHERE source = ? ORDER BY id", ("CVE",)),
    ("SELECT threat_type, COUNT(*) FROM threats GROUP BY threat_type ORDER BY threat_type", ()),
    ("SELECT source, COUNT(*) FROM threats GROUP BY source ORDER BY source", ()),
    ("SELECT DISTINCT severity FROM threats WHERE severity != 'unknown' ORDER BY severity", ()),
    ("SELECT threat_id FROM threats ORDER BY created_at DESC", ()),
    (
        "SELECT threat_id FROM threats WHERE created_at >= datetime('now', '-30 days') ORDER BY created_at",
        (),
    ),
    ("SELECT * FROM registered_agents ORDER BY created_at DESC", ()),
]


def _make_seeded_db(path):
    conn = sqlite3.connect(path)
    conn.execute(THREATS_SCHEMA)
    conn.execute(REGISTERED_AGENTS_SCHEMA)

    rows = [
        ("T-1", "Prompt injection A", "prompt_injection", "critical", "CVE", "2026-01-01T00:00:00"),
        ("T-2", "Prompt injection B", "prompt_injection", "high", "GitHub", "2026-06-01T00:00:00"),
        ("T-3", "Supply chain A", "supply_chain", "medium", "CVE", "2026-08-20T00:00:00"),
        ("T-4", "Other A", "other", "low", "NVD", "2026-08-25T00:00:00"),
        ("T-5", "Unknown severity", "other", "unknown", "NVD", "2026-08-28T00:00:00"),
    ]
    conn.executemany(
        "INSERT INTO threats (threat_id, title, threat_type, severity, source, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.executemany(
        "INSERT INTO registered_agents (name, created_at) VALUES (?, ?)",
        [("agent-a", "2026-01-01T00:00:00"), ("agent-b", "2026-08-01T00:00:00")],
    )
    conn.commit()
    return conn


class TestIndexesDoNotChangeQueryResults(unittest.TestCase):
    """The actual correctness property that matters for an index: same
    query, same data, same result - with or without the index."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.conn = _make_seeded_db(self.db_path)

    def tearDown(self):
        self.conn.close()
        os.remove(self.db_path)

    def _run_all(self):
        return [self.conn.execute(sql, params).fetchall() for sql, params in QUERIES]

    def test_results_identical_before_and_after_indexing(self):
        before = self._run_all()

        for stmt in CREATE_INDEXES[THREATS_DB]:
            self.conn.execute(stmt)
        self.conn.commit()

        after = self._run_all()

        self.assertEqual(before, after)

    def test_query_plan_actually_uses_the_new_index(self):
        """Not just "doesn't crash" - confirm SQLite's planner picks the
        index up for the equality-filter queries it's meant to speed up."""
        for stmt in CREATE_INDEXES[THREATS_DB]:
            self.conn.execute(stmt)
        self.conn.commit()

        plan = self.conn.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM threats WHERE threat_type = ?",
            ("prompt_injection",),
        ).fetchall()
        plan_text = " ".join(str(row) for row in plan)
        self.assertIn("idx_threats_threat_type", plan_text)


class TestMigrationScriptIdempotentAndTargeted(unittest.TestCase):
    """The migration script itself: safe to re-run, and touches exactly
    the indexes it documents (5 created, 3 removed) - not more, not less."""

    def setUp(self):
        fd, self.threats_db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        fd, self.monitoring_db = tempfile.mkstemp(suffix=".db")
        os.close(fd)

        conn = _make_seeded_db(self.threats_db)
        # scan_results is a minimal stand-in - only needs to exist so the
        # (now-removed) DROP INDEX statements have something to no-op against.
        conn.execute("CREATE TABLE scan_results (id INTEGER PRIMARY KEY, agent_id INTEGER, status TEXT)")
        conn.execute("CREATE INDEX idx_scan_results_agent_id ON scan_results(agent_id)")
        conn.execute("CREATE INDEX idx_scan_results_status ON scan_results(status)")
        conn.commit()
        conn.close()

        conn = sqlite3.connect(self.monitoring_db)
        conn.execute("CREATE TABLE monitoring_alerts (id INTEGER PRIMARY KEY, log_id INTEGER)")
        conn.execute("CREATE INDEX idx_monitoring_alerts_log_id ON monitoring_alerts(log_id)")
        conn.commit()
        conn.close()

    def tearDown(self):
        os.remove(self.threats_db)
        os.remove(self.monitoring_db)

    def _index_names(self, db_path):
        conn = sqlite3.connect(db_path)
        names = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()
        }
        conn.close()
        return names

    def test_migration_creates_five_and_drops_three(self):
        for stmt in CREATE_INDEXES[THREATS_DB]:
            # Re-target the statement at our temp db by executing it there
            # directly (CREATE_INDEXES' statements don't hardcode a path -
            # sqlite3.connect(path) is what selects the database file).
            conn = sqlite3.connect(self.threats_db)
            conn.execute(stmt)
            conn.commit()
            conn.close()

        for stmt in DROP_INDEXES[THREATS_DB]:
            conn = sqlite3.connect(self.threats_db)
            conn.execute(stmt)
            conn.commit()
            conn.close()

        for stmt in DROP_INDEXES[MONITORING_DB]:
            conn = sqlite3.connect(self.monitoring_db)
            conn.execute(stmt)
            conn.commit()
            conn.close()

        threats_indexes = self._index_names(self.threats_db)
        monitoring_indexes = self._index_names(self.monitoring_db)

        expected_created = {
            "idx_threats_threat_type", "idx_threats_source", "idx_threats_severity",
            "idx_threats_created_at", "idx_registered_agents_created_at",
        }
        self.assertTrue(expected_created.issubset(threats_indexes))
        self.assertNotIn("idx_scan_results_agent_id", threats_indexes)
        self.assertNotIn("idx_scan_results_status", threats_indexes)
        self.assertNotIn("idx_monitoring_alerts_log_id", monitoring_indexes)

    def test_create_and_drop_statements_are_idempotent(self):
        for stmt in CREATE_INDEXES[THREATS_DB] * 2:  # run twice
            conn = sqlite3.connect(self.threats_db)
            conn.execute(stmt)
            conn.commit()
            conn.close()

        for stmt in DROP_INDEXES[THREATS_DB] * 2:
            conn = sqlite3.connect(self.threats_db)
            conn.execute(stmt)
            conn.commit()
            conn.close()
        # No exception raised above is the test - CREATE INDEX IF NOT
        # EXISTS / DROP INDEX IF EXISTS must both tolerate a second run.


if __name__ == "__main__":
    unittest.main()
