"""
One-off manual maintenance script, not part of the automated pipeline (run
from the repository root).

Create the scan_results table (async scan persistence - see core/scan_store.py,
API_DOCUMENTATION.md, SECURITY.md). Lives in data/threats.db, not a separate
file: agent_id is a real SQL foreign key to registered_agents, which only
works because they're in the same file (SQLite can't enforce one across
separate database files - see monitoring_logs/monitoring_alerts for the
plain-TEXT-no-FK alternative used when that's not possible). Note that
FK enforcement itself is off by default in SQLite and this codebase never
turns it on (PRAGMA foreign_keys) - the REFERENCES clause here is
documentation of intent, not an enforced constraint.

Idempotent: safe to re-run, does nothing if the table already exists.

No index on agent_id/status: audited (see scripts/maintenance/add_query_indexes.py)
and confirmed nothing anywhere in the codebase ever filters this table by
either column - every real access goes through the primary key `id`. Indexing
them added write overhead for zero read benefit, so they were dropped there
and are not created here either.
"""

import sqlite3

DB_PATH = 'data/threats.db'

# vulnerability_score is nullable and stays NULL whenever nothing was
# actually testable (status='completed' but every threat technical-
# errored) - never coerced to 0, which would look identical to a real
# clean scan. NULL also occurs for status in ('pending', 'running')
# simply because the score isn't computed yet - a consumer must check
# status before drawing any conclusion from a NULL score (see
# API_DOCUMENTATION.md).
CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id INTEGER REFERENCES registered_agents(id),
    agent_name TEXT NOT NULL,
    triggered_by_key_label TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    total_tested INTEGER,
    vulnerabilities_found INTEGER,
    safe_threats INTEGER,
    technical_errors INTEGER,
    vulnerability_score REAL,
    report_json TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
)
"""

def main():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='scan_results'"
    )
    already_exists = cursor.fetchone() is not None

    cursor.execute(CREATE_TABLE_SQL)
    conn.commit()
    conn.close()

    if already_exists:
        print("scan_results already existed - no change made.")
    else:
        print("Created scan_results table.")


if __name__ == '__main__':
    main()
