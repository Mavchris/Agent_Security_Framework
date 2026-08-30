"""
One-off manual maintenance script, not part of the automated pipeline (run
from the repository root).

Adds the API-key attribution columns used by core/agent_registry.py and
monitoring/monitoring_store.py once named API keys exist (see core/auth.py,
SECURITY.md, ROADMAP.md):

- registered_agents.created_by_key_label / deactivated_by_key_label
  (data/threats.db)
- monitoring_logs.created_by_key_label / monitoring_alerts.created_by_key_label
  (data/monitoring.db)

All nullable - rows that predate this feature simply have no attribution,
same NULL-means-"not tracked" convention as e.g. threats.translated_at.
Idempotent: safe to re-run, existing columns are skipped, not re-added.
"""

import sqlite3

THREATS_DB = 'data/threats.db'
MONITORING_DB = 'data/monitoring.db'


def _add_column(conn, table, column, coltype):
    try:
        conn.execute(f'ALTER TABLE {table} ADD COLUMN {column} {coltype}')
        conn.commit()
        print(f"Added {table}.{column}.")
    except sqlite3.OperationalError:
        print(f"{table}.{column} already exists - no change made.")


def main():
    conn = sqlite3.connect(THREATS_DB)
    _add_column(conn, 'registered_agents', 'created_by_key_label', 'TEXT')
    _add_column(conn, 'registered_agents', 'deactivated_by_key_label', 'TEXT')
    conn.close()

    conn = sqlite3.connect(MONITORING_DB)
    _add_column(conn, 'monitoring_logs', 'created_by_key_label', 'TEXT')
    _add_column(conn, 'monitoring_alerts', 'created_by_key_label', 'TEXT')
    conn.close()


if __name__ == '__main__':
    main()
