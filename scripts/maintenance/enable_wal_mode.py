"""
One-off manual maintenance script, not part of the automated pipeline (run from the
repository root).

Switch data/threats.db, data/monitoring.db, and data/auth.db from SQLite's default
rollback-journal mode to WAL (write-ahead log). Journal mode is stored in the database
file itself, so this only needs to run once per file - it is not something every
connection needs to set. Idempotent: safe to re-run (PRAGMA journal_mode=WAL on an
already-WAL database is a no-op that just reports the current mode back).

Why: readers (dashboards, the API) and writers (the pipeline, the orchestrator) open
the same files concurrently. In the default rollback-journal mode a writer holds an
exclusive lock for the duration of its transaction, so a concurrent reader can hit
"database is locked". WAL lets readers proceed against the last-committed snapshot
while a writer is active.
"""

import sqlite3

DB_PATHS = ['data/threats.db', 'data/monitoring.db', 'data/auth.db']


def main():
    for db_path in DB_PATHS:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        mode = cursor.fetchone()[0]
        conn.close()
        print(f"{db_path}: journal_mode={mode}")


if __name__ == '__main__':
    main()
