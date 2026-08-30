"""
One-off manual maintenance script, not part of the automated pipeline (run from the repository root).

Create monitoring_logs and monitoring_alerts in their own database file,
data/monitoring.db - deliberately separate from data/threats.db (the
public threat catalog). These tables can contain real production
prompt/response text from monitored agents; keeping them in a different
file limits the chance of that text leaking out through something that
exports/shares "the threat catalog" without realizing it now also holds
monitoring history (see SECURITY.md). Idempotent: safe to re-run.

agent_id is a plain INTEGER, not a SQL foreign key: SQLite can't enforce
a FOREIGN KEY across two separate database files, so the link to
registered_agents (in data/threats.db) is maintained at the application
level (core/agent_registry.get_agent_by_name), not by the schema. It's
nullable - an agent doesn't have to be pre-registered to log monitoring
activity, matching the existing POST /monitoring/log-request behavior.

created_by_key_label is the same kind of plain-TEXT, no-FK link to a
named API key (data/auth.db, core/auth.py) - present here so a brand-new
database gets it in one shot; a database created before this feature
existed needs scripts/maintenance/add_api_key_attribution_columns.py
instead.
"""

import sqlite3

DB_PATH = 'data/monitoring.db'

CREATE_LOGS_SQL = """
CREATE TABLE IF NOT EXISTS monitoring_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id INTEGER,
    agent_name TEXT NOT NULL,
    user_id TEXT,
    session_id TEXT,
    prompt TEXT NOT NULL,
    response TEXT NOT NULL,
    risk_level TEXT NOT NULL CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    alert_triggered BOOLEAN NOT NULL DEFAULT 0,
    detected_threats TEXT NOT NULL DEFAULT '[]',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by_key_label TEXT
)
"""

CREATE_ALERTS_SQL = """
CREATE TABLE IF NOT EXISTS monitoring_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id INTEGER REFERENCES monitoring_logs(id),
    agent_id INTEGER,
    agent_name TEXT NOT NULL,
    user_id TEXT,
    session_id TEXT,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    message TEXT NOT NULL,
    detected_threats TEXT NOT NULL DEFAULT '[]',
    resolved BOOLEAN NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by_key_label TEXT
)
"""

CREATE_INDEXES_SQL = [
    "CREATE INDEX IF NOT EXISTS idx_monitoring_logs_agent_name ON monitoring_logs(agent_name)",
    "CREATE INDEX IF NOT EXISTS idx_monitoring_alerts_agent_name ON monitoring_alerts(agent_name)",
    "CREATE INDEX IF NOT EXISTS idx_monitoring_alerts_log_id ON monitoring_alerts(log_id)",
]


def main():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name IN ('monitoring_logs', 'monitoring_alerts')"
    )
    already_exists = {row[0] for row in cursor.fetchall()}

    cursor.execute(CREATE_LOGS_SQL)
    cursor.execute(CREATE_ALERTS_SQL)
    for stmt in CREATE_INDEXES_SQL:
        cursor.execute(stmt)
    conn.commit()
    conn.close()

    for table in ('monitoring_logs', 'monitoring_alerts'):
        if table in already_exists:
            print(f"{table} already existed - no change made.")
        else:
            print(f"Created {table}.")


if __name__ == '__main__':
    main()
