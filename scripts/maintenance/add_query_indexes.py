"""
One-off manual maintenance script, not part of the automated pipeline (run
from the repository root).

Adds indexes for query patterns actually observed in the codebase (grepped
across pipeline/, api/, dashboard/, core/, monitoring/, scripts/maintenance/ -
see ARCHITECTURE.md's Data Layer section for the summary): threats.threat_type/
source/severity/created_at and registered_agents.created_at are each filtered,
grouped, or sorted by on a hot path (public API endpoints, every dashboard
page load) with no index behind them. At the current scale (~650 threats, 2
agents) the effect is not measurable - this is preparation for growth, not a
fix for an observed slowdown; say so if anyone asks why it was done now.

threats.ai_relevant and registered_agents.is_active were deliberately left
out despite being filtered on a hot path too - both are near-boolean columns
with poor selectivity, where an index rarely helps SQLite's query planner
choose it over a full scan.

Also drops 3 indexes that the same audit found have no matching query
anywhere in the codebase - scan_results.agent_id/status and
monitoring_alerts.log_id are indexed, but every real read/write against
those tables goes through the primary key `id`, never through these
columns. An index with no matching query only costs write overhead for
zero read benefit, so they're removed rather than kept "just in case" -
consistent with this script's own premise of indexing from observed usage,
not preventively. create_scan_results_table.py and
create_monitoring_tables.py no longer create them either, so a brand-new
database doesn't reintroduce what this script just removed.

Idempotent: safe to re-run (CREATE INDEX IF NOT EXISTS / DROP INDEX IF
EXISTS both no-op on a second run).
"""

import sqlite3

THREATS_DB = 'data/threats.db'
MONITORING_DB = 'data/monitoring.db'

# registered_agents lives in the same file as threats (see
# create_registered_agents_table.py), hence both under THREATS_DB here.
CREATE_INDEXES = {
    THREATS_DB: [
        "CREATE INDEX IF NOT EXISTS idx_threats_threat_type ON threats(threat_type)",
        "CREATE INDEX IF NOT EXISTS idx_threats_source ON threats(source)",
        "CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity)",
        "CREATE INDEX IF NOT EXISTS idx_threats_created_at ON threats(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_registered_agents_created_at ON registered_agents(created_at)",
    ],
}

DROP_INDEXES = {
    THREATS_DB: [
        "DROP INDEX IF EXISTS idx_scan_results_agent_id",
        "DROP INDEX IF EXISTS idx_scan_results_status",
    ],
    MONITORING_DB: [
        "DROP INDEX IF EXISTS idx_monitoring_alerts_log_id",
    ],
}


def main():
    for db_path, statements in CREATE_INDEXES.items():
        conn = sqlite3.connect(db_path)
        for stmt in statements:
            conn.execute(stmt)
        conn.commit()
        conn.close()
        print(f"{db_path}: ensured {len(statements)} index(es) exist.")

    for db_path, statements in DROP_INDEXES.items():
        conn = sqlite3.connect(db_path)
        for stmt in statements:
            conn.execute(stmt)
        conn.commit()
        conn.close()
        print(f"{db_path}: ensured {len(statements)} unused index(es) are gone.")


if __name__ == '__main__':
    main()
