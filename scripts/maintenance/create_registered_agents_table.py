"""
One-off manual maintenance script, not part of the automated pipeline (run from the repository root).

Create the registered_agents table (multi-agent registry - see
README/ARCHITECTURE for the feature). Idempotent: safe to re-run, does
nothing if the table already exists. No data to migrate - this is a
fresh table, not an alteration of existing data.

created_by_key_label/deactivated_by_key_label are named-API-key
attribution columns (see core/auth.py, SECURITY.md) - present here so a
brand-new database gets them in one shot; a database created before this
feature existed needs
scripts/maintenance/add_api_key_attribution_columns.py instead.
"""

import sqlite3

DB_PATH = 'data/threats.db'

# agent_type is constrained to what testing/agent_wrappers.py's
# get_agent_wrapper() actually supports as a registry entry (canonical
# names only - 'gpt-4'/'hf' aliases are a get_agent_wrapper() convenience,
# not stored here). No 'huggingface' - it crashes when loaded into the
# same process as pandas/pyarrow on this project's Windows environment;
# a HuggingFace-backed agent is registered as 'remote_http' instead, see
# docs/examples/huggingface_agent_server.py and core/agent_registry.py's
# VALID_AGENT_TYPES.
CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS registered_agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    agent_type TEXT NOT NULL CHECK (agent_type IN (
        'mock', 'claude', 'openai', 'mistral', 'llama', 'remote_http'
    )),
    config TEXT NOT NULL DEFAULT '{}',
    environment TEXT,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by_key_label TEXT,
    deactivated_by_key_label TEXT
)
"""


def main():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='registered_agents'"
    )
    already_exists = cursor.fetchone() is not None

    cursor.execute(CREATE_TABLE_SQL)
    conn.commit()
    conn.close()

    if already_exists:
        print("registered_agents already existed - no change made.")
    else:
        print("Created registered_agents table.")


if __name__ == '__main__':
    main()
