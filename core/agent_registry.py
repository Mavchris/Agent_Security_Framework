"""
Agent registry - CRUD for the registered_agents table (persistent
multi-agent support, see README/ARCHITECTURE). Shared by the dashboard
so "Test Agent" and "Monitor Production" converge on the same source of
truth instead of duplicating this logic, and usable later by the API/CLI
without having to re-implement it.

config is stored as a JSON string in the DB; every function here works
with it as a plain Python dict at the call boundary. Secrets never go
in config - only e.g. an auth_env_var *name*, the real value stays in
config/.env.local (see SECURITY.md).
"""

import json
import sqlite3
from typing import Any, Dict, List, Optional

DB_PATH = 'data/threats.db'

# Mirrors the CHECK constraint on registered_agents.agent_type
# (scripts/maintenance/create_registered_agents_table.py) and what
# testing/agent_wrappers.py's get_agent_wrapper() actually supports.
VALID_AGENT_TYPES = {
    'mock', 'claude', 'openai', 'mistral', 'llama', 'huggingface', 'remote_http',
}


def _get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    agent = dict(row)
    agent['config'] = json.loads(agent['config']) if agent['config'] else {}
    agent['is_active'] = bool(agent['is_active'])
    return agent


def register_agent(
    name: str,
    agent_type: str,
    config: Optional[Dict[str, Any]] = None,
    environment: Optional[str] = None,
    db_path: str = DB_PATH,
) -> Dict[str, Any]:
    """
    Register a new agent.

    Raises:
        ValueError: unknown agent_type, or a duplicate name (both are
            also enforced by the DB schema itself - checked here first
            purely for a clearer error message than sqlite3.IntegrityError).
    """
    if agent_type not in VALID_AGENT_TYPES:
        raise ValueError(
            f"Unknown agent_type: {agent_type!r}. Must be one of: {sorted(VALID_AGENT_TYPES)}"
        )

    conn = _get_connection(db_path)
    try:
        cursor = conn.execute(
            'INSERT INTO registered_agents (name, agent_type, config, environment) '
            'VALUES (?, ?, ?, ?)',
            (name, agent_type, json.dumps(config or {}), environment),
        )
        conn.commit()
        agent_id = cursor.lastrowid
    except sqlite3.IntegrityError as e:
        raise ValueError(f"Could not register agent {name!r}: {e}") from e
    finally:
        conn.close()

    return get_agent_config(agent_id, db_path=db_path)


def list_agents(
    environment: Optional[str] = None,
    active_only: bool = True,
    db_path: str = DB_PATH,
) -> List[Dict[str, Any]]:
    """List registered agents, most recently created first."""
    conn = _get_connection(db_path)
    try:
        query = 'SELECT * FROM registered_agents WHERE 1=1'
        params: List[Any] = []
        if active_only:
            query += ' AND is_active = 1'
        if environment:
            query += ' AND environment = ?'
            params.append(environment)
        query += ' ORDER BY created_at DESC'
        rows = conn.execute(query, params).fetchall()
    finally:
        conn.close()

    return [_row_to_dict(row) for row in rows]


def get_agent_config(agent_id: int, db_path: str = DB_PATH) -> Optional[Dict[str, Any]]:
    """Get a single registered agent by ID, or None if it doesn't exist
    (including if it was deactivated - deactivate_agent() doesn't delete
    the row, so callers that must exclude inactive agents should check
    the returned dict's 'is_active' field)."""
    conn = _get_connection(db_path)
    try:
        row = conn.execute(
            'SELECT * FROM registered_agents WHERE id = ?', (agent_id,)
        ).fetchone()
    finally:
        conn.close()

    return _row_to_dict(row) if row else None


def get_agent_by_name(name: str, db_path: str = DB_PATH) -> Optional[Dict[str, Any]]:
    """Get a single registered agent by its (unique) name, or None if no
    agent is registered under that name. Used to link monitoring activity
    for an arbitrary agent_name back to a registered agent, when one
    exists - see monitoring/monitoring_store.py."""
    conn = _get_connection(db_path)
    try:
        row = conn.execute(
            'SELECT * FROM registered_agents WHERE name = ?', (name,)
        ).fetchone()
    finally:
        conn.close()

    return _row_to_dict(row) if row else None


def deactivate_agent(agent_id: int, db_path: str = DB_PATH) -> bool:
    """Soft-delete: set is_active=0 rather than removing the row, so
    monitoring history tied to this agent isn't orphaned. Returns True
    if a matching row was found and updated."""
    conn = _get_connection(db_path)
    try:
        cursor = conn.execute(
            'UPDATE registered_agents SET is_active = 0 WHERE id = ?', (agent_id,)
        )
        conn.commit()
    finally:
        conn.close()

    return cursor.rowcount > 0


def build_wrapper(agent: Dict[str, Any]):
    """Instantiate a working AgentWrapper for a registered agent dict (as
    returned by list_agents()/get_agent_config()), via the same factory
    used for one-off, non-registered agents."""
    from testing.agent_wrappers import get_agent_wrapper
    return get_agent_wrapper(agent['agent_type'], **agent['config'])
