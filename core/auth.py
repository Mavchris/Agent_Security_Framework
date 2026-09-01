"""
Named API key authentication (see SECURITY.md and ROADMAP.md's short-term
authentication plan).

Keys are opaque, high-entropy random tokens (secrets.token_urlsafe) - never
stored in plaintext, only key_hash (SHA-256 of the raw key) is persisted.
SHA-256 rather than a slow password KDF (bcrypt/argon2) is deliberate: this
hashes a 256-bit random token, not a human-chosen password, so there's no
dictionary/brute-force surface a slow KDF would need to defend against -
the entropy already lives in the key itself.

Kept in its own database file, data/auth.db, separate from data/threats.db
(the public threat catalog, safe to export/share as-is) and
data/monitoring.db (production prompt/response text). Auth material
shouldn't travel with either - see create_monitoring_tables.py for the
same reasoning applied to that split.
"""

import hashlib
import logging
import secrets
import sqlite3
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DB_PATH = 'data/auth.db'

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL UNIQUE,
    key_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    expires_at TIMESTAMP
)
"""


def _get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    # Idempotent and cheap - guarantees no separate "run this migration
    # first" step before the very first key can be created. expires_at is
    # in CREATE_TABLE_SQL for brand-new databases; for one created before
    # this column existed, add it here the same idempotent way (see
    # scripts/maintenance/add_api_key_attribution_columns.py for the same
    # pattern applied to other tables) - NULL for every pre-existing row,
    # so already-issued keys keep never expiring (backward compatible).
    conn.execute(CREATE_TABLE_SQL)
    try:
        conn.execute('ALTER TABLE api_keys ADD COLUMN expires_at TIMESTAMP')
        conn.commit()
    except sqlite3.OperationalError:
        pass  # column already exists
    return conn


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode('utf-8')).hexdigest()


def generate_key(
    label: str, db_path: str = DB_PATH, expires_in_days: Optional[int] = None
) -> str:
    """Create a new API key for `label`. Returns the raw key - this is the
    only time it is ever available; only its hash is stored.

    Args:
        expires_in_days: if given, the key stops verifying after this many
            days (see verify_key). Omitted/None means no expiration - the
            same behavior as before this parameter existed, so existing
            callers (and already-issued keys) are unaffected.

    Raises:
        ValueError: a key already exists under this label.
    """
    raw_key = f"asif_{secrets.token_urlsafe(32)}"
    expires_at = (
        (datetime.now() + timedelta(days=expires_in_days)).isoformat()
        if expires_in_days is not None
        else None
    )

    conn = _get_connection(db_path)
    try:
        conn.execute(
            'INSERT INTO api_keys (label, key_hash, expires_at) VALUES (?, ?, ?)',
            (label, _hash_key(raw_key), expires_at),
        )
        conn.commit()
    except sqlite3.IntegrityError as e:
        raise ValueError(f"A key already exists under label {label!r}: {e}") from e
    finally:
        conn.close()

    return raw_key


def verify_key(raw_key: Optional[str], db_path: str = DB_PATH) -> Optional[str]:
    """Check a candidate key. Returns the key's label if it's valid,
    active, and not expired (and stamps last_used_at), None otherwise -
    including for an empty/missing key, so callers can pass a header
    value straight through without a separate not-None check.

    An expired key returns None here exactly like a deactivated one - the
    caller (require_api_key in api/app.py) gives the client the same
    generic 401 either way; only this function's own server-side log
    line below distinguishes unknown/inactive/expired."""
    if not raw_key:
        return None

    conn = _get_connection(db_path)
    try:
        row = conn.execute(
            'SELECT label, is_active, expires_at FROM api_keys WHERE key_hash = ?',
            (_hash_key(raw_key),),
        ).fetchone()
        if row is None:
            return None

        status = _status(row['is_active'], row['expires_at'])
        if status != 'active':
            logger.warning(
                "Rejected API key: label=%r reason=%s", row['label'], status
            )
            return None

        conn.execute(
            'UPDATE api_keys SET last_used_at = ? WHERE label = ?',
            (datetime.now().isoformat(), row['label']),
        )
        conn.commit()
        return row['label']
    finally:
        conn.close()


def _status(is_active: bool, expires_at: Optional[str]) -> str:
    if not is_active:
        return 'inactive'
    if expires_at is not None and expires_at <= datetime.now().isoformat():
        return 'expired'
    return 'active'


def list_keys(db_path: str = DB_PATH) -> List[Dict[str, Any]]:
    """All keys with a derived status ('active'/'inactive'/'expired') -
    never the key itself, only its hash is ever stored (see module
    docstring), so there is nothing to return even if a caller wanted it.
    Used by scripts/maintenance/list_api_keys.py (see ROADMAP.md's
    named-API-key follow-ups: there was previously no way to see what
    keys exist without querying data/auth.db directly)."""
    conn = _get_connection(db_path)
    try:
        rows = conn.execute(
            'SELECT label, created_at, last_used_at, is_active, expires_at '
            'FROM api_keys ORDER BY created_at'
        ).fetchall()
    finally:
        conn.close()

    return [
        {
            'label': row['label'],
            'created_at': row['created_at'],
            'last_used_at': row['last_used_at'],
            'expires_at': row['expires_at'],
            'status': _status(row['is_active'], row['expires_at']),
        }
        for row in rows
    ]


def deactivate_key(label: str, db_path: str = DB_PATH) -> bool:
    """Revoke a key without deleting its row, so past attribution
    (created_by_key_label on registered_agents/monitoring_logs/
    monitoring_alerts) stays meaningful. Returns True if a matching
    label was found."""
    conn = _get_connection(db_path)
    try:
        cursor = conn.execute(
            'UPDATE api_keys SET is_active = 0 WHERE label = ?', (label,)
        )
        conn.commit()
    finally:
        conn.close()

    return cursor.rowcount > 0
