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
import secrets
import sqlite3
from datetime import datetime
from typing import Optional

DB_PATH = 'data/auth.db'

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL UNIQUE,
    key_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT 1
)
"""


def _get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    # Idempotent and cheap - guarantees no separate "run this migration
    # first" step before the very first key can be created.
    conn.execute(CREATE_TABLE_SQL)
    return conn


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode('utf-8')).hexdigest()


def generate_key(label: str, db_path: str = DB_PATH) -> str:
    """Create a new API key for `label`. Returns the raw key - this is the
    only time it is ever available; only its hash is stored.

    Raises:
        ValueError: a key already exists under this label.
    """
    raw_key = f"asif_{secrets.token_urlsafe(32)}"

    conn = _get_connection(db_path)
    try:
        conn.execute(
            'INSERT INTO api_keys (label, key_hash) VALUES (?, ?)',
            (label, _hash_key(raw_key)),
        )
        conn.commit()
    except sqlite3.IntegrityError as e:
        raise ValueError(f"A key already exists under label {label!r}: {e}") from e
    finally:
        conn.close()

    return raw_key


def verify_key(raw_key: Optional[str], db_path: str = DB_PATH) -> Optional[str]:
    """Check a candidate key. Returns the key's label if it's valid and
    active (and stamps last_used_at), None otherwise - including for an
    empty/missing key, so callers can pass a header value straight
    through without a separate not-None check."""
    if not raw_key:
        return None

    conn = _get_connection(db_path)
    try:
        row = conn.execute(
            'SELECT label, is_active FROM api_keys WHERE key_hash = ?',
            (_hash_key(raw_key),),
        ).fetchone()
        if row is None or not row['is_active']:
            return None

        conn.execute(
            'UPDATE api_keys SET last_used_at = ? WHERE label = ?',
            (datetime.now().isoformat(), row['label']),
        )
        conn.commit()
        return row['label']
    finally:
        conn.close()


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
