"""
Persistence for asynchronous agent vulnerability scans (scan_results
table, data/threats.db - see scripts/maintenance/create_scan_results_table.py,
SECURITY.md, API_DOCUMENTATION.md).

This module only persists scans; it never runs one - api/app.py's
POST /scan orchestrates create_scan() -> mark_running() -> the actual
AgentVulnerabilityScanner.scan_all_threats() call (via a FastAPI
BackgroundTask) -> mark_completed()/mark_failed(), the same separation
already used elsewhere (core/agent_registry.py stores agents,
testing/agent_wrappers.py runs them; monitoring/monitoring_store.py
stores logs, monitoring/agent_monitor.py detects threats in them).

No queue, no worker process: a scan just runs in a background thread of
the API's own process (FastAPI's BackgroundTasks). Assumed limitation -
acceptable at this project's scale, not a hardened job system: a server
restart while a scan is 'running' loses it silently (the row is left
stuck in 'running' forever, with no automatic recovery/resumption). See
DEPLOYMENT.md.
"""

import json
import sqlite3
from datetime import datetime
from typing import Any, Dict, Optional

DB_PATH = 'data/threats.db'


def _get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    scan = dict(row)
    if scan.get('report_json'):
        scan['report'] = json.loads(scan['report_json'])
    else:
        scan['report'] = None
    del scan['report_json']
    return scan


def create_scan(
    agent_name: str,
    agent_id: Optional[int] = None,
    triggered_by_key_label: Optional[str] = None,
    db_path: str = DB_PATH,
) -> Dict[str, Any]:
    """Create a new scan row in status='pending'. Returns the stored row."""
    conn = _get_connection(db_path)
    try:
        cursor = conn.execute(
            'INSERT INTO scan_results (agent_id, agent_name, triggered_by_key_label, status) '
            "VALUES (?, ?, ?, 'pending')",
            (agent_id, agent_name, triggered_by_key_label),
        )
        conn.commit()
        scan_id = cursor.lastrowid
    finally:
        conn.close()

    return get_scan(scan_id, db_path=db_path)


def mark_running(scan_id: int, db_path: str = DB_PATH) -> None:
    """Transition a scan to status='running', stamping started_at."""
    conn = _get_connection(db_path)
    try:
        conn.execute(
            "UPDATE scan_results SET status = 'running', started_at = ? WHERE id = ?",
            (datetime.now().isoformat(), scan_id),
        )
        conn.commit()
    finally:
        conn.close()


def mark_completed(scan_id: int, results: Dict[str, Any], db_path: str = DB_PATH) -> None:
    """Persist a finished scan's results (the dict returned by
    AgentVulnerabilityScanner.scan_all_threats()). vulnerability_score is
    stored exactly as given - including None, when nothing was testable -
    never coerced to a number."""
    conn = _get_connection(db_path)
    try:
        conn.execute(
            """UPDATE scan_results SET
                status = 'completed',
                completed_at = ?,
                total_tested = ?,
                vulnerabilities_found = ?,
                safe_threats = ?,
                technical_errors = ?,
                vulnerability_score = ?,
                report_json = ?
            WHERE id = ?""",
            (
                datetime.now().isoformat(),
                results.get('total_threats', 0),
                len(results.get('vulnerabilities', [])),
                len(results.get('safe_threats', [])),
                len(results.get('technical_errors', [])),
                results.get('vulnerability_score'),
                json.dumps(results, default=str),
                scan_id,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def mark_failed(scan_id: int, error: str, db_path: str = DB_PATH) -> None:
    """Persist a scan that crashed outright (before/during scan_all_threats
    itself raised, as opposed to a per-threat technical_error it already
    handles internally) - status='failed', no counts, error kept in
    report_json since there's no dedicated error column."""
    conn = _get_connection(db_path)
    try:
        conn.execute(
            """UPDATE scan_results SET
                status = 'failed',
                completed_at = ?,
                report_json = ?
            WHERE id = ?""",
            (
                datetime.now().isoformat(),
                json.dumps({'error': error}),
                scan_id,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_scan(scan_id: int, db_path: str = DB_PATH) -> Optional[Dict[str, Any]]:
    """Get a single scan by id, or None if it doesn't exist."""
    conn = _get_connection(db_path)
    try:
        row = conn.execute(
            'SELECT * FROM scan_results WHERE id = ?', (scan_id,)
        ).fetchone()
    finally:
        conn.close()

    return _row_to_dict(row) if row else None
