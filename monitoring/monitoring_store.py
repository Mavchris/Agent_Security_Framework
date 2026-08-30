"""
Cross-process persistence for agent monitoring (logs + alerts).

Separate database file (data/monitoring.db) from data/threats.db (the
public threat catalog) - these tables can contain real production
prompt/response text, kept apart from the catalog (see SECURITY.md).

This is the shared source of truth read by both api/app.py and the
dashboard's "Monitor Production" tab - AgentMonitor (monitoring/
agent_monitor.py) no longer keeps its own in-memory logs/alerts as the
authoritative record, it writes through to this module and this module
is what gets read back, from either process.
"""

import json
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional

DB_PATH = 'data/monitoring.db'


def _get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _log_row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    entry = dict(row)
    entry['detected_threats'] = json.loads(entry['detected_threats'])
    entry['alert_triggered'] = bool(entry['alert_triggered'])
    return entry


def _alert_row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    entry = dict(row)
    entry['detected_threats'] = json.loads(entry['detected_threats'])
    entry['resolved'] = bool(entry['resolved'])
    return entry


def write_log(
    agent_name: str,
    prompt: str,
    response: str,
    risk_level: str,
    alert_triggered: bool,
    detected_threats: List[Dict[str, Any]],
    agent_id: Optional[int] = None,
    user_id: Optional[str] = None,
    session_id: Optional[str] = None,
    created_by_key_label: Optional[str] = None,
    db_path: str = DB_PATH,
) -> Dict[str, Any]:
    """Persist one request/response log entry. Returns the stored row
    (including its new id and created_at)."""
    conn = _get_connection(db_path)
    try:
        cursor = conn.execute(
            'INSERT INTO monitoring_logs '
            '(agent_id, agent_name, user_id, session_id, prompt, response, '
            ' risk_level, alert_triggered, detected_threats, created_by_key_label) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                agent_id, agent_name, user_id, session_id, prompt, response,
                risk_level, alert_triggered, json.dumps(detected_threats),
                created_by_key_label,
            ),
        )
        conn.commit()
        log_id = cursor.lastrowid
    finally:
        conn.close()

    return get_log(log_id, db_path=db_path)


def write_alert(
    log_id: int,
    agent_name: str,
    alert_type: str,
    severity: str,
    message: str,
    detected_threats: List[Dict[str, Any]],
    agent_id: Optional[int] = None,
    user_id: Optional[str] = None,
    session_id: Optional[str] = None,
    created_by_key_label: Optional[str] = None,
    db_path: str = DB_PATH,
) -> Dict[str, Any]:
    """Persist one alert, linked back to the log entry that triggered it.
    Returns the stored row."""
    conn = _get_connection(db_path)
    try:
        cursor = conn.execute(
            'INSERT INTO monitoring_alerts '
            '(log_id, agent_id, agent_name, user_id, session_id, alert_type, '
            ' severity, message, detected_threats, created_by_key_label) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                log_id, agent_id, agent_name, user_id, session_id, alert_type,
                severity, message, json.dumps(detected_threats),
                created_by_key_label,
            ),
        )
        conn.commit()
        alert_id = cursor.lastrowid
    finally:
        conn.close()

    return get_alert(alert_id, db_path=db_path)


def get_log(log_id: int, db_path: str = DB_PATH) -> Optional[Dict[str, Any]]:
    conn = _get_connection(db_path)
    try:
        row = conn.execute('SELECT * FROM monitoring_logs WHERE id = ?', (log_id,)).fetchone()
    finally:
        conn.close()
    return _log_row_to_dict(row) if row else None


def get_alert(alert_id: int, db_path: str = DB_PATH) -> Optional[Dict[str, Any]]:
    conn = _get_connection(db_path)
    try:
        row = conn.execute('SELECT * FROM monitoring_alerts WHERE id = ?', (alert_id,)).fetchone()
    finally:
        conn.close()
    return _alert_row_to_dict(row) if row else None


def get_logs(
    agent_name: Optional[str] = None,
    limit: Optional[int] = 100,
    db_path: str = DB_PATH,
) -> List[Dict[str, Any]]:
    """Most recent logs first. limit=None returns everything (used by
    AgentMonitor.export_logs())."""
    conn = _get_connection(db_path)
    try:
        query = 'SELECT * FROM monitoring_logs'
        params: List[Any] = []
        if agent_name:
            query += ' WHERE agent_name = ?'
            params.append(agent_name)
        query += ' ORDER BY created_at DESC, id DESC'
        if limit is not None:
            query += ' LIMIT ?'
            params.append(limit)
        rows = conn.execute(query, params).fetchall()
    finally:
        conn.close()
    return [_log_row_to_dict(row) for row in rows]


def get_alerts(
    agent_name: Optional[str] = None,
    limit: Optional[int] = 100,
    db_path: str = DB_PATH,
) -> List[Dict[str, Any]]:
    """Most recent alerts first. limit=None returns everything."""
    conn = _get_connection(db_path)
    try:
        query = 'SELECT * FROM monitoring_alerts'
        params: List[Any] = []
        if agent_name:
            query += ' WHERE agent_name = ?'
            params.append(agent_name)
        query += ' ORDER BY created_at DESC, id DESC'
        if limit is not None:
            query += ' LIMIT ?'
            params.append(limit)
        rows = conn.execute(query, params).fetchall()
    finally:
        conn.close()
    return [_alert_row_to_dict(row) for row in rows]


def get_statistics(agent_name: str, db_path: str = DB_PATH) -> Dict[str, Any]:
    """Same shape as the old in-memory AgentMonitor.get_statistics(), now
    computed fresh from the shared DB so it's consistent across processes."""
    conn = _get_connection(db_path)
    try:
        total_requests = conn.execute(
            'SELECT COUNT(*) FROM monitoring_logs WHERE agent_name = ?', (agent_name,)
        ).fetchone()[0]

        alert_rows = conn.execute(
            'SELECT * FROM monitoring_alerts WHERE agent_name = ?', (agent_name,)
        ).fetchall()
    finally:
        conn.close()

    alerts = [_alert_row_to_dict(row) for row in alert_rows]
    total_alerts = len(alerts)

    by_threat_type: Dict[str, int] = {}
    by_risk_level: Dict[str, int] = {}
    for alert in alerts:
        by_risk_level[alert['severity']] = by_risk_level.get(alert['severity'], 0) + 1
        for threat in alert['detected_threats']:
            threat_type = threat.get('threat_type', 'unknown')
            by_threat_type[threat_type] = by_threat_type.get(threat_type, 0) + 1

    return {
        'total_requests_logged': total_requests,
        'total_alerts': total_alerts,
        'alert_rate': (total_alerts / total_requests * 100) if total_requests > 0 else 0,
        'by_threat_type': by_threat_type,
        'by_risk_level': by_risk_level,
    }
