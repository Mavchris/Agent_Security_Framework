"""
FastAPI REST API for Agent Security Intelligence Framework
Exposes threat data from SQLite database
"""

import logging
import os

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
import sqlite3
from typing import Any, Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Agent Security Intelligence API",
    description="REST API for threat intelligence on AI agents",
    version="1.0.0"
)

# CORS: no permissive "*" default. This API has no auth (see SECURITY.md)
# and is designed for local/trusted-network use only, so the default is
# to allow no cross-origin requests at all. Set CORS_ALLOWED_ORIGINS (comma-
# separated) before any deployment where a browser-based client on a
# different origin needs to call this API - review SECURITY.md first.
_cors_origins = [o.strip() for o in os.getenv('CORS_ALLOWED_ORIGINS', '').split(',') if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Log the real exception server-side; never leak str(e) to the client
    (can expose file paths, SQL structure, etc - see SECURITY.md)."""
    logger.error("Unhandled exception on %s %s", request.method, request.url.path, exc_info=exc)
    return JSONResponse(status_code=500, content={"error": "Internal server error", "status": "error"})


# Database path
DB_PATH = 'data/threats.db'


def get_db_connection():
    """Get SQLite database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.get("/")
async def root():
    """Root endpoint - API info"""
    return {
        "name": "Agent Security Intelligence API",
        "version": "1.0.0",
        "endpoints": {
            "/threats": "Get all threats with filtering",
            "/stats": "Get statistics",
            "/threats/{threat_id}": "Get specific threat",
            "/agents": "List registered agents (requires X-API-Key)",
            "/health": "Health check"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM threats')
        count = cursor.fetchone()[0]
        conn.close()
        
        return {
            "status": "healthy",
            "database": "connected",
            "threats_count": count
        }
    except Exception as e:
        # Kept as a local try/except rather than the global handler: a
        # health check reporting itself unhealthy is a normal 200
        # response for monitoring tools, not a 500 server error.
        logger.error("Health check failed", exc_info=e)
        return {
            "status": "unhealthy",
            "error": "Internal server error"
        }


@app.get("/threats")
async def get_threats(
    threat_type: Optional[str] = Query(None, description="Filter by threat type"),
    source: Optional[str] = Query(None, description="Filter by source (CVE, GitHub, ArXiv)"),
    limit: int = Query(100, ge=1, le=1000, description="Limit results"),
    offset: int = Query(0, ge=0, description="Offset for pagination")
):
    """
    Get all threats with optional filtering
    
    Query Parameters:
    - threat_type: Filter by threat type (prompt_injection, tool_abuse, data_leakage, model_extraction, behavioral_anomaly, other)
    - source: Filter by source (CVE, GitHub, ArXiv)
    - limit: Number of results (default: 100, max: 1000)
    - offset: Pagination offset (default: 0)
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Build query
    query = 'SELECT * FROM threats WHERE 1=1'
    params = []

    if threat_type:
        query += ' AND threat_type = ?'
        params.append(threat_type)

    if source:
        query += ' AND source = ?'
        params.append(source)

    query += ' ORDER BY id DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])

    # Execute query
    cursor.execute(query, params)
    threats = cursor.fetchall()

    # Get total count
    count_query = 'SELECT COUNT(*) FROM threats WHERE 1=1'
    if threat_type:
        count_query += ' AND threat_type = ?'
    if source:
        count_query += ' AND source = ?'

    count_params = []
    if threat_type:
        count_params.append(threat_type)
    if source:
        count_params.append(source)

    cursor.execute(count_query, count_params)
    total = cursor.fetchone()[0]

    conn.close()

    # Convert to dict
    result = {
        "total": total,
        "limit": limit,
        "offset": offset,
        "count": len(threats),
        "threats": [dict(threat) for threat in threats]
    }

    return result


@app.get("/threats/{threat_id}")
async def get_threat(threat_id: str):
    """Get specific threat by ID"""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM threats WHERE threat_id = ?', (threat_id,))
    threat = cursor.fetchone()

    conn.close()

    if threat:
        return dict(threat)
    else:
        return JSONResponse(
            status_code=404,
            content={
                "error": f"Threat {threat_id} not found",
                "status": "not_found"
            }
        )


@app.get("/stats")
async def get_stats():
    """Get statistics about threats"""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Total count
    cursor.execute('SELECT COUNT(*) FROM threats')
    total = cursor.fetchone()[0]

    # Count by type
    cursor.execute('SELECT threat_type, COUNT(*) as count FROM threats GROUP BY threat_type ORDER BY count DESC')
    by_type = {row[0]: row[1] for row in cursor.fetchall()}

    # Count by source
    cursor.execute('SELECT source, COUNT(*) as count FROM threats GROUP BY source ORDER BY count DESC')
    by_source = {row[0]: row[1] for row in cursor.fetchall()}

    # Date range
    cursor.execute('SELECT MIN(collected_at), MAX(collected_at) FROM threats')
    min_date, max_date = cursor.fetchone()

    conn.close()

    return {
        "total_threats": total,
        "by_threat_type": by_type,
        "by_source": by_source,
        "date_range": {
            "earliest": min_date,
            "latest": max_date
        }
    }


@app.get("/threat-types")
async def get_threat_types():
    """Get list of available threat types - the classifier's own taxonomy
    (core.classifier.ImprovedThreatClassifier.categories), not a separately
    maintained list, so this can't drift from what /stats.by_threat_type
    actually reports."""
    return {
        "threat_types": _classifier.categories
    }


@app.get("/sources")
async def get_sources():
    """Get list of available sources"""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT DISTINCT source FROM threats ORDER BY source')
    sources = [row[0] for row in cursor.fetchall()]

    conn.close()

    return {
        "sources": sources
    }

# ============================================
# MONITORING ENDPOINTS
# ============================================

import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from monitoring.agent_monitor import AgentMonitor
from core.auth import verify_key
from core.classifier import ImprovedThreatClassifier

_classifier = ImprovedThreatClassifier()

# One AgentMonitor per agent name, so monitoring multiple agents at once
# doesn't overwrite each other's in-memory logs/alerts (used to be a single
# global instance, reassigned on every agent_name switch - see ROADMAP).
monitor_instances: Dict[str, AgentMonitor] = {}


def _get_or_create_monitor(agent_name: str) -> AgentMonitor:
    if agent_name not in monitor_instances:
        monitor_instances[agent_name] = AgentMonitor(agent_name=agent_name)
    return monitor_instances[agent_name]


# The threat catalog endpoints above stay open (public data - NVD, GitHub,
# etc). Everything under /monitoring/* deals with real production agent
# activity (see SECURITY.md) and requires a named API key, sent as
# X-API-Key. auto_error=False so a missing header reaches require_api_key
# as None and gets the same generic 401 as an invalid one, rather than
# FastAPI's own not-quite-matching default error shape.
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(api_key: Optional[str] = Depends(_api_key_header)) -> str:
    """FastAPI dependency: resolves to the requesting key's label if valid
    and active, otherwise raises 401. Never echoes the candidate key or
    any lookup detail back to the client (see the generic-error convention
    used by unhandled_exception_handler above) - the real reason (absent,
    unknown, or deactivated) is only in this server-side log line."""
    label = verify_key(api_key)
    if label is None:
        logger.warning("Rejected request with missing or invalid API key")
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return label


class LogRequestBody(BaseModel):
    """Request body for POST /monitoring/log-request"""
    agent_name: str
    prompt: str
    response: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None


@app.post("/monitoring/log-request")
async def log_request(body: LogRequestBody, key_label: str = Depends(require_api_key)):
    """
    Log a request for monitoring. Requires a valid X-API-Key header.

    POST /monitoring/log-request
    {
        "agent_name": "MyAgent",
        "prompt": "user input",
        "response": "agent response",
        "user_id": "user123",
        "session_id": "session456"
    }
    """

    monitor_instance = _get_or_create_monitor(body.agent_name)

    # Log the request
    log_entry = monitor_instance.log_request(
        prompt=body.prompt,
        response=body.response,
        user_id=body.user_id,
        session_id=body.session_id,
        created_by_key_label=key_label,
    )

    return {
        "status": "logged",
        "agent_name": body.agent_name,
        "alert_triggered": log_entry['alert_triggered'],
        "risk_level": log_entry['risk_level'],
        "detected_threats": len(log_entry['detected_threats'])
    }


@app.get("/monitoring/stats/{agent_name}")
async def get_monitoring_stats(agent_name: str, _: str = Depends(require_api_key)):
    """
    Get monitoring statistics for an agent. Requires a valid X-API-Key header.

    GET /monitoring/stats/MyAgent
    """

    monitor_instance = _get_or_create_monitor(agent_name)

    stats = monitor_instance.get_statistics()

    return {
        "agent_name": agent_name,
        "statistics": stats,
        "status": "success"
    }


@app.get("/monitoring/alerts/{agent_name}")
async def get_monitoring_alerts(
    agent_name: str,
    limit: int = Query(10, ge=1, le=100),
    _: str = Depends(require_api_key),
):
    """
    Get recent alerts for an agent. Requires a valid X-API-Key header.

    GET /monitoring/alerts/MyAgent?limit=5
    """

    monitor_instance = _get_or_create_monitor(agent_name)

    alerts = monitor_instance.get_alerts(limit=limit)

    return {
        "agent_name": agent_name,
        "total_alerts": monitor_instance.get_statistics()['total_alerts'],
        "recent_alerts": alerts,
        "status": "success"
    }


@app.get("/monitoring/health/{agent_name}")
async def get_agent_health(agent_name: str, _: str = Depends(require_api_key)):
    """
    Get health status of monitored agent. Requires a valid X-API-Key header.

    GET /monitoring/health/MyAgent
    """

    monitor_instance = _get_or_create_monitor(agent_name)

    stats = monitor_instance.get_statistics()

    # Determine health status
    alert_rate = stats['alert_rate']
    if alert_rate > 50:
        health_status = "🔴 CRITICAL"
    elif alert_rate > 30:
        health_status = "🟠 WARNING"
    elif alert_rate > 10:
        health_status = "🟡 CAUTION"
    else:
        health_status = "🟢 HEALTHY"

    return {
        "agent_name": agent_name,
        "health_status": health_status,
        "alert_rate": f"{alert_rate:.1f}%",
        "total_requests": stats['total_requests_logged'],
        "total_alerts": stats['total_alerts'],
        "status": "success"
    }

# ============================================
# AGENT REGISTRY ENDPOINTS
# ============================================
# Thin HTTP layer over core/agent_registry.py - the same shared CRUD the
# dashboard's registration form already uses, not a reimplementation.
# All 4 endpoints require a named API key: this is the same
# administrative surface as the dashboard's gated "Agent Operations"
# page (SSRF-adjacent for remote_http agents - see SECURITY.md).

from core.agent_registry import deactivate_agent, get_agent_config, list_agents, register_agent


class RegisterAgentBody(BaseModel):
    """Request body for POST /agents - same fields as the dashboard's
    registration form (dashboard/pages/operations.py)."""
    name: str
    agent_type: str
    config: Optional[Dict[str, Any]] = None
    environment: Optional[str] = None


@app.get("/agents")
async def get_agents(
    environment: Optional[str] = Query(None, description="Filter by environment"),
    active_only: bool = Query(True, description="Exclude deactivated agents"),
    _: str = Depends(require_api_key),
):
    """
    List registered agents. Requires a valid X-API-Key header.

    GET /agents?environment=production&active_only=true
    """
    return {"agents": list_agents(environment=environment, active_only=active_only)}


@app.post("/agents")
async def create_agent(body: RegisterAgentBody, key_label: str = Depends(require_api_key)):
    """
    Register a new agent. Requires a valid X-API-Key header.

    POST /agents
    {"name": "my_agent", "agent_type": "mock"}
    """
    try:
        return register_agent(
            body.name, body.agent_type,
            config=body.config, environment=body.environment,
            created_by_key_label=key_label,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/agents/{agent_id}")
async def get_agent(agent_id: int, _: str = Depends(require_api_key)):
    """
    Get a single registered agent by id. Requires a valid X-API-Key
    header. Returns a deactivated agent too (check its is_active field) -
    same behavior as core.agent_registry.get_agent_config().

    GET /agents/3
    """
    agent = get_agent_config(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
    return agent


@app.post("/agents/{agent_id}/deactivate")
async def deactivate_agent_endpoint(agent_id: int, key_label: str = Depends(require_api_key)):
    """
    Deactivate a registered agent (soft-delete - the row and its
    monitoring/scan history are kept). Requires a valid X-API-Key header.

    POST /agents/3/deactivate
    """
    if not deactivate_agent(agent_id, deactivated_by_key_label=key_label):
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
    return {"id": agent_id, "status": "deactivated"}


# ============================================
# SCAN ENDPOINTS
# ============================================
# Runs asynchronously (a real scan against a real agent can take
# 11-45 minutes - see ROADMAP.md/the scan-reliability vague - far past
# any reasonable synchronous HTTP timeout). POST /scan returns
# immediately with a scan id; GET /scan/results/{id} is polled for
# progress/result. FastAPI's BackgroundTasks (a thread from the same
# process) is used rather than a real job queue - deliberately, not
# built for this project's scale - see core/scan_store.py and
# DEPLOYMENT.md for the accepted limitation: a server restart while a
# scan is 'running' loses it silently, no resume.

from core import scan_store
from core.agent_registry import build_wrapper
from testing.agent_scanner import AgentVulnerabilityScanner
from testing.agent_wrappers import get_agent_wrapper


class ScanRequestBody(BaseModel):
    """Request body for POST /scan - exactly one of agent_id (a
    registered agent) or agent_type (a one-off "quick type" scan,
    nothing saved to registered_agents) must be given, matching the two
    entry paths already on the dashboard's "Test Agent" tab."""
    agent_id: Optional[int] = None
    agent_type: Optional[str] = None
    agent_name: Optional[str] = None
    agent_config: Optional[Dict[str, Any]] = None
    limit: Optional[int] = None


def _run_scan_background(scan_id: int, agent, limit: Optional[int]):
    """Runs in a background thread (FastAPI BackgroundTasks) after
    POST /scan has already returned its response to the client."""
    try:
        scan_store.mark_running(scan_id)
        scanner = AgentVulnerabilityScanner(agent, db_path=DB_PATH)
        results = scanner.scan_all_threats(verbose=False, limit=limit)
        scan_store.mark_completed(scan_id, results)
    except Exception as e:
        logger.error("Scan %d failed", scan_id, exc_info=e)
        scan_store.mark_failed(scan_id, str(e))


@app.post("/scan")
async def trigger_scan(
    body: ScanRequestBody,
    background_tasks: BackgroundTasks,
    key_label: str = Depends(require_api_key),
):
    """
    Start an asynchronous vulnerability scan. Requires a valid X-API-Key
    header. Returns immediately with the new scan's id and status
    ('pending') - poll GET /scan/results/{id} for progress/result.

    POST /scan
    {"agent_id": 3}
    or
    {"agent_type": "mock", "agent_name": "my_agent"}
    """
    if (body.agent_id is None) == (body.agent_type is None):
        raise HTTPException(
            status_code=400,
            detail="Provide exactly one of agent_id or agent_type",
        )

    if body.agent_id is not None:
        agent_row = get_agent_config(body.agent_id)
        if agent_row is None or not agent_row['is_active']:
            raise HTTPException(
                status_code=404,
                detail=f"Registered agent {body.agent_id} not found or inactive",
            )
        agent = build_wrapper(agent_row)
        agent_name = agent_row['name']
    else:
        try:
            agent = get_agent_wrapper(body.agent_type, **(body.agent_config or {}))
        except (ValueError, ImportError, TypeError) as e:
            raise HTTPException(status_code=400, detail=str(e))
        agent_name = body.agent_name or f"{body.agent_type}-quick-scan"

    scan_row = scan_store.create_scan(
        agent_name=agent_name,
        agent_id=body.agent_id,
        triggered_by_key_label=key_label,
    )
    background_tasks.add_task(_run_scan_background, scan_row['id'], agent, body.limit)

    return {"id": scan_row['id'], "status": scan_row['status'], "agent_name": agent_name}


@app.get("/scan/results/{scan_id}")
async def get_scan_results(scan_id: int, _: str = Depends(require_api_key)):
    """
    Get a scan's current status, or its full result once completed.
    Requires a valid X-API-Key header.

    vulnerability_score is null both while status is 'pending'/'running'
    (not computed yet) AND when status is 'completed' but every threat
    technical-errored (nothing was actually measurable) - always check
    status before drawing any conclusion from a null score. See
    API_DOCUMENTATION.md.

    GET /scan/results/42
    """
    scan_row = scan_store.get_scan(scan_id)
    if scan_row is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return scan_row


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)