"""
FastAPI REST API for Agent Security Intelligence Framework
Exposes threat data from SQLite database
"""

import logging
import os

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
import sqlite3
from typing import Dict, List, Optional
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
            "/agents": "Get unique agents",
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
    """Get list of available threat types"""
    return {
        "threat_types": [
            "prompt_injection",
            "tool_abuse",
            "data_leakage",
            "model_extraction",
            "behavioral_anomaly",
            "other"
        ]
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
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)