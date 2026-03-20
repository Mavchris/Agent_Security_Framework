"""
FastAPI REST API for Agent Security Intelligence Framework
Exposes threat data from SQLite database
"""

from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
import sqlite3
from typing import List, Optional
from datetime import datetime

# Initialize FastAPI app
app = FastAPI(
    title="Agent Security Intelligence API",
    description="REST API for threat intelligence on AI agents",
    version="1.0.0"
)

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
        return {
            "status": "unhealthy",
            "error": str(e)
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
    try:
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
    
    except Exception as e:
        return {
            "error": str(e),
            "status": "error"
        }


@app.get("/threats/{threat_id}")
async def get_threat(threat_id: str):
    """Get specific threat by ID"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM threats WHERE threat_id = ?', (threat_id,))
        threat = cursor.fetchone()
        
        conn.close()
        
        if threat:
            return dict(threat)
        else:
            return {
                "error": f"Threat {threat_id} not found",
                "status": "not_found"
            }
    
    except Exception as e:
        return {
            "error": str(e),
            "status": "error"
        }


@app.get("/stats")
async def get_stats():
    """Get statistics about threats"""
    try:
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
    
    except Exception as e:
        return {
            "error": str(e),
            "status": "error"
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
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT DISTINCT source FROM threats ORDER BY source')
        sources = [row[0] for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            "sources": sources
        }
    
    except Exception as e:
        return {
            "error": str(e),
            "status": "error"
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)