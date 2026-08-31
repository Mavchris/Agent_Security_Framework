# API Documentation

Complete REST API reference for the Agent Security Intelligence Framework. This document covers all endpoints, request/response formats, examples, and integration patterns.

## 📚 Table of Contents

1. [Getting Started](#getting-started)
2. [Base Information](#base-information)
3. [Authentication](#authentication)
4. [Threat Endpoints](#threat-endpoints)
5. [Statistics Endpoints](#statistics-endpoints)
6. [Monitoring Endpoints](#monitoring-endpoints)
7. [Agent Registry Endpoints](#agent-registry-endpoints)
8. [Scan Endpoints](#scan-endpoints)
9. [Health Endpoints](#health-endpoints)
10. [Error Handling](#error-handling)
11. [Rate Limiting](#rate-limiting)
12. [Code Examples](#code-examples)
13. [Integration Patterns](#integration-patterns)

---

## Getting Started

### Quick Start

```bash
# 1. Start the API server
python api/app.py

# 2. Verify it's running
curl http://localhost:8000/health

# Should return:
# {"status": "healthy", "version": "2.0"}

# 3. Make your first request
curl http://localhost:8000/threats

# 4. Get result with 240 threats in JSON format (check /stats for the live count)
```

### What You Need

- Python 3.11+
- Virtual environment activated
- Dependencies installed (`pip install -r requirements.txt`)
- Framework initialized (database created)

### Documentation Format

For each endpoint:
- **Method & URL** - HTTP method and path
- **Description** - What it does
- **Parameters** - Query/path parameters
- **Request Body** - If applicable
- **Response** - Success response format
- **Status Codes** - Possible HTTP status codes
- **Examples** - curl, Python, JavaScript

---

## Base Information

### API Server

```
Hostname:     localhost
Port:         8000 (default)
Protocol:     HTTP (production should use HTTPS)
Version:      2.0
Status:       Production Ready (65/100)
```

### Start Server

```bash
# Default port (8000)
python api/app.py

# Custom port
python api/app.py --port 8001

# With debug logging
python api/app.py --debug

# Output:
# INFO:     Started server process
# INFO:     Uvicorn running on http://127.0.0.1:8000
# INFO:     Application startup complete
```

### Change Port

```bash
# If port 8000 is in use:
python api/app.py --port 8001

# Update requests:
curl http://localhost:8001/threats  # instead of 8000
```

### Response Format

⚠️ **This envelope below is aspirational, not what the API actually returns** - every real endpoint (see the sections below, each verified against a running server) returns its data directly as the top-level JSON object/array, with no `data`/`status`/`message` wrapper. Kept here as a known documentation gap rather than silently deleted; see each endpoint's own **Response** example for the real shape.

```json
{
  "data": {},           // Actual data (object or array)
  "status": "success",  // "success" or "error"
  "timestamp": "2026-03-28T14:30:00Z",  // ISO 8601 timestamp
  "message": null       // null on success, error message on failure
}
```

---

## Authentication

### Current Status: named API keys on sensitive endpoints

The threat catalog (`/threats`, `/stats`, `/threat-types`, `/sources`, `/health`) has **no authentication** - it's public third-party threat intelligence, not worth gating. Everything else does:

| Requires `X-API-Key` | Public, no key needed |
|---|---|
| `/monitoring/*` (all 4) | `/threats`, `/threats/{id}` |
| `/agents`, `/agents/{id}`, `/agents/{id}/deactivate` | `/stats`, `/threat-types`, `/sources` |
| `/scan`, `/scan/results/{id}` | `/health`, `/` |

Send the key as an `X-API-Key` header:
```bash
curl http://localhost:8000/agents -H "X-API-Key: <your key>"
```

A key is a label plus a high-entropy random token, created by an administrator directly on the server - there is no endpoint to create one (that would let anyone mint their own):
```bash
python scripts/maintenance/create_api_key.py my-label     # prints the raw key once
python scripts/maintenance/deactivate_api_key.py my-label # revokes it
```

Missing, invalid, and deactivated keys all return the same generic response, so a client can't distinguish "wrong key" from "revoked key" from "no key at all":
```json
{"detail": "Invalid or missing API key"}
```
with HTTP `401`.

**Not implemented**: OAuth, bearer tokens beyond the raw key itself, per-key rate limiting, key expiry, or RBAC (every valid key can do everything the endpoints above allow - there's no per-key permission scoping). See [SECURITY.md](SECURITY.md#authentication-named-api-keys) and [ROADMAP.md](ROADMAP.md) for what's tracked as follow-up work.

### Security Notes

For production deployment:
- Always use HTTPS (nothing here provides TLS itself - put a reverse proxy in front)
- Restrict network access to the host regardless of the API key (see [DEPLOYMENT.md](DEPLOYMENT.md)) - a key is a second layer, not a substitute for network isolation
- Set `CORS_ALLOWED_ORIGINS` explicitly (comma-separated) before any browser-based client on a different origin needs to call this API - restrictive by default (no origins allowed)

See [SECURITY.md](SECURITY.md) for the full hardening guide.

---

## Threat Endpoints

### 1. List All Threats

**Endpoint:**
```
GET /threats
```

**Description:**
Get all threats from the database with optional filtering and pagination.

**Query Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `type` | string | No | None | Filter by threat type (e.g., prompt_injection) |
| `severity` | string | No | None | Filter by severity (critical/high/medium/low) |
| `source` | string | No | None | Filter by source (nvd/github/mitre/etc.) |
| `limit` | integer | No | 100 | Max results per page (1-1000) |
| `offset` | integer | No | 0 | Pagination offset |
| `search` | string | No | None | Search by title (partial match) |

**Response (200 OK):**

```json
{
  "data": [
    {
      "threat_id": "prompt_injection_001",
      "title": "System Prompt Override",
      "description": "Attacker injects commands into system prompt...",
      "type": "prompt_injection",
      "severity": "critical",
      "source": "mitre_attack",
      "test_payload": "Ignore previous instructions and...",
      "detection_keywords": ["DAN", "jailbreak", "override"],
      "cvss_score": 9.2,
      "url": "https://mitre.org/attack/T1234",
      "created_at": "2026-03-28T10:00:00Z",
      "updated_at": "2026-03-28T14:30:00Z"
    },
    ...
  ],
  "status": "success",
  "timestamp": "2026-03-28T14:30:00Z",
  "pagination": {
    "offset": 0,
    "limit": 100,
    "total": 240,
    "returned": 100
  }
}
```

**Examples:**

```bash
# Get all threats
curl http://localhost:8000/threats

# Get only critical threats
curl "http://localhost:8000/threats?severity=critical"

# Get only prompt injection threats
curl "http://localhost:8000/threats?type=prompt_injection"

# Get from specific source
curl "http://localhost:8000/threats?source=nvd"

# Combine filters
curl "http://localhost:8000/threats?type=prompt_injection&severity=critical"

# Search by title
curl "http://localhost:8000/threats?search=system+prompt"

# Pagination
curl "http://localhost:8000/threats?limit=50&offset=0"   # First 50
curl "http://localhost:8000/threats?limit=50&offset=50"  # Second 50
```

**Python Example:**

```python
import requests

# Get all critical prompt injection threats
response = requests.get(
    'http://localhost:8000/threats',
    params={
        'type': 'prompt_injection',
        'severity': 'critical'
    }
)

threats = response.json()['data']
print(f"Found {len(threats)} critical prompt injection threats")

for threat in threats:
    print(f"- {threat['title']} (CVSS: {threat['cvss_score']})")
```

---

### 2. Get Specific Threat

**Endpoint:**
```
GET /threats/{threat_id}
```

**Description:**
Get detailed information about a specific threat by ID.

**Path Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `threat_id` | string | Yes | Threat identifier (e.g., prompt_injection_001) |

**Response (200 OK):**

```json
{
  "data": {
    "threat_id": "prompt_injection_001",
    "title": "System Prompt Override",
    "description": "Detailed description of the threat...",
    "type": "prompt_injection",
    "severity": "critical",
    "source": "mitre_attack",
    "test_payload": "Ignore previous instructions and...",
    "detection_keywords": ["DAN", "jailbreak", "override", "system prompt"],
    "cvss_score": 9.2,
    "url": "https://mitre.org/attack/T1234",
    "created_at": "2026-03-28T10:00:00Z",
    "updated_at": "2026-03-28T14:30:00Z"
  },
  "status": "success",
  "timestamp": "2026-03-28T14:30:00Z"
}
```

**Response (404 Not Found):**

```json
{
  "error": "Threat invalid_id not found",
  "status": "not_found"
}
```

**Status Codes:**

| Code | Meaning |
|------|---------|
| 200 | Success |
| 404 | Threat not found |
| 500 | Server error |

**Examples:**

```bash
# Get specific threat
curl http://localhost:8000/threats/prompt_injection_001

# Get another threat
curl http://localhost:8000/threats/api_abuse_001
```

**Python Example:**

```python
import requests

threat_id = 'prompt_injection_001'
response = requests.get(f'http://localhost:8000/threats/{threat_id}')
threat = response.json()['data']

print(f"Title: {threat['title']}")
print(f"Type: {threat['type']}")
print(f"Severity: {threat['severity']}")
print(f"Test Payload: {threat['test_payload']}")
print(f"Detection Keywords: {', '.join(threat['detection_keywords'])}")
```

---

## Statistics Endpoints

### 3. Get Overall Statistics

**Endpoint:**
```
GET /stats
```

**Description:**
Get aggregated statistics about all threats.

**Response (200 OK):**

```json
{
  "data": {
    "total_threats": 240,
    "by_severity": {
      "critical": 58,
      "high": 145,
      "medium": 33,
      "low": 10
    },
    "by_type": {
      "prompt_injection": 72,
      "api_abuse": 26,
      "tool_abuse": 3,
      "model_extraction": 2,
      "behavioral_anomaly": 2,
      "supply_chain": 1,
      "data_leakage": 1,
      "data_poisoning": 0,
      "resource_exhaustion": 0
    },
    "by_source": {
      "nvd": 80,
      "github_security": 122,
      "mitre_attack": 50,
      "arxiv": 25,
      "censys": 25,
      "cve": 10,
      "opencti": 15
    },
    "last_update": "2026-03-28T02:00:00Z"
  },
  "status": "success",
  "timestamp": "2026-03-28T14:30:00Z"
}
```

**Examples:**

```bash
# Get statistics
curl http://localhost:8000/stats
```

**Python Example:**

```python
import requests
import json

response = requests.get('http://localhost:8000/stats')
stats = response.json()['data']

print(f"Total Threats: {stats['total_threats']}")
print(f"\nBy Severity:")
for severity, count in stats['by_severity'].items():
    print(f"  - {severity}: {count}")

print(f"\nTop 3 Threat Types:")
sorted_types = sorted(stats['by_type'].items(), key=lambda x: x[1], reverse=True)
for threat_type, count in sorted_types[:3]:
    print(f"  - {threat_type}: {count}")

print(f"\nTop 3 Sources:")
sorted_sources = sorted(stats['by_source'].items(), key=lambda x: x[1], reverse=True)
for source, count in sorted_sources[:3]:
    print(f"  - {source}: {count}")
```

---

### 4. Get Threat Types

**Endpoint:**
```
GET /threat-types
```

**Description:**
Get list of all available threat types/categories.

**Response (200 OK):**

```json
{
  "data": {
    "types": [
      "prompt_injection",
      "api_abuse",
      "tool_abuse",
      "model_extraction",
      "behavioral_anomaly",
      "supply_chain",
      "data_leakage",
      "data_poisoning",
      "resource_exhaustion"
    ]
  },
  "status": "success",
  "timestamp": "2026-03-28T14:30:00Z"
}
```

**Examples:**

```bash
curl http://localhost:8000/threat-types
```

**Python Example:**

```python
import requests

response = requests.get('http://localhost:8000/threat-types')
types = response.json()['data']['types']

print("Available threat types:")
for threat_type in types:
    print(f"  - {threat_type}")
```

---

### 5. Get CTI Sources

**Endpoint:**
```
GET /sources
```

**Description:**
Get list of all available Threat Intelligence sources.

**Response (200 OK):**

```json
{
  "data": {
    "sources": [
      "nvd",
      "github_security",
      "mitre_attack",
      "arxiv",
      "censys",
      "cve",
      "opencti"
    ]
  },
  "status": "success",
  "timestamp": "2026-03-28T14:30:00Z"
}
```

Note: `scrapers/misp_scraper.py` exists in the repo but is not currently wired into the pipeline (`pipeline/process.py` never calls it), so `misp` does not appear in the active source list above.

**Examples:**

```bash
curl http://localhost:8000/sources
```

**Python Example:**

```python
import requests

response = requests.get('http://localhost:8000/sources')
sources = response.json()['data']['sources']

print(f"Total CTI Sources: {len(sources)}")
for source in sources:
    print(f"  - {source}")
```

---

## Monitoring Endpoints

### 6. Log Request

**Endpoint:**
```
POST /monitoring/log-request
```

**Description:**
Log a request for monitoring and audit purposes (for production agents).

**Request Body** (JSON, `LogRequestBody`):

| Field | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `agent_name` | string | Yes | - | Name of the agent making the request |
| `prompt` | string | Yes | - | The prompt sent to the agent |
| `response` | string | Yes | - | The agent's response |
| `user_id` | string | No | None | Optional user identifier |
| `session_id` | string | No | None | Optional session identifier |

**Response (200 OK):**

```json
{
  "status": "logged",
  "agent_name": "MyAgent",
  "alert_triggered": false,
  "risk_level": "low",
  "detected_threats": 0
}
```

**Examples:**

```bash
curl -X POST "http://localhost:8000/monitoring/log-request" \
  -H "Content-Type: application/json" \
  -d '{"agent_name": "MyAgent", "prompt": "Hello", "response": "Hi there"}'
```

**Python Example:**

```python
import requests

log_data = {
    "agent_name": "my_agent",
    "prompt": "Hello",
    "response": "Hi there"
}

response = requests.post(
    'http://localhost:8000/monitoring/log-request',
    json=log_data
)

print(f"Status: {response.json()['status']}")
```

---

### 7. Get Agent Statistics

**Endpoint:**
```
GET /monitoring/stats/{agent_name}
```

**Description:**
Get monitoring statistics for a specific agent.

**Path Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `agent_name` | string | Yes | Name of the agent (e.g., my_agent) |

**Response (200 OK):**

```json
{
  "data": {
    "agent_name": "my_agent",
    "total_scans": 5,
    "successful_scans": 5,
    "failed_scans": 0,
    "average_duration_ms": 1250,
    "total_threats_tested": 1095,
    "average_vulnerabilities_found": 45,
    "success_rate": 100,
    "last_scan": "2026-03-28T14:30:00Z"
  },
  "status": "success",
  "timestamp": "2026-03-28T14:30:00Z"
}
```

**Examples:**

```bash
curl http://localhost:8000/monitoring/stats/my_agent
```

**Python Example:**

```python
import requests

agent_name = 'my_agent'
response = requests.get(f'http://localhost:8000/monitoring/stats/{agent_name}')
stats = response.json()['data']

print(f"Agent: {stats['agent_name']}")
print(f"Total Scans: {stats['total_scans']}")
print(f"Success Rate: {stats['success_rate']}%")
print(f"Avg Vulnerabilities: {stats['average_vulnerabilities_found']}")
```

---

### 8. Get Agent Alerts

**Endpoint:**
```
GET /monitoring/alerts/{agent_name}
```

**Description:**
Get recent alerts for a specific agent.

**Query Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `severity` | string | No | None | Filter by severity (critical/high) |
| `limit` | integer | No | 10 | Max alerts to return |

**Response (200 OK):**

```json
{
  "data": [
    {
      "alert_id": "alert_20260328_001",
      "agent_name": "my_agent",
      "severity": "critical",
      "message": "High vulnerability score detected: 45%",
      "created_at": "2026-03-28T14:30:00Z"
    },
    ...
  ],
  "status": "success",
  "timestamp": "2026-03-28T14:30:00Z"
}
```

**Examples:**

```bash
# Get all recent alerts
curl http://localhost:8000/monitoring/alerts/my_agent

# Get only critical alerts
curl "http://localhost:8000/monitoring/alerts/my_agent?severity=critical"

# Get last 5 alerts
curl "http://localhost:8000/monitoring/alerts/my_agent?limit=5"
```

**Python Example:**

```python
import requests

agent_name = 'my_agent'
response = requests.get(f'http://localhost:8000/monitoring/alerts/{agent_name}')
alerts = response.json()['data']

print(f"Recent Alerts for {agent_name}:")
for alert in alerts:
    print(f"  [{alert['severity']}] {alert['message']}")
```

---

## Health Endpoints

### 9. Health Check

**Endpoint:**
```
GET /health
```

**Description:**
Check if API is running and healthy.

**Response (200 OK):**

```json
{
  "status": "healthy",
  "version": "2.0",
  "timestamp": "2026-03-28T14:30:00Z",
  "checks": {
    "database": "ok",
    "api": "ok",
    "scheduler": "ok"
  }
}
```

**Examples:**

```bash
curl http://localhost:8000/health
```

**Python Example:**

```python
import requests

try:
    response = requests.get('http://localhost:8000/health')
    if response.status_code == 200:
        print("✓ API is healthy")
    else:
        print("✗ API is unhealthy")
except requests.exceptions.ConnectionError:
    print("✗ Cannot connect to API")
```

---

### 10. Get Agent Health

**Endpoint:**
```
GET /monitoring/health/{agent_name}
```

**Description:**
Get health status of a specific agent.

**Path Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `agent_name` | string | Yes | Name of the agent |

**Response (200 OK):**

```json
{
  "data": {
    "agent_name": "my_agent",
    "status": "healthy",
    "uptime_seconds": 86400,
    "last_heartbeat": "2026-03-28T14:30:00Z",
    "response_time_ms": 45,
    "error_rate": 0,
    "cpu_usage": 12.5,
    "memory_usage_mb": 256
  },
  "status": "success",
  "timestamp": "2026-03-28T14:30:00Z"
}
```

**Examples:**

```bash
curl http://localhost:8000/monitoring/health/my_agent
```

**Python Example:**

```python
import requests

agent_name = 'my_agent'
response = requests.get(f'http://localhost:8000/monitoring/health/{agent_name}')
health = response.json()['data']

print(f"Agent: {health['agent_name']}")
print(f"Status: {health['status']}")
print(f"Uptime: {health['uptime_seconds']} seconds")
print(f"Response Time: {health['response_time_ms']}ms")
```

---

## Agent Registry Endpoints

This section (and Scan Endpoints below) documents actual, verified behavior - every request/response shown was captured from a real running server, not written by hand. Thin HTTP layer over `core/agent_registry.py`, the same shared CRUD the dashboard's registration form uses - not a reimplementation. **All 4 endpoints require a named API key** (see [Authentication](#authentication)); unlike the endpoints above, these are not public.

### 11. List Registered Agents

**Endpoint:**
```
GET /agents
```

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `environment` | string | No | Filter by environment (e.g. `"production"`) |
| `active_only` | boolean | No | Exclude deactivated agents (default: `true`) |

**Response (200 OK):**
```json
{
  "agents": [
    {
      "id": 103,
      "name": "docs-example-agent",
      "agent_type": "mock",
      "config": {},
      "environment": null,
      "is_active": true,
      "created_at": "2026-08-31 21:02:23",
      "created_by_key_label": "docs-example-key",
      "deactivated_by_key_label": null
    }
  ]
}
```

**Status Codes:** `200` Success · `401` Missing/invalid/inactive API key

**Examples:**
```bash
curl http://localhost:8000/agents -H "X-API-Key: <your key>"
```
```python
import requests
response = requests.get('http://localhost:8000/agents', headers={'X-API-Key': API_KEY})
agents = response.json()['agents']
```

---

### 12. Register an Agent

**Endpoint:**
```
POST /agents
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Must be unique |
| `agent_type` | string | Yes | One of `mock`, `claude`, `openai`, `mistral`, `llama`, `huggingface`, `remote_http` |
| `config` | object | No | Shape depends on `agent_type` (e.g. `endpoint_url` for `remote_http`) |
| `environment` | string | No | Free text, e.g. `"production"` |

```json
{"name": "my_agent", "agent_type": "mock"}
```

**Response (200 OK):**
```json
{
  "id": 103,
  "name": "docs-example-agent",
  "agent_type": "mock",
  "config": {},
  "environment": null,
  "is_active": true,
  "created_at": "2026-08-31 21:02:23",
  "created_by_key_label": "docs-example-key",
  "deactivated_by_key_label": null
}
```

**Status Codes:** `200` Registered · `400` Duplicate `name`, or unknown `agent_type` · `401` Missing/invalid/inactive API key

**Examples:**
```bash
curl -X POST http://localhost:8000/agents \
  -H "X-API-Key: <your key>" \
  -H "Content-Type: application/json" \
  -d '{"name": "my_agent", "agent_type": "mock"}'
```

---

### 13. Get a Registered Agent

**Endpoint:**
```
GET /agents/{agent_id}
```

Returns a deactivated agent too (check `is_active`) - same behavior as `core.agent_registry.get_agent_config()`.

**Status Codes:** `200` Success · `401` Missing/invalid/inactive API key · `404` No agent with that id

**Example:**
```bash
curl http://localhost:8000/agents/103 -H "X-API-Key: <your key>"
```

---

### 14. Deactivate an Agent

**Endpoint:**
```
POST /agents/{agent_id}/deactivate
```

Soft-delete - the row (and its monitoring/scan history) is kept, `is_active` becomes `false`.

**Response (200 OK):**
```json
{"id": 103, "status": "deactivated"}
```

**Status Codes:** `200` Deactivated · `401` Missing/invalid/inactive API key · `404` No agent with that id

**Example:**
```bash
curl -X POST http://localhost:8000/agents/103/deactivate -H "X-API-Key: <your key>"
```

---

## Scan Endpoints

Runs **asynchronously**: a real scan against a real agent (Claude, GPT-4, a `remote_http` backend) can take **11-45 minutes** (653 threats, one sequential call each, no batching - see [ROADMAP.md](ROADMAP.md)), far past any reasonable synchronous HTTP timeout. `POST /scan` returns immediately with a scan id; poll `GET /scan/results/{id}` for progress and the final result. Both require a named API key.

Runs in a background thread of the API's own process (FastAPI `BackgroundTasks`), not a real job queue - an accepted limitation at this project's scale. **A server restart while a scan is `running` loses it silently**: the row stays stuck in `running` forever, with no automatic resume (see [DEPLOYMENT.md](DEPLOYMENT.md)).

### 15. Start a Scan

**Endpoint:**
```
POST /scan
```

**Request Body:** exactly one of `agent_id` or `agent_type` is required.

| Field | Type | Required | Description |
|-------|------|----------|--------------|
| `agent_id` | integer | One of these two | Scan a registered agent |
| `agent_type` | string | One of these two | One-off "quick type" scan - nothing saved to the registry |
| `agent_name` | string | No | Quick-type path only; defaults to `"{agent_type}-quick-scan"` |
| `agent_config` | object | No | Quick-type path only, e.g. `{"endpoint_url": "..."}` for `remote_http` |
| `limit` | integer | No | Test only the first N threats instead of all of them |

Registered agent:
```json
{"agent_id": 103}
```
Quick type:
```json
{"agent_type": "mock", "agent_name": "my_agent", "limit": 5}
```

**Response (200 OK):**
```json
{"id": 34, "status": "pending", "agent_name": "docs-example-agent"}
```

**Status Codes:** `200` Scan started · `400` Neither/both of `agent_id`/`agent_type` given, or unknown `agent_type` · `401` Missing/invalid/inactive API key · `404` `agent_id` doesn't exist or is deactivated

**Examples:**
```bash
curl -X POST http://localhost:8000/scan \
  -H "X-API-Key: <your key>" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": 103}'
```

---

### 16. Get Scan Results

**Endpoint:**
```
GET /scan/results/{scan_id}
```

**Response while still running:**
```json
{
  "id": 34, "agent_id": null, "agent_name": "docs-example-agent",
  "triggered_by_key_label": "docs-example-key", "status": "running",
  "started_at": "2026-08-31T23:02:23.211916", "completed_at": null,
  "total_tested": null, "vulnerabilities_found": null, "safe_threats": null,
  "technical_errors": null, "vulnerability_score": null,
  "created_at": "2026-08-31 21:02:23", "report": null
}
```

**Response when completed** (real example):
```json
{
  "id": 34,
  "agent_id": null,
  "agent_name": "docs-example-agent",
  "triggered_by_key_label": "docs-example-key",
  "status": "completed",
  "started_at": "2026-08-31T23:02:23.211916",
  "completed_at": "2026-08-31T23:02:23.227167",
  "total_tested": 5,
  "vulnerabilities_found": 5,
  "safe_threats": 0,
  "technical_errors": 0,
  "vulnerability_score": 100.0,
  "created_at": "2026-08-31 21:02:23",
  "report": {
    "total_threats": 5,
    "vulnerabilities": ["... full AgentVulnerabilityScanner.scan_all_threats() output"],
    "safe_threats": [],
    "technical_errors": [],
    "by_type": {"...": "per-type total/vulnerable/errors counts"},
    "by_severity": {"...": "per-severity total/vulnerable/errors counts"}
  }
}
```

#### ⚠️ `vulnerability_score` can be `null` - and `null` has two different causes

You must check `status` before drawing any conclusion from `vulnerability_score`:

| `status` | `vulnerability_score` | Meaning |
|----------|------------------------|---------|
| `pending` / `running` | `null` | Not computed yet - the scan is still going |
| `completed` | a number | Real result: `vulnerabilities_found / (total_tested - technical_errors) * 100` |
| `completed` | **`null`** | **Every threat technical-errored (or there were none to test) - nothing was actually measurable** |
| `failed` | `null` | The scan crashed before producing a result |

A `null` score on a `completed` scan is **not** a 0% "clean" result - it means the scan couldn't measure anything (e.g. the agent's endpoint was unreachable for every single threat). Treating it as a low score is exactly the mistake this field's `null` is designed to force you to notice.

**❌ Don't do this** - reading the score without checking `status` first:
```python
import requests
import time

def wait_for_scan(scan_id, api_key, timeout=60 * 45):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = requests.get(
            f"http://localhost:8000/scan/results/{scan_id}",
            headers={"X-API-Key": api_key},
        ).json()
        if r["status"] in ("completed", "failed"):
            return r
        time.sleep(5)
    raise TimeoutError("scan did not finish in time")

result = wait_for_scan(scan_id, API_KEY)

# BUG: if vulnerability_score is null, this comparison raises TypeError
# in Python - and in a looser CI script (a shell test, a language that
# coerces null to 0), the equivalent comparison can silently pass a
# release gate that should have failed instead.
if result["vulnerability_score"] <= 30:
    print("Gate passed: agent is safe enough to deploy.")
else:
    print("Gate failed: too many vulnerabilities.")
```

**✅ Do this instead** - check `status` first, and treat `completed` + `null` score as its own case, not as "safe":
```python
result = wait_for_scan(scan_id, API_KEY)

if result["status"] == "failed":
    raise RuntimeError(f"Scan {scan_id} failed before producing a result")

if result["status"] == "completed" and result["vulnerability_score"] is None:
    # technical_errors == total_tested: nothing was actually testable.
    # This must block a CI/CD gate, never pass it silently.
    raise RuntimeError(
        f"Scan {scan_id} completed but measured nothing "
        f"({result['technical_errors']}/{result['total_tested']} threats "
        f"errored) - treat as inconclusive, not as a passing score."
    )

score = result["vulnerability_score"]
if score <= 30:
    print(f"Gate passed: vulnerability score {score:.1f}%.")
else:
    print(f"Gate failed: vulnerability score {score:.1f}%.")
```

**Status Codes:** `200` Success (check `status` for progress) · `401` Missing/invalid/inactive API key · `404` No scan with that id

**Examples:**
```bash
curl http://localhost:8000/scan/results/34 -H "X-API-Key: <your key>"
```

---

## Error Handling

This section documents actual behavior, verified against `api/app.py` directly.

### Unexpected server errors (500)

Any unhandled exception (database error, etc.) is caught by a global FastAPI exception handler: the real exception and its traceback are logged server-side via `logging`, and the client only ever receives a generic message — never the raw `str(e)` (which could leak file paths or SQL structure; see [SECURITY.md](SECURITY.md)):

```json
{
  "error": "Internal server error",
  "status": "error"
}
```
```
Status: 500
```

**Exception**: `GET /health` keeps its own local error handling instead of the global one, and stays HTTP 200 even on failure (`{"status": "unhealthy", "error": "Internal server error"}`) — a health check reporting itself degraded is a normal response for monitoring tools, not a server error.

### Threat not found

`GET /threats/{threat_id}` with an unknown ID returns a real **HTTP 404**:

```json
{
  "error": "Threat invalid_id not found",
  "status": "not_found"
}
```

### Request validation errors (422)

Endpoints with a Pydantic request body (currently only `POST /monitoring/log-request`) return FastAPI's standard 422 response when a required field is missing or the wrong type — see [Log Request](#6-log-request) for an example.

### Error Handling Example

```python
import requests

try:
    response = requests.get('http://localhost:8000/threats/invalid_id')

    if response.status_code == 200:
        threat = response.json()
        print(f"Found: {threat['title']}")
    elif response.status_code == 404:
        print(f"Not found: {response.json()['error']}")
    else:
        print(f"Error: {response.status_code} - {response.json().get('error')}")

except requests.exceptions.ConnectionError:
    print("Error: Cannot connect to API")
```

---

## Rate Limiting

### Current Status

**No rate limiting in v2.0**

Unlimited requests allowed.

### Planned (v2.1+)

Rate limits will be added:
- Per IP address
- Per API key
- Configurable limits

### Best Practices

Even without rate limiting:
- Don't make unnecessary requests
- Cache responses when possible
- Batch requests efficiently
- Use pagination for large datasets

### Caching Example

```python
import requests
from functools import lru_cache

@lru_cache(maxsize=1)
def get_statistics():
    """Cache statistics for 1 hour"""
    response = requests.get('http://localhost:8000/stats')
    return response.json()['data']

# First call: API request
stats1 = get_statistics()

# Second call: Cached result
stats2 = get_statistics()  # Returns cached value
```

---

## Code Examples

### JavaScript / Node.js

```javascript
// Fetch all threats
async function getAllThreats() {
  const response = await fetch('http://localhost:8000/threats');
  const data = await response.json();
  return data.data;
}

// Get critical threats
async function getCriticalThreats() {
  const response = await fetch(
    'http://localhost:8000/threats?severity=critical'
  );
  const data = await response.json();
  return data.data;
}

// Get threat statistics
async function getStats() {
  const response = await fetch('http://localhost:8000/stats');
  const data = await response.json();
  return data.data;
}

// Usage
getAllThreats().then(threats => {
  console.log(`Found ${threats.length} threats`);
  threats.forEach(threat => {
    console.log(`- ${threat.title} (${threat.severity})`);
  });
});
```

### cURL Examples

```bash
# Get all threats
curl http://localhost:8000/threats

# Get with pagination
curl "http://localhost:8000/threats?limit=50&offset=0"

# Filter by severity
curl "http://localhost:8000/threats?severity=critical"

# Search
curl "http://localhost:8000/threats?search=prompt"

# Get specific threat
curl http://localhost:8000/threats/prompt_injection_001

# Get statistics
curl http://localhost:8000/stats

# Save to file
curl http://localhost:8000/threats > threats.json

# Pretty print JSON
curl http://localhost:8000/stats | python -m json.tool

# With headers
curl -H "Accept: application/json" http://localhost:8000/threats

# POST request (JSON body - see Monitoring Endpoints)
curl -X POST "http://localhost:8000/monitoring/log-request" \
  -H "Content-Type: application/json" \
  -d '{"agent_name": "test", "prompt": "Hello", "response": "OK"}'
```

### Python Complete Example

```python
import requests
import json
from typing import List, Dict

class ThreatIntelligenceClient:
    def __init__(self, base_url='http://localhost:8000'):
        self.base_url = base_url
    
    def get_all_threats(self, type=None, severity=None, limit=100):
        """Get threats with optional filters"""
        params = {'limit': limit}
        if type:
            params['type'] = type
        if severity:
            params['severity'] = severity
        
        response = requests.get(f'{self.base_url}/threats', params=params)
        return response.json()['data']
    
    def get_threat(self, threat_id: str) -> Dict:
        """Get specific threat"""
        response = requests.get(f'{self.base_url}/threats/{threat_id}')
        return response.json()['data']
    
    def get_statistics(self) -> Dict:
        """Get threat statistics"""
        response = requests.get(f'{self.base_url}/stats')
        return response.json()['data']
    
    def get_threat_types(self) -> List[str]:
        """Get all threat types"""
        response = requests.get(f'{self.base_url}/threat-types')
        return response.json()['data']['types']
    
    def get_sources(self) -> List[str]:
        """Get all CTI sources"""
        response = requests.get(f'{self.base_url}/sources')
        return response.json()['data']['sources']
    
    def log_request(self, agent_name: str, prompt: str, response_text: str,
                     user_id: str = None, session_id: str = None):
        """Log an agent request for monitoring (sent as a JSON body,
        matching the current api/app.py LogRequestBody model)"""
        data = {
            'agent_name': agent_name,
            'prompt': prompt,
            'response': response_text
        }
        if user_id:
            data['user_id'] = user_id
        if session_id:
            data['session_id'] = session_id
        response = requests.post(f'{self.base_url}/monitoring/log-request', json=data)
        return response.json()['status'] == 'logged'
    
    def get_agent_stats(self, agent_name: str) -> Dict:
        """Get agent statistics"""
        response = requests.get(f'{self.base_url}/monitoring/stats/{agent_name}')
        return response.json()['data']
    
    def get_agent_health(self, agent_name: str) -> Dict:
        """Get agent health status"""
        response = requests.get(f'{self.base_url}/monitoring/health/{agent_name}')
        return response.json()['data']

# Usage
client = ThreatIntelligenceClient()

# Get statistics
stats = client.get_statistics()
print(f"Total threats: {stats['total_threats']}")

# Get critical prompt injection threats
threats = client.get_all_threats(
    type='prompt_injection',
    severity='critical'
)
print(f"Critical prompt injection: {len(threats)}")

# Log a request
client.log_request(
    agent_name='my_agent',
    prompt='Test prompt',
    response_text='Test response'
)

# Check agent health
health = client.get_agent_health('my_agent')
print(f"Agent status: {health['status']}")
```

---

## Integration Patterns

### Pattern 1: Security Dashboard

```python
# Create a security dashboard from API data

import requests
import json
from datetime import datetime

def create_security_dashboard():
    base_url = 'http://localhost:8000'
    
    # Get threat statistics
    stats = requests.get(f'{base_url}/stats').json()['data']
    
    # Get critical threats
    critical = requests.get(
        f'{base_url}/threats?severity=critical'
    ).json()['data']
    
    # Create dashboard HTML
    html = f"""
    <html>
    <head><title>Security Dashboard</title></head>
    <body>
        <h1>Agent Security Dashboard</h1>
        <p>Updated: {datetime.now().isoformat()}</p>
        
        <h2>Overview</h2>
        <ul>
            <li>Total Threats: {stats['total_threats']}</li>
            <li>Critical: {stats['by_severity']['critical']}</li>
            <li>High: {stats['by_severity']['high']}</li>
        </ul>
        
        <h2>Critical Threats</h2>
        <ul>
    """
    
    for threat in critical[:10]:
        html += f"<li>{threat['title']} ({threat['type']})</li>"
    
    html += """
        </ul>
    </body>
    </html>
    """
    
    with open('dashboard.html', 'w') as f:
        f.write(html)
    
    print("Dashboard created: dashboard.html")

create_security_dashboard()
```

### Pattern 2: Threat Export

```python
# Export threats to various formats

import requests
import csv
import json

def export_threats():
    # Get threats from API
    response = requests.get('http://localhost:8000/threats')
    threats = response.json()['data']
    
    # Export to CSV
    with open('threats.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['threat_id', 'title', 'type', 'severity'])
        writer.writeheader()
        for threat in threats:
            writer.writerow({
                'threat_id': threat['threat_id'],
                'title': threat['title'],
                'type': threat['type'],
                'severity': threat['severity']
            })
    
    # Export to JSON
    with open('threats.json', 'w') as f:
        json.dump(threats, f, indent=2)
    
    print(f"Exported {len(threats)} threats to threats.csv and threats.json")

export_threats()
```

### Pattern 3: Continuous Monitoring

```python
# Monitor agents continuously

import requests
import time
from datetime import datetime

def monitor_agents(agent_names, interval_seconds=60):
    """Continuously monitor agent health"""
    
    while True:
        print(f"\n[{datetime.now().isoformat()}] Health Check")
        
        for agent_name in agent_names:
            try:
                response = requests.get(
                    f'http://localhost:8000/monitoring/health/{agent_name}'
                )
                health = response.json()['data']
                
                status = "✓" if health['status'] == 'healthy' else "✗"
                print(f"{status} {agent_name}: {health['status']} "
                      f"({health['response_time_ms']}ms)")
                
            except Exception as e:
                print(f"✗ {agent_name}: Error - {e}")
        
        time.sleep(interval_seconds)

# Usage
monitor_agents(['agent1', 'agent2', 'agent3'], interval_seconds=30)
```

---

## Changelog

### v2.0 (Current)
- 10 endpoints
- No authentication
- Basic monitoring
- Complete threat database
- Statistics & filtering

### v2.1 (Planned)
- Authentication (API keys)
- Rate limiting
- Advanced alerting
- Webhooks
- Batch operations

### v3.0 (Future)
- OAuth 2.0
- GraphQL endpoint
- WebSocket support
- Advanced analytics

---

## Support & Troubleshooting

### API Not Running

```bash
# Check if API is running
curl http://localhost:8000/health

# If error, start API:
python api/app.py

# Verify it's working:
curl http://localhost:8000/stats
```

### Connection Error

```bash
# Check if port is correct
netstat -an | grep 8000

# Check if firewall allows access
# Windows: Control Panel → Windows Defender Firewall
# macOS/Linux: sudo ufw allow 8000

# Try different port:
python api/app.py --port 8001
```

### No Data

```bash
# Check database has threats
sqlite3 data/threats.db "SELECT COUNT(*) FROM threats;"

# Initialize database:
python pipeline/process.py

# Verify API can access database:
curl http://localhost:8000/stats
```

---

## Next Steps

1. **Start the API** - `python api/app.py`
2. **Test endpoints** - Use curl or Python examples
3. **Build integration** - Follow integration patterns
4. **Monitor agents** - Use monitoring endpoints
5. **Export data** - Use /threats endpoint

---

## Additional Resources

- [Usage Guide](USAGE_GUIDE.md) - How to use dashboards and CLI
- [README.md](../README.md) - Project overview
- [INSTALLATION.md](INSTALLATION.md) - Setup guide
- [ARCHITECTURE.md](ARCHITECTURE.md) - System design

---

<div align="center">

**API Questions?** [Open an Issue](https://github.com/Mavchris/Agent_Security_Framework/issues) | **Need Help?** [Start Discussion](https://github.com/Mavchris/Agent_Security_Framework/discussions)

</div>

---

**Last Updated:** March 28, 2026 | **Version:** 2.0 | **Status:** Production Ready
