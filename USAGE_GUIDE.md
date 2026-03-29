# Usage Guide

Complete guide to using the Agent Security Intelligence Framework. Learn how to navigate dashboards, use the CLI scanner, work with the REST API, and more.

## 📚 Table of Contents

1. [Quick Start](#quick-start)
2. [Dashboard Overview](#dashboard-overview)
3. [Dashboard 1: Operations](#dashboard-1-operations)
4. [Dashboard 2: Intelligence Veille](#dashboard-2-intelligence-veille)
5. [Dashboard 3: Catalog](#dashboard-3-catalog)
6. [CLI Scanner](#cli-scanner)
7. [REST API](#rest-api)
8. [Automation & Orchestrator](#automation--orchestrator)
9. [Common Tasks](#common-tasks)
10. [Tips & Tricks](#tips--tricks)

---

## Quick Start

Get up and running in 2 minutes:

### Launch Dashboards

```bash
# Navigate to project directory
cd Agent_security_framework

# Activate virtual environment (if not already)
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\Activate.ps1  # Windows PowerShell

# Start dashboard hub
streamlit run dashboard/main.py

# Opens automatically at: http://localhost:8501
```

You'll see a welcome page with 3 buttons:
- **Operations** - Test agents & monitor production
- **Intelligence** - Threat overview & veille automation
- **Catalog** - Search 236+ threats

### Test Scanner

```bash
# Test with MockAgent (fast, 1 minute)
python testing/cli.py --scan-agent mock --verbose

# Output shows:
# - Total threats tested: 219
# - Vulnerabilities found: 218
# - Vulnerability score: 99.5%
```

### View Orchestrator Status

```bash
# Check automation status
python orchestrator.py --status

# Shows:
# - Last execution
# - Threats collected
# - Next scheduled run
# - Taux succès: 100%
```

---

## Dashboard Overview

### Navigation Hub

```
┌─────────────────────────────────────┐
│   Agent Security Intelligence       │
│   Framework Navigation Hub          │
├─────────────────────────────────────┤
│                                     │
│  [ Operations ]  [ Intelligence ]   │
│    Test Agents   Threat Overview    │
│    Monitor Prod  Veille Automation  │
│                                     │
│  [ Catalog ]                        │
│    Search Threats                   │
│                                     │
│  [ API Docs ] (Future)              │
│  [ Settings ] (Future)              │
│                                     │
└─────────────────────────────────────┘
```

### Global Features

All dashboards include:
- **Real-time refresh** (Ctrl+R or browser refresh)
- **Export buttons** (CSV, JSON, PDF)
- **Search/filters** (per dashboard)
- **Mobile responsive** (works on phone/tablet)
- **Dark/Light theme** (via Streamlit menu)

---

## Dashboard 1: Operations

### Purpose
Test AI agents for vulnerabilities and monitor production agents.

### Access
```
Click "Operations" on navigation hub
or
streamlit run dashboard/pages/1_operations.py
```

### Layout

#### Tab 1: Test Agent

**Agent Selection**
```
Dropdown: Select agent type
├─ Mock (fastest, for testing)
├─ Claude (requires ANTHROPIC_API_KEY)
├─ GPT-4 (requires OPENAI_API_KEY)
├─ Llama (requires Ollama installed)
├─ Mistral (requires Ollama installed)
├─ HuggingFace (requires transformers installed)
└─ Custom (auto-detect your agent)
```

**Scanner Options**
```
- Show/hide advanced options
- Number of threats to test (1-219)
- Verbosity level
- Export format (JSON, CSV)
```

**Real-time Results**
```
📊 KPI Cards:
├─ Threats Tested: (running count)
├─ Vulnerabilities Found: (count)
├─ Critical Issues: (count)
└─ Vulnerability Score: (percentage)

📈 Charts:
├─ Vulnerabilities by Type (bar)
├─ Vulnerabilities by Severity (bar)
├─ Progress (line chart, real-time)
└─ Top 10 Vulnerabilities (table)

⬇️ Export:
├─ Download JSON
└─ Download CSV
```

**Workflow Example: Test with Mistral**

```
1. Select Agent Type: "Mistral"
   (Requires: Ollama server running in background)

2. Click "Start Scan"

3. Watch real-time progress:
   - Progress bar advances
   - KPI cards update live
   - Charts fill in gradually

4. Wait 10-15 minutes
   (219 threats × 3-4 sec per threat)

5. View results:
   - Vulnerabilities found: ~35-50
   - Vulnerability score: 15-25%
   - Breakdown by type
   - Top critical issues

6. Export results:
   - Click "Download JSON"
   - File: vulnerabilities_mistral_20260328.json
   - Share with team, add to reports

7. Compare to MockAgent:
   - Mock: 99.5% (simulation)
   - Mistral: 15-25% (real behavior)
   - Gap shows gap between simulation vs reality
```

#### Tab 2: Monitor Production

**Production Agent Status**
```
📊 Health Metrics:
├─ Agent Status: Healthy/Warning/Critical
├─ Last Heartbeat: (timestamp)
├─ Uptime: (days/hours)
├─ Response Time: (milliseconds)
└─ Error Rate: (percentage)

🚨 Alerts:
├─ Critical Threats Detected: (count)
├─ Recent Alerts: (table, last 24h)
└─ Alert History: (chart, last 7 days)

📈 Performance:
├─ Request Rate: (per minute)
├─ Average Response Time: (ms)
├─ Error Rate Trend: (line chart)
└─ Uptime: (percentage)

⚡ Actions:
├─ [ Start Agent ]
├─ [ Stop Agent ]
├─ [ Restart Agent ]
├─ [ Run Scan Now ]
└─ [ View Logs ]
```

**Workflow Example: Monitor Custom Agent**

```
1. Agent already running in production
   (e.g., your company's custom LLM wrapper)

2. Open "Monitor Production" tab

3. Framework auto-discovers agent at localhost:8000

4. Monitor in real-time:
   - Healthy green indicator
   - Request rate
   - Response times
   - Error rate trends

5. If warning appears:
   - Check "Alert Trend" chart
   - View logs with [View Logs]
   - Click [Run Scan] to diagnose

6. Act on alerts:
   - Click [Stop Agent] if critical
   - Fix underlying issue
   - Click [Start Agent] to resume
   - Verify health returns to green
```

---

## Dashboard 2: Intelligence Veille

### Purpose
Threat overview, veille automation status, recent threats, logs.

### Access
```
Click "Intelligence" on navigation hub
or
streamlit run dashboard/pages/2_intelligence.py
```

### Tabs Overview

#### Tab 1: Vue d'Ensemble (Overview)

**Threat Metrics**
```
📊 KPI Cards:
├─ Total Menaces: 236
├─ Critiques: 58
├─ Hautes: 145
├─ Moyennes: 33
└─ Basses: 10

⚙️ Orchestrator Status:
├─ Exécutions: 1+
├─ Taux succès: 100%
├─ Menaces collectées: 236
├─ Dernière exécution: (timestamp)
└─ Prochaines tâches: (schedule)

📈 Distribution Charts:
├─ Par Sévérité (bar chart)
├─ Par Type (bar chart)
└─ Par Source (pie chart)

📊 Tendances (30 days):
├─ Line chart: menaces collectées/jour
├─ Moyenne/jour: X menaces
└─ Pic collectes: X menaces (date)
```

**Workflow Example: Daily Briefing**

```
1. Every morning, check "Vue d'Ensemble"

2. KPI cards tell you at a glance:
   - Total threats: 236 (baseline)
   - Critical: 58 (what to focus on)
   - Orchestrator: 100% success (system healthy)

3. Check Orchestrator Status:
   - Dernière exécution: "Today 02:00 UTC" ✓
   - Menaces collectées: "0" (normal, all in DB)
   - Taux succès: "100%" ✓

4. Review Tendances:
   - Spike yesterday? (chart shows)
   - Normal trend? (should be flat)
   - Anomalies? (investigate)

5. Decision: All normal? Continue. Anomaly? Go to Tab 2 (Menaces Récentes)
```

#### Tab 2: Menaces Récentes (Recent Threats)

**Threat Table**
```
Columns:
├─ ID: Unique threat identifier
├─ Title: Threat name
├─ Type: Category (9 options)
├─ Severity: critical/high/medium/low
├─ Source: Which CTI feed
└─ Date: When collected

Filters:
├─ Type filter: Select 1+ categories
├─ Severity filter: Select 1+ severity levels
├─ Search: By ID or title
└─ [Apply] [Reset]

Results:
├─ Shows up to 50 latest threats
├─ Pagination: Next/Previous
└─ Total: X threats matching filters
```

**Workflow Example: Find Prompt Injection Vulnerabilities**

```
1. Click "Menaces Récentes" tab

2. Apply filters:
   - Type: Select only "prompt_injection"
   - Severity: Select "critical" & "high"
   - Click [Apply]

3. Results show:
   - 72 prompt injection threats
   - 30 are critical/high
   - Ordered by newest first

4. Review top results:
   - Read threat descriptions
   - Understand attack vectors
   - Check detection keywords

5. Export filtered results:
   - Click [Download CSV]
   - File: threats_20260328.csv
   - Share with security team
   - Use in risk assessment

6. Or expand individual threat:
   - Click on row
   - See full details:
     ├─ Complete description
     ├─ Test payload (how to test)
     ├─ Detection keywords
     ├─ CVSS score
     └─ Source URL
```

#### Tab 3: Orchestrateur Status

**Scheduler Information**
```
📊 Execution Metrics:
├─ Total Executions: 1+
├─ Successful: X
├─ Failed: Y
├─ Success Rate: Z%

📅 Last Execution:
├─ Date & Time: (timestamp)
├─ Duration: X seconds
├─ Threats Collected: N
├─ Status: ✓ Success / ✗ Failed

🔄 Next Scheduled:
├─ Daily: 02:00 UTC (tomorrow)
├─ Weekly: Monday 10:00 UTC (next Monday)
├─ Health Check: Hourly (next: in X min)

⚡ Manual Actions:
├─ [Run Daily Pipeline] (immediate)
├─ [Run Weekly Pipeline] (immediate)
├─ [Run Health Check] (immediate)
└─ [Refresh Status]
```

**Workflow Example: Verify Automation**

```
1. Click "Orchestrateur" tab each day

2. Check metrics:
   - Success Rate: Should be 100% ✓
   - Last Execution: Should be today 02:00 UTC ✓
   - Threats Collected: Should be 0 (all in DB)

3. If something wrong:
   - Success Rate < 100%: Check logs (Tab 4)
   - Last Execution old: Run manually [Run Daily Pipeline]
   - Status shows errors: Review Tab 4 logs

4. For manual triggering:
   - Need fresh data? [Run Daily Pipeline] (now)
   - Need validation? [Run Weekly Pipeline]
   - Quick health check? [Health Check]

5. After manual run:
   - Wait 30 seconds
   - Click [Refresh Status]
   - Status should update
```

#### Tab 4: Logs & Monitoring

**Log Viewer**
```
Features:
├─ Real-time log display
├─ Last 50 lines by default
├─ Slider: View 10-200 lines
├─ Auto-refresh: Every 5 seconds
├─ [Refresh Now] button
└─ [Download Full Logs]

Log Format:
[2026-03-28 14:30:00] [INFO] Pipeline started
[2026-03-28 14:30:02] [INFO] Scraping NVD...
[2026-03-28 14:30:05] [INFO] Collected 25 threats
[2026-03-28 14:30:10] [INFO] Classifying threats...
[2026-03-28 14:30:15] [INFO] Pipeline complete
```

**Workflow Example: Troubleshoot Failed Pipeline**

```
1. Orchestrator shows: Failed run

2. Click "Logs" tab

3. Increase slider to 100 lines

4. Scroll to find [ERROR]:
   [2026-03-28 02:00:00] [ERROR] NVD scraper timeout
   [2026-03-28 02:00:05] [ERROR] Retry attempt 1...
   [2026-03-28 02:00:10] [ERROR] Retry attempt 2...
   [2026-03-28 02:00:15] [ERROR] NVD scraper failed

5. Understand issue:
   - NVD API was slow
   - 3 retries attempted
   - Finally failed after timeout

6. Options:
   - Wait for next run (02:00 UTC tomorrow)
   - Run manually: [Run Daily Pipeline] in Orchestrator tab
   - Check internet connection
   - Check NVD API status

7. Export logs for debugging:
   - [Download Full Logs]
   - File: orchestrator_20260328.log
   - Share with developer/support
```

---

## Dashboard 3: Catalog

### Purpose
Search and explore 236+ threats with advanced filtering.

### Access
```
Click "Catalog" on navigation hub
or
streamlit run dashboard/pages/3_catalog.py
```

### Features

**Advanced Filters**
```
Filter by Type:
├─ prompt_injection (72)
├─ api_abuse (26)
├─ tool_abuse (3)
├─ model_extraction (2)
├─ behavioral_anomaly (2)
├─ supply_chain (1)
├─ data_leakage (1)
├─ data_poisoning (0)
└─ resource_exhaustion (0)

Filter by Severity:
├─ critical (58)
├─ high (145)
├─ medium (33)
└─ low (10)

Filter by Source:
├─ NVD (NIST)
├─ GitHub Security
├─ MITRE ATT&CK
├─ ArXiv
├─ Censys
├─ MISP
└─ OpenCTI

Search:
├─ By threat ID
├─ By title (partial match)
└─ Full-text search
```

**Threat Details**
```
For each threat, see:
├─ Threat ID
├─ Title
├─ Description (full)
├─ Type (category)
├─ Severity (level)
├─ Source (CTI feed)
├─ Test Payload (how to test vulnerability)
├─ Detection Keywords (what to look for)
├─ CVSS Score
└─ Source URL (click to original)
```

**Workflow Example: Research Prompt Injection**

```
1. Open "Catalog" dashboard

2. Filter:
   - Type: Select "prompt_injection"
   - Severity: Select "critical" & "high"

3. Results: 72 prompt injection threats
   - 30 are critical/high severity
   - Newest first

4. Expand first result:
   - Read full description
   - Understand attack technique
   - Review test payload:
     "Ignore previous instructions and..."
   - Check detection keywords:
     "DAN", "jailbreak", "override", "ignore"

5. Use this knowledge:
   - Update your agent defenses
   - Test your agent with payload
   - Implement detection keywords

6. Export for analysis:
   - Select multiple threats (checkboxes)
   - Click [Export Selected] CSV
   - Import to spreadsheet
   - Share with team

7. Or continue browsing:
   - Click next threat
   - Learn attack patterns
   - Build security knowledge
```

### Export Options

```bash
# Option 1: Via Dashboard
- Select threats
- Click [Export CSV] or [Export JSON]
- File downloaded to Downloads/

# Option 2: Via CLI
python testing/cli.py --scan-agent mock --output threats.json
# Exports all threats in JSON format

# Option 3: Via API
curl http://localhost:8000/threats?format=json > threats.json
# Raw API export

# Option 4: Via Database
sqlite3 data/threats.db "SELECT * FROM threats;" > threats.csv
# Direct database export
```

---

## CLI Scanner

### Basic Usage

```bash
# Syntax
python testing/cli.py [OPTIONS]

# Options
--scan-agent AGENT          Agent to test (mock, claude, gpt4, mistral, etc.)
--output FILE               Save results to JSON file
--verbose                   Show detailed output
--limit N                   Test only N threats (default: all)
--help                      Show all options
```

### Examples

#### Example 1: Quick Test (MockAgent)

```bash
python testing/cli.py --scan-agent mock --verbose

# Output:
# Agent Security Framework - Vulnerability Scanner
# Agent: MockAgent
# Threats to test: 219
# 
# [████████████████████] 100%
# 
# RESULTS:
# ├─ Total Threats: 219
# ├─ Vulnerabilities Found: 218
# ├─ Vulnerability Score: 99.5%
# ├─ Safe Threats: 1
# └─ Execution Time: 52 seconds
#
# BREAKDOWN BY TYPE:
# ├─ prompt_injection: 72 found (100%)
# ├─ api_abuse: 26 found (100%)
# ├─ tool_abuse: 3 found (100%)
# └─ ...
#
# BREAKDOWN BY SEVERITY:
# ├─ critical: 58 found (100%)
# ├─ high: 145 found (100%)
# ├─ medium: 33 found (100%)
# └─ low: 10 found (95%)
#
# TOP 10 VULNERABILITIES:
# 1. Prompt Injection via System Prompt
# 2. API Key Extraction
# 3. Function Call Abuse
# ...
```

#### Example 2: Test with Mistral (Real LLM)

```bash
# Prerequisites:
# 1. ollama pull mistral
# 2. ollama serve (in separate terminal)

python testing/cli.py --scan-agent mistral --verbose --output mistral_audit.json

# Output (similar to above, but:)
# ├─ Vulnerabilities Found: ~45 (real behavior)
# ├─ Vulnerability Score: ~20%
# └─ Execution Time: 652 seconds (10+ minutes)
#
# File created: mistral_audit.json
# Contains full results in JSON format
```

#### Example 3: Test Subset (Quick Validation)

```bash
# Test only 20 threats (quick validation)
python testing/cli.py --scan-agent claude --limit 20 --output quick_test.json

# Output:
# ├─ Total Threats: 20 (of 219)
# ├─ Vulnerabilities Found: 18
# ├─ Vulnerability Score: 90%
# └─ Execution Time: 45 seconds
#
# Fast way to validate before full scan
```

#### Example 4: Custom Agent

```bash
# Test your own agent
python testing/cli.py --scan-agent custom --output custom_audit.json

# Framework auto-detects:
# ├─ query() method
# ├─ generate() method
# ├─ chat() method
# ├─ run() method
# └─ call() method
#
# Uses first one found
```

#### Example 5: Comparison (Multiple Agents)

```bash
# Test multiple agents in sequence
python testing/cli.py --scan-agent mock --output mock.json
python testing/cli.py --scan-agent mistral --output mistral.json
python testing/cli.py --scan-agent claude --output claude.json

# Now compare results:
# Mock: 99.5% vulnerabilities (simulation)
# Mistral: 20% (real LLM)
# Claude: 25% (real LLM)
#
# Compare files:
diff mock.json mistral.json
```

### Output Files

```json
{
  "scan_date": "2026-03-28T14:30:00Z",
  "agent_type": "mistral",
  "total_threats": 219,
  "vulnerabilities_found": 45,
  "vulnerability_score": 20.5,
  "execution_time_seconds": 652,
  "results_by_type": {
    "prompt_injection": {
      "total": 72,
      "found": 15,
      "percentage": 20.8
    },
    "api_abuse": {
      "total": 26,
      "found": 8,
      "percentage": 30.8
    }
    ...
  },
  "results_by_severity": {
    "critical": {
      "total": 58,
      "found": 20,
      "percentage": 34.5
    },
    ...
  },
  "top_vulnerabilities": [
    {
      "threat_id": "prompt_injection_001",
      "title": "System Prompt Override",
      "severity": "critical",
      "detected": true
    },
    ...
  ]
}
```

---

## REST API

### Base URL

```
http://localhost:8000
```

### Start API Server

```bash
python api/app.py

# Or specify port:
python api/app.py --port 8001

# Output:
# INFO:     Started server process
# INFO:     Uvicorn running on http://127.0.0.1:8000
# INFO:     Application startup complete
```

### Endpoints

#### 1. Get All Threats

```bash
GET /threats

# curl example:
curl http://localhost:8000/threats

# Python example:
import requests
response = requests.get('http://localhost:8000/threats')
threats = response.json()
print(f"Total threats: {len(threats)}")

# Response (JSON array):
[
  {
    "threat_id": "prompt_injection_001",
    "title": "System Prompt Override",
    "type": "prompt_injection",
    "severity": "critical",
    "source": "mitre_attack",
    "description": "...",
    "test_payload": "...",
    "detection_keywords": [...],
    "created_at": "2026-03-28T10:00:00Z"
  },
  ...
]

# Optional parameters:
?type=prompt_injection          # Filter by type
?severity=critical              # Filter by severity
?source=nvd                      # Filter by source
?limit=50                        # Limit results
?offset=50                       # Pagination offset
```

#### 2. Get Specific Threat

```bash
GET /threats/{threat_id}

# curl example:
curl http://localhost:8000/threats/prompt_injection_001

# Python example:
threat = requests.get('http://localhost:8000/threats/prompt_injection_001').json()
print(threat['title'])

# Response:
{
  "threat_id": "prompt_injection_001",
  "title": "System Prompt Override",
  "type": "prompt_injection",
  "severity": "critical",
  ...
}
```

#### 3. Get Statistics

```bash
GET /stats

# curl example:
curl http://localhost:8000/stats

# Python example:
stats = requests.get('http://localhost:8000/stats').json()
print(f"Total threats: {stats['total']}")

# Response:
{
  "total_threats": 236,
  "by_severity": {
    "critical": 58,
    "high": 145,
    "medium": 33,
    "low": 10
  },
  "by_type": {
    "prompt_injection": 72,
    "api_abuse": 26,
    ...
  },
  "by_source": {
    "nvd": 80,
    "github": 122,
    ...
  }
}
```

#### 4. Get Threat Types

```bash
GET /threat-types

# curl example:
curl http://localhost:8000/threat-types

# Response:
{
  "types": [
    "prompt_injection",
    "api_abuse",
    "tool_abuse",
    "model_extraction",
    "behavioral_anomaly",
    "data_leakage",
    "data_poisoning",
    "supply_chain",
    "resource_exhaustion"
  ]
}
```

#### 5. Get Sources

```bash
GET /sources

# Response:
{
  "sources": [
    "nvd",
    "github_security",
    "mitre_attack",
    "arxiv",
    "censys",
    "misp",
    "opencti"
  ]
}
```

#### 6. Get Agent Health

```bash
GET /monitoring/health/{agent_name}

# curl example:
curl http://localhost:8000/monitoring/health/my_agent

# Response:
{
  "agent_name": "my_agent",
  "status": "healthy",
  "uptime_seconds": 86400,
  "last_heartbeat": "2026-03-28T14:30:00Z",
  "response_time_ms": 45
}
```

### API Examples

#### Use Case 1: Fetch All Critical Threats

```python
import requests

# Get all threats
response = requests.get('http://localhost:8000/threats')
all_threats = response.json()

# Filter for critical
critical = [t for t in all_threats if t['severity'] == 'critical']

print(f"Critical threats: {len(critical)}")
for threat in critical[:5]:
    print(f"- {threat['title']}")
```

#### Use Case 2: Export to CSV

```python
import requests
import csv

# Get all threats
threats = requests.get('http://localhost:8000/threats').json()

# Write to CSV
with open('threats.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['threat_id', 'title', 'type', 'severity', 'source'])
    writer.writeheader()
    for threat in threats:
        writer.writerow({
            'threat_id': threat['threat_id'],
            'title': threat['title'],
            'type': threat['type'],
            'severity': threat['severity'],
            'source': threat['source']
        })

print("Exported to threats.csv")
```

#### Use Case 3: Build Dashboard Integration

```python
import requests
import json

# Get statistics
stats = requests.get('http://localhost:8000/stats').json()

# Create dashboard payload
dashboard_data = {
    "total_threats": stats['total_threats'],
    "severity_breakdown": stats['by_severity'],
    "type_breakdown": stats['by_type'],
    "source_breakdown": stats['by_source'],
    "timestamp": "2026-03-28T14:30:00Z"
}

# Send to your dashboard
with open('dashboard_data.json', 'w') as f:
    json.dump(dashboard_data, f, indent=2)
```

---

## Automation & Orchestrator

### Start Orchestrator

```bash
python orchestrator.py

# Output:
# [2026-03-28 14:30:00] Starting Pipeline Orchestrator
# [2026-03-28 14:30:00] Scheduler initialized
# [2026-03-28 14:30:00] Next daily pipeline: 2026-03-29 02:00 UTC
# [2026-03-28 14:30:00] Next weekly pipeline: 2026-03-29 10:00 UTC
# [2026-03-28 14:30:00] Health check scheduled: every hour
# [2026-03-28 14:30:00] Orchestrator running... (Ctrl+C to stop)
```

### Schedule

```
Daily Pipeline (02:00 UTC):
├─ Scrape all 7 CTI sources
├─ Collect new threats
├─ Classify threats
├─ Update database
└─ Save metrics

Weekly Pipeline (Monday 10:00 UTC):
├─ Run daily pipeline (if not run today)
├─ Validate all threats
├─ Deduplicate database
├─ Generate weekly report
└─ Archive old data

Health Check (Hourly):
├─ Verify database integrity
├─ Check disk space
├─ Validate configuration
└─ Report any issues
```

### Manual Commands

```bash
# Check status
python orchestrator.py --status

# Run daily pipeline immediately
python orchestrator.py --run-daily

# Run weekly pipeline immediately
python orchestrator.py --run-weekly

# Test mode (run pipeline once and exit)
python orchestrator.py --test

# Run with debug logging
python orchestrator.py --debug

# Stop orchestrator (if running)
# Ctrl+C in terminal
```

### View Metrics

```bash
# View orchestrator metrics
cat logs/orchestrator_metrics.json

# Example output:
{
  "total_runs": 5,
  "successful_runs": 5,
  "failed_runs": 0,
  "last_run_time": "2026-03-28T02:00:00Z",
  "last_threats_collected": 0,
  "execution_times": [8.2, 8.1, 8.3, 8.0, 8.2],
  "average_execution_time": 8.16
}
```

### View Logs

```bash
# View orchestrator logs
tail -f logs/orchestrator.log

# Example:
# [2026-03-28 02:00:00] [INFO] Starting daily pipeline
# [2026-03-28 02:00:01] [INFO] NVD scraper started
# [2026-03-28 02:00:05] [INFO] Collected 25 NVD threats
# [2026-03-28 02:00:05] [INFO] GitHub scraper started
# [2026-03-28 02:00:10] [INFO] Collected 0 GitHub threats (all duplicates)
# ...
# [2026-03-28 02:00:15] [INFO] Pipeline completed
```

---

## Common Tasks

### Task 1: Evaluate Your Agent

```bash
# Step 1: Prepare your agent
# Make sure it's running at http://localhost:8000
# Or wrapped in our framework (see testing/agent_wrappers.py)

# Step 2: Run scanner
python testing/cli.py --scan-agent custom --output evaluation.json --verbose

# Step 3: Review results
# Check vulnerability score
# Review breakdown by type/severity
# Identify top vulnerabilities

# Step 4: Remediate
# Fix identified vulnerabilities
# Update agent defenses

# Step 5: Re-test
python testing/cli.py --scan-agent custom --output evaluation_v2.json
# Compare scores: evaluation.json vs evaluation_v2.json
```

### Task 2: Build Monthly Security Report

```bash
# Step 1: Gather data
python testing/cli.py --scan-agent mock --output baseline.json

# Step 2: Create report in Python
import json
from datetime import datetime

with open('baseline.json') as f:
    data = json.load(f)

report = f"""
AGENT SECURITY ASSESSMENT REPORT
Date: {datetime.now().strftime('%Y-%m-%d')}

Executive Summary:
- Total threats tested: {data['total_threats']}
- Vulnerabilities found: {data['vulnerabilities_found']}
- Vulnerability score: {data['vulnerability_score']:.1f}%

Recommendations:
1. Address critical vulnerabilities first
2. Implement detection keywords
3. Schedule monthly re-testing
4. Keep threat database updated (auto via orchestrator)

Detailed results: See attached baseline.json
"""

with open('report.txt', 'w') as f:
    f.write(report)

print("Report created: report.txt")
```

### Task 3: Setup Continuous Monitoring

```bash
# Step 1: Start orchestrator (runs forever)
python orchestrator.py &

# Step 2: Start API server (runs forever)
python api/app.py &

# Step 3: Start dashboard
streamlit run dashboard/main.py

# Step 4: Monitor from dashboard
# Intelligence → Orchestrateur → Check status
# Intelligence → Vue d'Ensemble → Review trends
# Check logs daily

# Step 5: Set calendar reminders
# - Weekly review (every Monday)
# - Monthly assessment (first of month)
# - Quarterly planning (every 3 months)
```

### Task 4: Share Threat Intelligence

```bash
# Export threats for sharing
python testing/cli.py --scan-agent mock --output threats_export.json

# Or via API:
curl http://localhost:8000/threats > threats_export.json

# Share file with team:
# - Via email
# - Via Slack
# - Via Git repository
# - Via shared drive
# - Via cloud storage

# Team can import:
# - Open in spreadsheet (convert JSON to CSV)
# - Load in their security tools
# - Integrate with SIEM
# - Create custom alerts
```

---

## Tips & Tricks

### Tip 1: Fast Testing

```bash
# MockAgent is 10x faster than real LLMs
# Use for quick validation before full scan

# Fast validation (30 seconds):
python testing/cli.py --scan-agent mock --limit 20

# Full test with real LLM (10+ minutes):
python testing/cli.py --scan-agent mistral

# Fast validation useful for:
- CI/CD pipelines
- Quick regression testing
- Before/after comparisons
- Development/testing
```

### Tip 2: Performance Tuning

```bash
# If slow, try these:

# 1. Use MockAgent (fast)
python testing/cli.py --scan-agent mock

# 2. Test subset of threats
python testing/cli.py --scan-agent mistral --limit 50

# 3. Run during off-peak hours
python testing/cli.py --scan-agent gpt4  # (at night)

# 4. Check system resources
# Close other applications
# Monitor RAM usage (should be < 1GB)
```

### Tip 3: Comparison Analysis

```bash
# Compare different agents
python testing/cli.py --scan-agent mock --output mock.json
python testing/cli.py --scan-agent mistral --output mistral.json
python testing/cli.py --scan-agent claude --output claude.json

# Compare results in Python:
import json

with open('mock.json') as f:
    mock = json.load(f)
with open('mistral.json') as f:
    mistral = json.load(f)
with open('claude.json') as f:
    claude = json.load(f)

print("Vulnerability Scores:")
print(f"- Mock: {mock['vulnerability_score']:.1f}%")
print(f"- Mistral: {mistral['vulnerability_score']:.1f}%")
print(f"- Claude: {claude['vulnerability_score']:.1f}%")

print("\nPrompt Injection Detection:")
print(f"- Mock: {mock['results_by_type']['prompt_injection']['percentage']:.1f}%")
print(f"- Mistral: {mistral['results_by_type']['prompt_injection']['percentage']:.1f}%")
print(f"- Claude: {claude['results_by_type']['prompt_injection']['percentage']:.1f}%")
```

### Tip 4: Automate in CI/CD

```bash
# GitHub Actions example (.github/workflows/security-test.yml):

name: Agent Security Test

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 02:00 UTC

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
      - name: Run security test
        run: |
          python testing/cli.py --scan-agent mock --output results.json
      - name: Check results
        run: |
          python -c "
          import json
          with open('results.json') as f:
              data = json.load(f)
          if data['vulnerability_score'] > 50:
              print('⚠️ High vulnerability score!')
              exit(1)
          else:
              print('✓ Agent passed security test')
          "
```

### Tip 5: Integration with SIEM

```bash
# Export to Splunk/ELK/etc.

import requests
import json

# Get threats from API
threats = requests.get('http://localhost:8000/threats').json()

# Format for SIEM (example for Splunk):
splunk_events = []
for threat in threats:
    event = {
        "event": threat,
        "source": "agent_security_framework",
        "sourcetype": "threat_intelligence",
        "host": "security-framework"
    }
    splunk_events.append(event)

# Send to Splunk HEC:
import requests
headers = {"Authorization": f"Splunk {hec_token}"}
for event in splunk_events:
    requests.post("https://splunk-server:8088/services/collector", 
                  json=event, headers=headers)

print(f"Sent {len(splunk_events)} events to Splunk")
```

---

## Keyboard Shortcuts

### Streamlit Dashboards

```
Ctrl+R or Cmd+R         Refresh page
r                       Rerun script
Ctrl+C                  Stop server
Ctrl+Shift+M            Toggle light/dark theme
?                       Show help
```

### Command Line

```
Ctrl+C                  Stop running process
↑ Arrow                 Previous command history
↓ Arrow                 Next command history
Ctrl+A                  Move to start of line
Ctrl+E                  Move to end of line
Ctrl+U                  Clear line
```

---

## Troubleshooting Common Issues

### Dashboard Shows "No Threats"

```bash
# 1. Check database exists
ls -la data/threats.db

# 2. Initialize database
python pipeline/process.py

# 3. Verify threats exist
sqlite3 data/threats.db "SELECT COUNT(*) FROM threats;"

# 4. Restart dashboard
# Ctrl+C then: streamlit run dashboard/main.py
```

### Scanner Takes Too Long

```bash
# Use MockAgent instead:
python testing/cli.py --scan-agent mock  # 1 minute
# Instead of:
python testing/cli.py --scan-agent mistral  # 10+ minutes

# Or limit threats:
python testing/cli.py --scan-agent claude --limit 20
```

### API Returns Empty Results

```bash
# 1. Check API is running
curl http://localhost:8000/health

# 2. Check database has data
python -c "import sqlite3; conn = sqlite3.connect('data/threats.db'); cursor = conn.cursor(); cursor.execute('SELECT COUNT(*) FROM threats'); print(cursor.fetchone()[0])"

# 3. Restart API
# Ctrl+C then: python api/app.py
```

---

## Next Steps

Now that you know how to use the framework:

1. **Explore dashboards** - Spend 30 min browsing threats
2. **Test your agent** - Run scanner on your custom agent
3. **Set up automation** - Start orchestrator for continuous monitoring
4. **Integrate with your tools** - Use API or export functions
5. **Review trends** - Check weekly reports for insights

---

## Additional Resources

- [README.md](../README.md) - Project overview
- [INSTALLATION.md](INSTALLATION.md) - Setup guide
- [API_DOCUMENTATION.md](API_DOCUMENTATION.md) - REST API details
- [ARCHITECTURE.md](ARCHITECTURE.md) - System design
- [GitHub Issues](https://github.com/Mavchris/Agent_Security_Framework/issues) - Report bugs
- [GitHub Discussions](https://github.com/Mavchris/Agent_Security_Framework/discussions) - Ask questions

---

<div align="center">

**Happy threat hunting! 🔍**

[Report Issues](https://github.com/Mavchris/Agent_Security_Framework/issues) | [Ask Questions](https://github.com/Mavchris/Agent_Security_Framework/discussions) | [Share Feedback](https://github.com/Mavchris/Agent_Security_Framework/issues)

</div>

---

**Last Updated:** March 28, 2026 | **Version:** 2.0 | **Status:** Production Ready
