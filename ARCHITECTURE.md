# Architecture Documentation

Complete system architecture documentation for the Agent Security Intelligence Framework. Includes design decisions, component descriptions, data flows, UML diagrams, and design patterns.

## 📚 Table of Contents

1. [Overview](#overview)
2. [Architectural Principles](#architectural-principles)
3. [System Architecture](#system-architecture)
4. [Component Descriptions](#component-descriptions)
5. [Data Flow](#data-flow)
6. [Database Design](#database-design)
7. [Design Patterns](#design-patterns)
8. [Module Organization](#module-organization)
9. [Deployment Architecture](#deployment-architecture)
10. [Security Architecture](#security-architecture)
11. [Performance Considerations](#performance-considerations)
12. [Extension Points](#extension-points)

---

## Overview

### Purpose

The Agent Security Intelligence Framework is designed to:
1. **Collect** threat intelligence from 9 CTI sources
2. **Classify** threats into 9 security categories
3. **Test** AI agents against real-world threats
4. **Monitor** agent security posture continuously
5. **Report** vulnerabilities and insights

### Architecture Goals

```
┌──────────────────────────────────┐
│   DESIGN GOALS                   │
├──────────────────────────────────┤
│ ✓ Modularity                     │
│ ✓ Extensibility                  │
│ ✓ Scalability                    │
│ ✓ Maintainability                │
│ ✓ Reliability (2/2 runs OK)      │
│ ✓ Transparency (open-source)     │
│ ✓ Automation (24/7 operation)    │
│ ✓ User Experience (3 dashboards) │
└──────────────────────────────────┘
```

### Key Metrics

```
┌──────────────────────────────────┐
│   CURRENT STATUS (v2.0)          │
├──────────────────────────────────┤
│ Total Code:      4000+ lines     │
│ Test Coverage:   13/13 passing   │
│ Threats DB:      653 threats     │
│ CTI Sources:     9 active        │
│ Threat Types:    9 categories    │
│ Dashboards:      3 production    │
│ API Endpoints:   10 functional   │
│ Automation:      2/2 runs OK     │
│ Production Ready: 65/100         │
└──────────────────────────────────┘
```

---

## Architectural Principles

### 1. Layered Architecture

```
┌─────────────────────────────────┐
│  PRESENTATION LAYER             │
│  (Dashboards, CLI, API)         │
├─────────────────────────────────┤
│  APPLICATION LAYER              │
│  (Services, Business Logic)     │
├─────────────────────────────────┤
│  DATA LAYER                     │
│  (Database, Storage)            │
├─────────────────────────────────┤
│  EXTERNAL LAYER                 │
│  (CTI Sources, APIs)            │
└─────────────────────────────────┘
```

### 2. Separation of Concerns

Each module has single responsibility:

```
Scrapers:       Extract threat data
Classifier:     Categorize threats
Scanner:        Test agents
Orchestrator:   Schedule tasks
Dashboards:     Visualize data
API:            Expose services
```

### 3. Abstraction Layers

**Multi-Agent Support Example:**

```python
# Abstract interface
class AgentWrapper:
    def query(self, prompt: str) -> str:
        pass

# Concrete implementations
class ClaudeWrapper(AgentWrapper):    # Anthropic
class GPT4Wrapper(AgentWrapper):      # OpenAI
class MistralWrapper(AgentWrapper):   # Ollama
class CustomWrapper(AgentWrapper):    # User's agent
```

Users add new agents by implementing single interface.

---

## System Architecture

### High-Level View

```
AGENT SECURITY INTELLIGENCE FRAMEWORK
═════════════════════════════════════════════════════════════

┌──────────────────────────────────────────────────────────┐
│                    PRESENTATION LAYER                    │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  ┌─────────────────┐  ┌─────────────────┐             │
│  │   Dashboards    │  │   REST API      │             │
│  │   (Streamlit)   │  │   (FastAPI)     │             │
│  └────────┬────────┘  └────────┬────────┘             │
│           │                    │                      │
│  ┌────────┴────────────────────┴────────┐            │
│  │   CLI Scanner (testing/cli.py)      │            │
│  └────────┬─────────────────────────────┘            │
└───────────┼────────────────────────────────────────────┘
            │
┌───────────┼────────────────────────────────────────────┐
│           ▼          APPLICATION LAYER                 │
├──────────────────────────────────────────────────────┤
│                                                      │
│  ┌──────────────┐  ┌──────────────┐                │
│  │   Scanner    │  │ Classifier   │                │
│  │  (419 lines) │  │ (9 categories)               │
│  └──────┬───────┘  └──────┬───────┘                │
│         │                 │                        │
│  ┌──────┴─────────────────┴──────┐                │
│  │   Orchestrator (Scheduler)    │                │
│  │   (schedule library)          │                │
│  └──────┬──────────────────────┘                │
│         │                                        │
│  ┌──────┴──────────────────────────────┐        │
│  │   Pipeline (ETL)                   │        │
│  │  ├─ Extract (9 sources)            │        │
│  │  ├─ Transform (normalize)          │        │
│  │  └─ Load (SQLite)                  │        │
│  └──────┬──────────────────────────┘        │
└─────────┼────────────────────────────────────┘
          │
┌─────────┼────────────────────────────────────────────┐
│         ▼          DATA LAYER                        │
├──────────────────────────────────────────────────────┤
│                                                      │
│  ┌──────────────────────────────────────┐          │
│  │   SQLite Database (threats.db)       │          │
│  │  ├─ threats table (653 rows)         │          │
│  │  ├─ classifications                 │          │
│  │  └─ metadata                        │          │
│  └──────────────────────────────────────┘          │
│                                                      │
│  ┌──────────────────────────────────────┐          │
│  │   File Storage (logs/)               │          │
│  │  ├─ orchestrator.log                 │          │
│  │  ├─ orchestrator_metrics.json        │          │
│  │  └─ weekly_report_*.json             │          │
│  └──────────────────────────────────────┘          │
│                                                      │
└──────────────────────────────────────────────────────┘
          │
┌─────────┼────────────────────────────────────────────┐
│         ▼          EXTERNAL LAYER                    │
├──────────────────────────────────────────────────────┤
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
│  │   NVD    │  │  GitHub  │  │   MITRE  │          │
│  │ (CVEs)   │  │(Exploits)│  │(Techniques)          │
│  └──────────┘  └──────────┘  └──────────┘          │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
│  │  ArXiv   │  │  Censys  │  │   CVE    │          │
│  │(Research)│  │(Internet)│  │(Vulnerabilities)    │
│  └──────────┘  └──────────┘  └──────────┘          │
│                                                      │
│  ┌──────────┐  ┌──────────────────────┐             │
│  │ OpenCTI  │  │  CIRCL Vuln-Lookup    │             │
│  │(Synthetic│  │(CNVD/FSTEC/JVN/CERT-FR)             │
│  └──────────┘  └──────────────────────┘             │
│                                                      │
│  ┌──────────┐                                       │
│  │  EUVD    │                                       │
│  │ (ENISA)  │                                       │
│  └──────────┘                                       │
│                                                      │
└──────────────────────────────────────────────────────┘

                    ┌─────────────┐
                    │ LLM Agents  │
                    │ (7 engines) │
                    │ - Claude    │
                    │ - GPT-4     │
                    │ - Mistral   │
                    │ - etc.      │
                    └─────────────┘
                          ▲
                          │ (tested against threats)
                          │
                    ┌─────┴──────┐
                    │   Scanner  │
                    │  Tests     │
                    │ Agents     │
                    └────────────┘
```

---

## Component Descriptions

### 1. Scrapers (9 sources)

```
PURPOSE: Extract threat data from CTI feeds

Location: scrapers/

Components (active, 9):
├─ cve_scraper.py                          (CVE vulnerabilities, via cve.circl.lu)
├─ github_scraper.py                       (Security advisories)
├─ arxiv_scraper.py                        (Research papers, via export.arxiv.org)
├─ mitre_scraper.py                        (Attack techniques)
├─ censys_scraper.py                       (Internet exposures - synthetic, see Known Limitations)
├─ nvd_scraper.py                          (CVE vulnerabilities)
├─ opencti_scraper.py                      (Structured intel - synthetic, see Known Limitations)
├─ circl_vulnerability_lookup_scraper.py   (CNVD/FSTEC/JVN/CERT-FR, via vulnerability.circl.lu)
└─ euvd_scraper.py                         (EU Vulnerability Database, via ENISA)

Note: scrapers/misp_scraper.py also exists but is not
currently wired into the pipeline (pipeline/process.py
never imports or calls it).

Shared base (scrapers/base_scraper.py, BaseScraper - added Vague 3c):
    __init__(base_url=None)   - self.data, self.error_count, self.base_url
    save_to_json(filename)    - UTF-8 JSON dump; default path per scraper
                                 via DEFAULT_OUTPUT_FILE
    get_stats()               - banner, totals, errors, severity breakdown
    request_with_retry(fn)    - wraps core/retry.py, no separate import needed
                                 (also used directly by testing/agent_scanner.py
                                 for agent.query() calls, not just scrapers)
    _print_extra_stats()      - hook for scraper-specific stats (GitHub stars/
                                 languages, MITRE tactics, Censys exposure types,
                                 CIRCL by-source, ArXiv date range); no-op by default

Deliberately NOT shared (differs legitimately per source - see the
Vague 3c diagnostic): the fetch method itself (name, signature, loop
shape - per-keyword vs per-source vs single bulk call vs synthetic
generation), response parsing (JSON vs XML vs hardcoded), auth
(GitHub token, Censys API key), and per-source severity mapping.

Responsibilities:
- Connect to external APIs
- Fetch latest threat data
- Handle rate limiting
- Parse responses
- Return normalized data
```

### 2. Classifier (9 categories)

Taxonomy revised 2026-08-24 to align with the OWASP Top 10 for LLM Applications (2025 v2.0), replacing the 8-category taxonomy from the defended thesis report. Data-driven: derived from analyzing a ~140-entry sample of what was landing in `other` (see DATA_SOURCES.md), not applied wholesale from the OWASP list — two OWASP categories (System Prompt Leakage, Vector/Embedding Weaknesses) were deliberately **not** added because the corpus showed no real matching content.

```
PURPOSE: Categorize threats into security types

Location: core/classifier.py

Categories (653 threats, after full reclassification):
├─ other                        (62.0%)
├─ prompt_injection             (24.3%)
├─ sensitive_info_disclosure    (4.7%)
├─ excessive_agency             (3.7%)
├─ supply_chain                 (1.7%)
├─ unbounded_consumption        (1.5%)
├─ improper_output_handling     (1.2%)
├─ model_extraction             (0.3%)
├─ data_poisoning               (0.3%)
└─ misinformation               (0.2%)

Plus a separate `ai_relevant` boolean (not a category — computed
independently): true for anything matched above, or for "other" entries
that still mention AI/LLM-specific vocabulary. 362/653 (55.4%) true.
Of the 405 "other" entries, 114 are ai_relevant=true (real AI-adjacent
content, just not a clean fit for the 9 categories) and 291 are
ai_relevant=false (confirmed off-topic - e.g. pre-2000 NVD CVEs pulled
in by a broad keyword search, classic non-AI MITRE ATT&CK techniques).

Algorithm:
1. Build a lowercase text blob from title + description + test_payload
   + detection_keywords
2. Match against keyword patterns for each of the 9 categories
3. Assign the category with the most keyword hits; 0 hits -> "other"
4. Separately, compute ai_relevant: true by construction if a category
   matched, else a secondary keyword pass over AI/LLM-specific terms

Metrics:
- Unit tests:  13/13 passing ✓
- Coverage:    All 653 threats (full reclassification, see
                scripts/maintenance/reclassify_taxonomy_2026_08.py)
- Accuracy:    Keyword-based (no ML)
- Speed:       <100ms per threat

Extensibility:
Add new category:
1. Add keywords to self.keywords dict (core/classifier.py,
   in ImprovedThreatClassifier.__init__)
2. Add unit test (tests/test_classifier.py)
3. Run: python -m pytest tests/test_classifier.py
```

### 3. Pipeline (ETL)

```
PURPOSE: Collect, process, store threat data

Location: pipeline/process.py

Flow:
Extract (9 sources)
    ↓
Transform (normalize, classify, deduplicate)
    ↓
Load (SQLite storage)
    ↓
Validate (11 unit tests)

Operations:
1. Extract:
   - Call each of 7 scrapers
   - Collect threats
   - Handle errors: each scraper call is wrapped in
     try/except; on failure the error is logged and the
     source moves on with a count of 0 (no retry)

2. Transform:
   - Normalize fields
   - Classify into 9 categories
   - Calculate severity
   - Generate detection keywords

3. Load:
   - Insert into threats table
   - Update existing (skip duplicates)
   - Maintain history
   - Log results

4. Validate:
   - Check data integrity
   - Verify classifications
   - Count threats
   - Report metrics

Scheduling:
- Daily:    02:00 UTC (automatic via orchestrator)
- Manual:   python pipeline/process.py
- Results:  logs/orchestrator.log + metrics.json
```

### 4. Orchestrator (Automation)

```
PURPOSE: Schedule and automate pipeline execution

Location: orchestrator.py

Technology: schedule (Python library)

Schedule:
┌─────────────────────────────────────┐
│ DAILY PIPELINE (02:00 UTC)          │
├─────────────────────────────────────┤
│ 1. Run ETL pipeline                 │
│ 2. Collect from 9 sources           │
│ 3. Update database                  │
│ 4. Save metrics                     │
│ 5. Log results                      │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│ WEEKLY PIPELINE (Monday 10:00 UTC)  │
├─────────────────────────────────────┤
│ 1. Run daily pipeline (if not done) │
│ 2. Validate all threats             │
│ 3. Deduplicate database             │
│ 4. Generate report                  │
│ 5. Archive old data                 │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│ HOURLY HEALTH CHECK                 │
├─────────────────────────────────────┤
│ 1. Verify database integrity        │
│ 2. Check disk space                 │
│ 3. Validate configuration           │
│ 4. Report issues                    │
└─────────────────────────────────────┘

Commands:
- Start:      python orchestrator.py
- Status:     python orchestrator.py --status
- Run now:    python orchestrator.py --run-daily
- Test:       python orchestrator.py --test
- Stop:       Ctrl+C

Reliability:
- Track record: 2/2 recorded executions succeeded
  (2026-03-28); not yet operated continuously
- Error handling: try/except per scraper, log and skip
  (no retry)
- Logging: Complete audit trail
- Metrics: Persistent storage
```

### 5. Scanner (Agent Testing)

```
PURPOSE: Test AI agents against threats

Location: testing/agent_scanner.py

Workflow:
┌──────────────────────────────────────┐
│ 1. Load 653 threats from database   │
├──────────────────────────────────────┤
│ 2. For each threat:                 │
│    a. Send test payload to agent    │
│    b. Measure response              │
│    c. Detect vulnerability          │
│    d. Record result                 │
├──────────────────────────────────────┤
│ 3. Analyze results                  │
│    a. Count vulnerabilities         │
│    b. Group by type/severity        │
│    c. Calculate scores              │
├──────────────────────────────────────┤
│ 4. Generate report                  │
│    a. JSON export                   │
│    b. CSV export                    │
│    c. Summary statistics            │
└──────────────────────────────────────┘

Usage:
python testing/cli.py --scan-agent mock --output results.json

Agents Supported:
- Mock:        Simulation (99.5% vulns)
- Claude:      Anthropic API
- GPT-4:       OpenAI API
- Mistral:     Ollama local
- Llama:       Ollama local
- HuggingFace: Local model
- Remote HTTP: Any agent reachable over HTTP (POST prompt, read response) -
               see "Agent Registry" below and docs/examples/local_agent_http_wrapper.py
               for wrapping a local script this way

Can be used either as a one-off ("quick type", nothing saved) or via a
registered agent from core/agent_registry.py (see "Agent Registry" below).

Output:
{
  "scan_date": "2026-03-28T14:30:00Z",
  "agent_type": "mistral",
  "total_threats": 653,
  "vulnerabilities_found": 45,
  "vulnerability_score": 20.5%,
  "results_by_type": {...},
  "results_by_severity": {...},
  "top_vulnerabilities": [...]
}
```

### 6. Dashboards (3 interactive UIs)

```
PURPOSE: Visualize threat data and monitor automation

Technology: Streamlit + Plotly

Structure:
├─ main.py                          (Navigation hub)
└─ pages/
   ├─ operations.py                 (Test agents + Monitor)
   ├─ intelligence.py               (Overview + Veille)
   └─ catalog.py                    (Search threats)

Features:
- Real-time updates
- Interactive charts
- Advanced filtering
- Data export (CSV/JSON)
- Mobile responsive

Dashboard 1: Operations
├─ Tab 1: Test Agent
│  ├─ Select agent (7 options)
│  ├─ Real-time progress
│  ├─ Live KPI cards
│  ├─ Vulnerability charts
│  └─ Export results
└─ Tab 2: Monitor Production
   ├─ Agent health status
   ├─ Performance metrics
   ├─ Alert history
   └─ Manual controls

Dashboard 2: Intelligence Veille
├─ Tab 1: Vue d'Ensemble
│  ├─ Threat KPI cards
│  ├─ Orchestrator status
│  ├─ Distribution charts
│  └─ Trend analysis
├─ Tab 2: Menaces Récentes
│  ├─ Threat table (50+)
│  ├─ Advanced filters
│  ├─ Expanded details
│  └─ Export filtered
├─ Tab 3: Orchestrateur
│  ├─ Execution metrics
│  ├─ Schedule info
│  └─ Manual triggers
└─ Tab 4: Logs
   ├─ Real-time log viewer
   ├─ Adjustable lines
   └─ Download full logs

Dashboard 3: Catalog
├─ Advanced search
├─ Type/severity/source filters
├─ Threat details
├─ Export selected
└─ Integration with SIEM tools
```

### 7. REST API (10 endpoints)

```
PURPOSE: Programmatic access to threat data

Technology: FastAPI + Uvicorn

Endpoints:
GET /threats              (List all, filtered)
GET /threats/{id}        (Specific threat)
GET /stats               (Aggregated statistics)
GET /threat-types        (Categories)
GET /sources             (CTI feeds)
POST /monitoring/log-request   (Log event)
GET /monitoring/stats/{agent}  (Agent metrics)
GET /monitoring/alerts/{agent} (Alerts)
GET /health              (API status)
GET /monitoring/health/{agent} (Agent health)

Design:
- Stateless (no sessions)
- RESTful (standard HTTP)
- JSON responses
- Standard error handling
- Pagination support
- Filtering & searching

Documentation:
See API_DOCUMENTATION.md (1400+ lines)
```

### 8. Agent Registry

```
PURPOSE: Persist agent identity/config so "Test Agent" and "Monitor
Production" share one source of truth instead of each keeping their own
list (previously: a free-text name typed per scan, and a hardcoded
Agent-1/2/3 list in the dashboard).

Location: core/agent_registry.py
Storage:  registered_agents table, data/threats.db

Schema:
  id, name (unique), agent_type (mock/claude/openai/mistral/llama/
  huggingface/remote_http, CHECK-constrained), config (JSON, shape
  depends on agent_type), environment (free text), is_active,
  created_at

CRUD:
  register_agent(name, agent_type, config, environment) -> dict
  list_agents(environment=None, active_only=True) -> list[dict]
  get_agent_config(agent_id) -> dict | None
  deactivate_agent(agent_id) -> bool          # soft delete (is_active=0)
  build_wrapper(agent) -> BaseAgentWrapper    # -> get_agent_wrapper(agent_type, **config)

Security:
  config never holds a secret directly - a remote_http agent stores
  auth_env_var (the *name* of an env var), the real token stays in
  config/.env.local and is read at call time by RemoteHTTPAgentWrapper,
  never persisted (see SECURITY.md).

Related:
  Live monitoring activity (logs/alerts) for an agent is persisted
  separately - see "9. Monitoring Persistence" below - and links back
  to this table via agent_id (application-level only, not a SQL FK:
  it's a different database file).
```

### 9. Monitoring Persistence

```
PURPOSE: Shared, cross-process source of truth for agent monitoring
activity, so an agent logging via POST /monitoring/log-request (api/app.py)
is visible from the dashboard's "Monitor Production" tab and vice versa -
previously each process kept its own in-memory AgentMonitor, so the two
never agreed on what had happened.

Location: monitoring/monitoring_store.py
Storage:  monitoring_logs, monitoring_alerts tables, data/monitoring.db
          - a SEPARATE file from data/threats.db's threats table, since
          these tables can contain real production prompt/response text
          (see SECURITY.md - data/threats.db itself isn't purely public
          either, once registered_agents/scan_results are accounted for).

Schema (monitoring_logs):
  id, agent_id (nullable, no cross-file FK - see below), agent_name,
  user_id, session_id, prompt, response, risk_level, alert_triggered,
  detected_threats (JSON), created_at

Schema (monitoring_alerts):
  id, log_id (-> monitoring_logs.id), agent_id, agent_name, user_id,
  session_id, alert_type, severity, message, detected_threats (JSON),
  resolved, created_at

Functions:
  write_log(...) / write_alert(...) -> dict   # called by AgentMonitor.log_request()
  get_logs(agent_name=None, limit=100) -> list[dict]
  get_alerts(agent_name=None, limit=100) -> list[dict]
  get_statistics(agent_name) -> dict

Who calls it:
  monitoring/agent_monitor.py - AgentMonitor.log_request() writes a log
  (and an alert, if threats are detected) on every call; get_statistics()/
  get_logs()/get_alerts() read back through this module rather than from
  any in-memory list, so a freshly-constructed AgentMonitor in any
  process sees the same history as any other.

  dashboard/pages/operations.py's "Monitor Production" tab calls
  monitoring_store directly (no AgentMonitor instance at all - it never
  triggers detection, only reads).

agent_id is a plain INTEGER, not a SQL foreign key: SQLite can't
enforce a FOREIGN KEY across two separate database files. The link to
registered_agents (data/threats.db) is resolved at write time via
core.agent_registry.get_agent_by_name() and is nullable - an agent
doesn't have to be pre-registered to log monitoring activity.
```

---

## Data Flow

### Daily Collection Flow

```
START (Daily at 02:00 UTC)
│
├─→ [Orchestrator] Trigger daily pipeline
│
├─→ [Pipeline] Extract phase
│   ├─→ [NVD Scraper]           → 25 threats
│   ├─→ [GitHub Scraper]        → 0 threats (duplicates)
│   ├─→ [ArXiv Scraper]         → 5 threats
│   ├─→ [MITRE Scraper]         → 0 threats (duplicates)
│   ├─→ [Censys Scraper]        → 2 threats
│   ├─→ [CVE Scraper]           → 1 threat
│   └─→ [OpenCTI Scraper]       → 3 threats
│
├─→ [Pipeline] Transform phase
│   ├─→ Normalize all fields
│   ├─→ Classify (9 categories)
│   ├─→ Calculate severity
│   └─→ Deduplicate (skip 6)
│
├─→ [Pipeline] Load phase
│   ├─→ Insert to SQLite
│   ├─→ Update metadata
│   └─→ Log statistics
│
├─→ [Orchestrator] Save metrics
│   ├─→ execution_time: 8.2 seconds
│   ├─→ threats_collected: 30
│   └─→ total_in_db: 653
│
├─→ [Orchestrator] Log completion
│   └─→ logs/orchestrator.log
│       logs/orchestrator_metrics.json
│
└─→ END (02:00 + 8 seconds)

Track record: 2/2 recorded executions succeeded (2026-03-28)
```

### Agent Scanning Flow

```
START: Scanner invoked
│
├─→ [Scanner] Load database (653 threats)
│
├─→ [Scanner] For each threat (0-653):
│   │
│   ├─→ [Scanner] Prepare test payload
│   │   └─→ threat['test_payload']
│   │
│   ├─→ [Wrapper] Send to agent
│   │   ├─→ Agent.query(payload)
│   │   └─→ Get response
│   │
│   ├─→ [Scanner] Analyze response
│   │   ├─→ Check for vulnerability patterns
│   │   ├─→ Match detection keywords
│   │   └─→ Record result (vulnerable Y/N)
│   │
│   └─→ [Scanner] Update progress bar
│       └─→ Display KPI cards (real-time)
│
├─→ [Scanner] Aggregate results
│   ├─→ Count vulnerabilities
│   ├─→ Group by type (9 categories)
│   ├─→ Group by severity (4 levels)
│   ├─→ Calculate score
│   └─→ Identify top 10
│
├─→ [Scanner] Generate output
│   └─→ JSON file with complete results
│
├─→ [Dashboard] Display results
│   ├─→ Update KPI cards
│   ├─→ Redraw charts
│   ├─→ Show vulnerability breakdown
│   └─→ Enable export buttons
│
└─→ END: Scan complete

Time: 30 sec - 10+ min (depending on agent)
Vulnerabilities: 0-653 (depending on agent resilience)
```

---

## Database Design

### Schema

```sql
CREATE TABLE threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    type TEXT NOT NULL,          -- 9 categories
    severity TEXT NOT NULL,       -- critical/high/medium/low
    source TEXT NOT NULL,         -- 9 CTI sources
    url TEXT,
    test_payload TEXT,
    detection_keywords TEXT,      -- JSON array
    cvss_score REAL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

`threats` also carries 4 nullable translation columns (Vague 3a, `core/translation.py`), added via `ALTER TABLE` migration rather than shown in the `CREATE TABLE` above since they only apply to CNVD/FSTEC/CERT-FR rows:

```sql
ALTER TABLE threats ADD COLUMN source_language TEXT;        -- 'zh'/'ru'/'fr'; NULL for English-native sources
ALTER TABLE threats ADD COLUMN title_translated TEXT;       -- NULL = not attempted for this field (e.g. zh titles) or unavailable/failed
ALTER TABLE threats ADD COLUMN description_translated TEXT; -- same NULL semantics, per-field
ALTER TABLE threats ADD COLUMN translated_at TIMESTAMP;     -- set only if at least one field above was translated
```

See [DATA_SOURCES.md](DATA_SOURCES.md#translation-of-non-english-sources) for the translation feature itself (optional dependency, per-language field policy, quality notes).

```sql
CREATE TABLE registered_agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    agent_type TEXT NOT NULL CHECK (agent_type IN (
        'mock', 'claude', 'openai', 'mistral', 'llama', 'huggingface', 'remote_http'
    )),
    config TEXT NOT NULL DEFAULT '{}',   -- JSON, shape depends on agent_type
    environment TEXT,                     -- free text, e.g. "production"
    is_active BOOLEAN NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

`data/monitoring.db` — a **separate file** from `data/threats.db`, see "9. Monitoring Persistence" above and SECURITY.md:

```sql
CREATE TABLE monitoring_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id INTEGER,                     -- app-level link only, no cross-file FK
    agent_name TEXT NOT NULL,
    user_id TEXT,
    session_id TEXT,
    prompt TEXT NOT NULL,                 -- real prompt text, truncated to 500 chars
    response TEXT NOT NULL,               -- real response text, truncated to 1000 chars
    risk_level TEXT NOT NULL CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    alert_triggered BOOLEAN NOT NULL DEFAULT 0,
    detected_threats TEXT NOT NULL DEFAULT '[]',  -- JSON
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE monitoring_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id INTEGER REFERENCES monitoring_logs(id),
    agent_id INTEGER,
    agent_name TEXT NOT NULL,
    user_id TEXT,
    session_id TEXT,
    alert_type TEXT NOT NULL,             -- distinct threat_types, comma-joined
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    message TEXT NOT NULL,
    detected_threats TEXT NOT NULL DEFAULT '[]',  -- JSON
    resolved BOOLEAN NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### Query Examples

```sql
-- Count by severity
SELECT severity, COUNT(*) FROM threats GROUP BY severity;

-- Find critical prompt injections
SELECT * FROM threats 
WHERE type='prompt_injection' AND severity='critical'
ORDER BY created_at DESC;

-- Threats by source
SELECT source, COUNT(*) FROM threats GROUP BY source;

-- Recent threats (last 24h)
SELECT * FROM threats 
WHERE created_at >= datetime('now', '-1 day')
ORDER BY created_at DESC;
```

---

## Design Patterns

### 1. Strategy Pattern (Agents)

```python
# Problem: Support 8 different agent engines (7 LLM SDKs/local models,
# plus a generic HTTP client for any remote agent)
# Solution: Strategy pattern with single interface

class BaseAgentWrapper(ABC):
    @abstractmethod
    def query(self, prompt: str) -> str:
        pass

class ClaudeAgentWrapper(BaseAgentWrapper):
    def query(self, prompt: str) -> str:
        # Claude-specific implementation

class OpenAIAgentWrapper(BaseAgentWrapper):
    def query(self, prompt: str) -> str:
        # GPT-4 specific implementation

class RemoteHTTPAgentWrapper(BaseAgentWrapper):
    def query(self, prompt: str) -> str:
        # POST {request_field: prompt} to endpoint_url, read response_field back

# Factory pattern for creation
def get_agent_wrapper(agent_type: str, **kwargs) -> BaseAgentWrapper:
    agents = {'claude': ClaudeAgentWrapper, 'openai': OpenAIAgentWrapper,
              'remote_http': RemoteHTTPAgentWrapper, ...}
    return agents[agent_type](**kwargs)
```

**Benefit:** Add new agents by implementing single interface

### 2. Base Class (Scrapers)

```python
# Problem: 9 different CTI source formats, but the real duplication
# (Vague 3c diagnostic) was only in init/persistence/stats bookkeeping -
# not in the fetch/parse logic itself, which differs legitimately per
# source (JSON vs XML, per-keyword vs per-source vs bulk fetch, auth).
# Solution: share only what's actually identical; no forced fetch()/
# parse() abstraction.

class BaseScraper:
    def __init__(self, base_url=None): ...
    def save_to_json(self, filename=None): ...
    def get_stats(self): ...
    def request_with_retry(self, request_fn, **kwargs): ...
    def _print_extra_stats(self): ...  # hook, no-op by default

class NVDScraper(BaseScraper):
    DEFAULT_OUTPUT_FILE = "data/raw_nvd.json"
    def fetch_cves(self, keywords=None, max_results=100):
        # NVD-specific API call + parsing - no shared fetch() exists

class GitHubScraper(BaseScraper):
    DEFAULT_OUTPUT_FILE = "data/raw_github.json"
    def fetch_exploits(self, queries=None, max_per_query=30):
        # GitHub-specific API call + parsing
```

**Benefit:** Removes the real duplication (init/save/stats) without
forcing a one-size-fits-all interface the 9 sources don't share.

### 3. Template Method (Pipeline)

```python
# Problem: ETL pipeline is same for every run
# Solution: Define skeleton, let subclasses override steps

class Pipeline:
    def run(self):
        data = self.extract()
        data = self.transform(data)
        self.load(data)
        self.validate()
    
    @abstractmethod
    def extract(self) -> List[Dict]:
        # Override in subclasses
    
    def transform(self, data: List[Dict]) -> List[Dict]:
        # Common transformation logic
    
    def load(self, data: List[Dict]):
        # Common database logic
```

### 4. Observer Pattern (Monitoring)

```python
# Problem: Need to monitor agent activity
# Solution: Observer pattern with callbacks

class MonitoringObserver(ABC):
    @abstractmethod
    def update(self, event: MonitoringEvent):
        pass

class LoggingObserver(MonitoringObserver):
    def update(self, event: MonitoringEvent):
        # Log the event
        
class AlertingObserver(MonitoringObserver):
    def update(self, event: MonitoringEvent):
        # Send alert if critical

# Scanner notifies observers
scanner = Scanner()
scanner.add_observer(LoggingObserver())
scanner.add_observer(AlertingObserver())
scanner.run()  # Automatically notifies all observers
```

---

## Module Organization

```
Agent_security_framework/
├─ README.md                         (Project overview)
├─ requirements.txt                  (Dependencies)
├─ orchestrator.py                   (Main automation)
│
├─ dashboard/                        (Presentation layer)
│  ├─ main.py                        (Navigation hub)
│  └─ pages/
│     ├─ operations.py
│     ├─ intelligence.py
│     └─ catalog.py
│
├─ testing/                          (Agent testing)
│  ├─ agent_scanner.py              (Nessus-like scanner)
│  ├─ agent_wrappers.py             (8 engines, incl. MockAgentWrapper,
│  │                                  RemoteHTTPAgentWrapper)
│  └─ cli.py                        (CLI interface)
│
├─ core/                             (Business logic)
│  ├─ classifier.py                 (9-category classifier)
│  └─ agent_registry.py             (persistent multi-agent registry)
│
├─ docs/examples/                    (copy-paste templates, not imported by ASIF)
│  └─ local_agent_http_wrapper.py   (expose a local script as remote_http)
│
├─ pipeline/                         (ETL)
│  └─ process.py                    (Extract, transform, load)
│
├─ scrapers/                         (CTI collection)
│  ├─ base_scraper.py               (BaseScraper - shared init/save/stats, Vague 3c)
│  ├─ retry.py                      (request_with_retry, wrapped by BaseScraper)
│  ├─ nvd_scraper.py
│  ├─ github_scraper.py
│  ├─ arxiv_scraper.py
│  ├─ mitre_scraper.py
│  ├─ censys_scraper.py
│  ├─ circl_vulnerability_lookup_scraper.py
│  ├─ euvd_scraper.py
│  ├─ misp_scraper.py               (not wired into the pipeline)
│  └─ cve_scraper.py
│
├─ api/                              (REST API)
│  └─ app.py                        (10 endpoints)
│
├─ monitoring/                       (Agent monitoring)
│  ├─ agent_monitor.py              (Detection logic, writes through to monitoring_store)
│  └─ monitoring_store.py           (Persistence: monitoring_logs/monitoring_alerts)
│
├─ data/                             (Data storage)
│  ├─ threats.db                    (SQLite - 653 threats + registered_agents)
│  └─ monitoring.db                 (SQLite - monitoring_logs/monitoring_alerts,
│                                     kept separate - see SECURITY.md)
│
├─ logs/                             (Audit trail)
│  ├─ orchestrator.log              (Execution logs)
│  ├─ orchestrator_metrics.json     (Performance metrics)
│  └─ weekly_report_*.json          (Reports)
│
├─ config/                           (Configuration)
│  └─ .env.local                    (API keys - git ignored)
│
├─ .env.example                      (Template, at repo root — copy to
│                                     config/.env.local)
│
├─ tests/                            (Unit tests)
│  └─ test_classifier.py            (13/13 passing ✓)
│
└─ (documentation, at repo root, no docs/ folder)
   ├─ README.md
   ├─ ARCHITECTURE.md
   ├─ API_DOCUMENTATION.md
   ├─ INSTALLATION.md
   ├─ USAGE_GUIDE.md
   ├─ SCRAPERS_DOCUMENTATION.md
   └─ ...
```

### Import Dependencies

```
api/app.py
├─ depends on: core/classifier.py
├─ depends on: data/threats.db
└─ depends on: monitoring/agent_monitor.py

orchestrator.py
├─ depends on: pipeline/process.py
├─ depends on: data/threats.db
└─ depends on: logs/orchestrator.log

pipeline/process.py
├─ depends on: scrapers/* (all 9 active; misp_scraper.py exists but isn't wired in)
├─ depends on: core/classifier.py
└─ depends on: data/threats.db

testing/cli.py
├─ depends on: testing/agent_scanner.py
├─ depends on: testing/agent_wrappers.py
└─ depends on: data/threats.db

dashboard/pages/*.py
├─ depends on: data/threats.db
├─ depends on: api/app.py
└─ depends on: logs/orchestrator.log
```

---

## Deployment Architecture

### Development

```
Local Machine
├─ Python 3.11 venv
├─ SQLite in ./data/
├─ Logs in ./logs/
└─ APIs on localhost:8000-8501
```

### Staging

```
Linux Server
├─ Docker container
├─ PostgreSQL database
├─ External storage for logs
└─ APIs behind reverse proxy
```

### Production (Future)

```
Cloud Infrastructure
├─ Kubernetes cluster
├─ Managed database (RDS/Cloud SQL)
├─ Load balancing
├─ HTTPS/TLS
├─ Authentication (OAuth)
├─ Rate limiting
├─ Monitoring (Prometheus/Grafana)
└─ Logging (ELK stack)
```

---

## Security Architecture

### Current (v2.0)

```
┌─────────────────────────────────────┐
│   PUBLIC API (No auth needed)       │
├─────────────────────────────────────┤
│ ✓ Open CTI data (threat intelligence)
│ ✓ Public documentation
│ ✗ No authentication required
│ ✗ No rate limiting
│ ✗ No encryption (HTTP only)
└─────────────────────────────────────┘

Best for: Development, internal use only
```

### Future (v2.1+)

```
┌─────────────────────────────────────┐
│   SECURED API (Auth required)       │
├─────────────────────────────────────┤
│ ✓ API key authentication
│ ✓ Rate limiting per IP/API key
│ ✓ HTTPS/TLS encryption
│ ✓ RBAC (role-based access control)
│ ✓ Audit logging
│ ✓ Data encryption at rest
│ ✓ OAuth 2.0 support
│ ✓ IP whitelisting
└─────────────────────────────────────┘

Best for: Production, multi-tenant
```

---

## Performance Considerations

### Optimization Strategies

```
1. DATABASE (see scripts/maintenance/add_query_indexes.py):
   - Indexes on threats(threat_type), threats(source), threats(severity),
     threats(created_at), registered_agents(created_at) - added from an
     audit of the query patterns actually used across the codebase
     (grepped pipeline/, api/, dashboard/, core/, monitoring/,
     scripts/maintenance/), not preventively. At the current scale
     (~650 threats) the effect isn't measurable - this is preparation
     for growth, not a fix for an observed slowdown.
   - threats.threat_id/id, registered_agents.name, and api_keys.key_hash/
     label are already indexed for free via PRIMARY KEY/UNIQUE
     constraints. monitoring_logs.agent_name and
     monitoring_alerts.agent_name are indexed too (the real hot filter
     on those tables).
   - Deliberately NOT indexed: scan_results.agent_id/status and
     monitoring_alerts.log_id used to have indexes, but the same audit
     found no query anywhere actually filters on them (every access
     goes through the primary key `id`) - pure write overhead for zero
     read benefit, so those 3 were dropped rather than kept "just in
     case". Also not indexed: threats.ai_relevant and
     registered_agents.is_active - both near-boolean, poor-selectivity
     columns where an index rarely helps SQLite's planner.
   - WAL journal mode is enabled on all three database files (see
     scripts/maintenance/enable_wal_mode.py) - readers (dashboards, API)
     don't block behind a concurrent writer (pipeline, orchestrator).

2. CACHING:
   - The API itself caches nothing - every request re-queries the
     database directly (see API_DOCUMENTATION.md's Rate Limiting
     section: this is a single-process, low-traffic service, not one
     bottlenecked on DB reads).
   - Dashboard only, via @st.cache_data (previously only the DB
     connection object was cached, via @st.cache_resource - no query
     result was):
     - dashboard/main.py get_platform_stats(): 30s TTL - deliberately
       the shortest in the app. This exact function used to display
       hardcoded metrics (fixed earlier in the project's history), so a
       long or unbounded TTL here specifically risked recreating a
       "looks live but isn't" symptom.
     - dashboard/pages/intelligence.py and dashboard/pages/catalog.py:
       300s (5 min) TTL on their stats/filter/listing queries - all
       driven by data that only changes on an orchestrator run
       (daily/weekly).
     - dashboard/pages/operations.py: 30s TTL on the per-agent
       monitoring stats/alerts loop (the one view meant to look close
       to live production monitoring), 300s on its threat-count query,
       and 60s on the registered-agent list - but that list is also
       explicitly invalidated (.clear()) the instant this page
       registers or deactivates an agent itself, so its own actions
       show up immediately rather than waiting out the TTL.

3. PAGINATION:
   - Limit default: 100 items
   - Offset-based pagination
   - Efficient SQL queries

4. PARALLELIZATION:
   - Multi-threaded scraping
   - Async/await for I/O
   - Worker pool for classification

5. COMPRESSION:
   - Gzip responses
   - Minify JSON
   - Compress logs
```

### Benchmarks

```
Operation              Time        Notes
─────────────────────────────────────
Load 653 threats      ~100ms      From SQLite
Classify 1 threat     <100ms      Keyword matching
Scan all threats      30s - 10m   Depends on agent
Generate stats        ~50ms       Aggregation query
API request           <10ms       Avg response time
```

---

## Extension Points

### Add New CTI Source

```python
# 1. Create new scraper
class NewSourceScraper(Scraper):
    def scrape(self) -> List[Dict]:
        # Fetch data
    
    def parse(self, data: Dict) -> Threat:
        # Convert to Threat

# 2. Register in pipeline
from pipeline.process import Pipeline
pipeline.add_scraper(NewSourceScraper())

# 3. Test
python pipeline/process.py
```

### Add New Threat Category

```python
# 1. Add keywords to self.keywords dict
#    (core/classifier.py, ImprovedThreatClassifier.__init__)
self.keywords = {
    'prompt_injection': [...],
    ...
    'new_category': ['keyword1', 'keyword2'],
}

# 2. Add unit test (tests/test_classifier.py)
def test_new_category():
    classifier = ImprovedThreatClassifier()
    threat = classifier.classify('keyword1 description')
    assert threat['type'] == 'new_category'

# 3. Test
python -m pytest tests/test_classifier.py::test_new_category
```

### Add New Dashboard

```python
# 1. Create new page (dashboard/pages/4_custom.py)
import streamlit as st

st.set_page_config(page_title="Custom", page_icon="🔧")
st.title("Custom Dashboard")

# Your code here

# 2. Add navigation link in main.py
# st.page_link("pages/4_custom.py", label="Custom", icon="🔧")

# 3. Test
streamlit run dashboard/main.py
```

### Add New Agent Type

Most new agents don't need a new wrapper class at all: if it can be
reached over HTTP (even a local script wrapped per
`docs/examples/local_agent_http_wrapper.py`), register it as
`remote_http` via `core/agent_registry.py` instead. Write a new wrapper
only for a genuinely different transport/SDK:

```python
# 1. Create wrapper (testing/agent_wrappers.py)
class MyAgentWrapper(BaseAgentWrapper):
    def __init__(self, config=None):
        self.client = MyAgentClient()
    
    def query(self, prompt: str) -> str:
        return self.client.ask(prompt)

# 2. Register in factory
def get_agent_wrapper(type, **kwargs):
    if type == 'myagent':
        return MyAgentWrapper()
    # ... etc

# 3. Test
python testing/cli.py --scan-agent myagent
```

---

## References

UML diagrams (component, deployment, class, sequence) are not available yet.

---

## Next Steps

1. **Understand the layers** - Review system architecture
2. **Study components** - Deep dive into each module
3. **Learn patterns** - Study design patterns used
4. **Extend framework** - Use extension points
5. **Deploy** - See deployment guide

---

<div align="center">

**Architecture Questions?** [Open an Issue](https://github.com/Mavchris/Agent_Security_Framework/issues) | **Design Discussion?** [Start Discussion](https://github.com/Mavchris/Agent_Security_Framework/discussions)

</div>

---

**Last Updated:** March 28, 2026 | **Version:** 2.0 | **Status:** Production Ready
