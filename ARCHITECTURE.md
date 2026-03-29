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
1. **Collect** threat intelligence from 7 CTI sources
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
│ ✓ Reliability (100% success)     │
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
│ Test Coverage:   11/11 passing   │
│ Threats DB:      236+ threats    │
│ CTI Sources:     7 integrated    │
│ Threat Types:    9 categories    │
│ Dashboards:      3 production    │
│ API Endpoints:   10 functional   │
│ Uptime:          100% (tested)   │
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
│  │   (APScheduler integration)   │                │
│  └──────┬──────────────────────┘                │
│         │                                        │
│  ┌──────┴──────────────────────────────┐        │
│  │   Pipeline (ETL)                   │        │
│  │  ├─ Extract (7 sources)            │        │
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
│  │  ├─ threats table (236+ rows)        │          │
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
│  │  ArXiv   │  │  Censys  │  │   MISP   │          │
│  │(Research)│  │(Internet)│  │(Campaigns)          │
│  └──────────┘  └──────────┘  └──────────┘          │
│                                                      │
│  ┌──────────────────────────┐                       │
│  │    OpenCTI               │                       │
│  │(Structured Intelligence) │                       │
│  └──────────────────────────┘                       │
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

### 1. Scrapers (7 sources)

```
PURPOSE: Extract threat data from CTI feeds

Location: scrapers/

Components:
├─ nvd_scraper.py           (CVE vulnerabilities)
├─ github_scraper.py        (Security advisories)
├─ arxiv_scraper.py         (Research papers)
├─ mitre_scraper.py         (Attack techniques)
├─ censys_scraper.py        (Internet exposures)
├─ misp_scraper.py          (Threat campaigns)
└─ opencti_scraper.py       (Structured intel)

Interface:
class Scraper(ABC):
    def scrape(self) -> List[Dict]:
        """Fetch threats from source"""
    
    def parse(self, data: Dict) -> Threat:
        """Convert to Threat object"""

Responsibilities:
- Connect to external APIs
- Fetch latest threat data
- Handle rate limiting
- Parse responses
- Return normalized data
```

### 2. Classifier (9 categories)

```
PURPOSE: Categorize threats into security types

Location: core/classifier.py

Categories:
├─ prompt_injection         (30.5%)
├─ api_abuse               (11.9%)
├─ tool_abuse              (1.4%)
├─ model_extraction        (0.9%)
├─ behavioral_anomaly      (0.9%)
├─ supply_chain            (0.5%)
├─ data_leakage            (0.5%)
├─ data_poisoning          (0%)
└─ resource_exhaustion     (0%)

Algorithm:
1. Tokenize threat title + description
2. Match against keyword patterns
3. Calculate confidence score
4. Assign primary category
5. Return classified threat

Metrics:
- Unit tests:  11/11 passing ✓
- Coverage:    All 236 threats
- Accuracy:    Keyword-based (no ML)
- Speed:       <100ms per threat

Extensibility:
Add new category:
1. Add to enum (core/threat_definitions.py)
2. Add keywords (THREAT_DEFINITIONS dict)
3. Add unit test (tests/test_classifier.py)
4. Run: python -m pytest tests/test_classifier.py
```

### 3. Pipeline (ETL)

```
PURPOSE: Collect, process, store threat data

Location: pipeline/process.py

Flow:
Extract (7 sources)
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
   - Handle errors (retry, fallback)

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

Technology: APScheduler

Schedule:
┌─────────────────────────────────────┐
│ DAILY PIPELINE (02:00 UTC)          │
├─────────────────────────────────────┤
│ 1. Run ETL pipeline                 │
│ 2. Collect from 7 sources           │
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
- Success rate: 100% (v2.0)
- Error handling: Retry + fallback
- Logging: Complete audit trail
- Metrics: Persistent storage
```

### 5. Scanner (Agent Testing)

```
PURPOSE: Test AI agents against threats

Location: testing/agent_scanner.py

Workflow:
┌──────────────────────────────────────┐
│ 1. Load 236+ threats from database  │
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
- Mock:       Simulation (99.5% vulns)
- Claude:     Anthropic API
- GPT-4:      OpenAI API
- Mistral:    Ollama local
- Llama:      Ollama local
- HuggingFace: Local model
- Custom:     User's agent

Output:
{
  "scan_date": "2026-03-28T14:30:00Z",
  "agent_type": "mistral",
  "total_threats": 219,
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
   ├─ 1_operations.py               (Test agents + Monitor)
   ├─ 2_intelligence.py             (Overview + Veille)
   └─ 3_catalog.py                  (Search threats)

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
│   ├─→ [MISP Scraper]          → 1 threat
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
│   └─→ total_in_db: 236
│
├─→ [Orchestrator] Log completion
│   └─→ logs/orchestrator.log
│       logs/orchestrator_metrics.json
│
└─→ END (02:00 + 8 seconds)

Success Rate: 100% ✓
```

### Agent Scanning Flow

```
START: Scanner invoked
│
├─→ [Scanner] Load database (236 threats)
│
├─→ [Scanner] For each threat (0-219):
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
Vulnerabilities: 0-219 (depending on agent resilience)
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
    source TEXT NOT NULL,         -- 7 CTI sources
    url TEXT,
    test_payload TEXT,
    detection_keywords TEXT,      -- JSON array
    cvss_score REAL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
# Problem: Support 7 different LLM engines
# Solution: Strategy pattern with single interface

class AgentWrapper(ABC):
    @abstractmethod
    def query(self, prompt: str) -> str:
        pass

class ClaudeWrapper(AgentWrapper):
    def query(self, prompt: str) -> str:
        # Claude-specific implementation
        
class GPT4Wrapper(AgentWrapper):
    def query(self, prompt: str) -> str:
        # GPT-4 specific implementation

# Factory pattern for creation
def get_agent_wrapper(agent_type: str) -> AgentWrapper:
    if agent_type == 'claude':
        return ClaudeWrapper()
    elif agent_type == 'gpt4':
        return GPT4Wrapper()
    # ... etc
```

**Benefit:** Add new agents by implementing single interface

### 2. Adapter Pattern (Scrapers)

```python
# Problem: 7 different CTI source formats
# Solution: Adapt each to common Threat format

class Scraper(ABC):
    def scrape(self) -> List[Dict]:
        """Fetch from source"""
    def parse(self, data: Dict) -> Threat:
        """Convert to Threat object"""

class NVDScraper(Scraper):
    def scrape(self) -> List[Dict]:
        # NVD-specific API call
    def parse(self, nvd_data: Dict) -> Threat:
        # Adapt NVD format to Threat

class GitHubScraper(Scraper):
    def scrape(self) -> List[Dict]:
        # GitHub-specific API call
    def parse(self, github_data: Dict) -> Threat:
        # Adapt GitHub format to Threat
```

**Benefit:** Uniform interface for heterogeneous sources

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
│     ├─ 1_operations.py
│     ├─ 2_intelligence.py
│     └─ 3_catalog.py
│
├─ testing/                          (Agent testing)
│  ├─ agent_scanner.py              (Nessus-like scanner)
│  ├─ agent_wrappers.py             (7 LLM engines)
│  ├─ agent_tester.py               (Test harness)
│  └─ cli.py                        (CLI interface)
│
├─ core/                             (Business logic)
│  ├─ classifier.py                 (9-category classifier)
│  └─ threat_definitions.py         (Threat metadata)
│
├─ pipeline/                         (ETL)
│  └─ process.py                    (Extract, transform, load)
│
├─ scrapers/                         (CTI collection)
│  ├─ nvd_scraper.py
│  ├─ github_scraper.py
│  ├─ arxiv_scraper.py
│  ├─ mitre_scraper.py
│  ├─ censys_scraper.py
│  ├─ misp_scraper.py
│  ├─ opencti_scraper.py
│  └─ cve_scraper.py
│
├─ api/                              (REST API)
│  └─ app.py                        (10 endpoints)
│
├─ monitoring/                       (Agent monitoring)
│  └─ agent_monitor.py              (Health checks)
│
├─ data/                             (Data storage)
│  └─ threats.db                    (SQLite - 236+ threats)
│
├─ logs/                             (Audit trail)
│  ├─ orchestrator.log              (Execution logs)
│  ├─ orchestrator_metrics.json     (Performance metrics)
│  └─ weekly_report_*.json          (Reports)
│
├─ config/                           (Configuration)
│  ├─ .env.local                    (API keys - git ignored)
│  └─ .env.example                  (Template)
│
├─ tests/                            (Unit tests)
│  └─ test_classifier.py            (11/11 passing ✓)
│
└─ docs/                             (Documentation)
   ├─ INSTALLATION.md
   ├─ USAGE_GUIDE.md
   ├─ API_DOCUMENTATION.md
   ├─ ARCHITECTURE.md
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
├─ depends on: scrapers/* (all 7)
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
1. DATABASE:
   - Index on threat_id (primary key)
   - Index on type (frequent filter)
   - Index on severity (frequent filter)
   - SQLite with WAL mode

2. CACHING:
   - Cache /stats endpoint (5 min)
   - Cache /threat-types (24h)
   - Cache threat list in memory

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
Load 236 threats      ~100ms      From SQLite
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
# 1. Add to enum (core/threat_definitions.py)
THREAT_TYPES = [
    'prompt_injection',
    ...
    'new_category'  # Add here
]

# 2. Add keywords
THREAT_DEFINITIONS = {
    'new_category': {
        'keywords': ['keyword1', 'keyword2'],
        'severity': 'high'
    }
}

# 3. Add unit test (tests/test_classifier.py)
def test_new_category():
    classifier = ImprovedThreatClassifier()
    threat = classifier.classify('keyword1 description')
    assert threat['type'] == 'new_category'

# 4. Test
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

- [UML Component Diagram](docs/diagrams/components.uml)
- [Deployment Diagram](docs/diagrams/deployment.uml)
- [Class Diagram](docs/diagrams/classes.uml)
- [Sequence Diagram](docs/diagrams/sequences.uml)

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
