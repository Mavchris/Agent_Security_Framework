# Agent Security Intelligence Framework

[![GitHub](https://img.shields.io/badge/GitHub-Mavchris/Agent_Security_Framework-blue?logo=github)](https://github.com/Mavchris/Agent_Security_Framework)
[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python)](https://www.python.org)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)]()

> **Automated threat intelligence & vulnerability assessment framework for AI agents**

A comprehensive security framework for testing, monitoring, and validating AI agents against real-world threats. Collects threat intelligence from 9 CTI sources, classifies threats into 9 categories, and provides automated vulnerability scanning with production-grade dashboards. See [Known Limitations](#known-limitations) for an honest read on what's proven vs. designed-but-not-yet-exercised.

## 🎯 Features

### 🔍 Threat Intelligence
- **9 CTI Sources**: CVE, NVD, MITRE ATT&CK, GitHub Security, ArXiv, Censys, OpenCTI, CIRCL Vulnerability-Lookup (CNVD/FSTEC/JVN/CERT-FR), EUVD (ENISA) — see [Known Limitations](#known-limitations), 2 of the 9 still return synthetic placeholder data
- **653 Threats Collected** (live count — see `/stats` or the Catalog dashboard): real-world vulnerabilities and attack vectors
- **9-Category Classification** (OWASP LLM Top 10 2025 v2.0 aligned, revised 2026-08-24): Prompt injection, sensitive info disclosure, supply chain, data poisoning, improper output handling, excessive agency, misinformation, unbounded consumption, model extraction (+ an `other` fallback, and a separate `ai_relevant` flag — see [Known Limitations](#known-limitations))
- **Scheduled Collection**: designed to run daily (02:00 UTC) + weekly maintenance (Monday 10:00 UTC) via the `schedule` library — see [Known Limitations](#known-limitations) for actual run history

### 🧪 Agent Testing
- **Multi-Agent Support**: Mock, Claude, GPT-4, Llama, Mistral, HuggingFace, Custom
- **Nessus-like Scanner**: Comprehensive vulnerability assessment
- **Real-time Results**: JSON/CSV export with detailed breakdowns
- **Confidence Scoring**: Evidence-based vulnerability detection

### 📊 Dashboards
- **Operations Dashboard**: Real-time agent testing & production monitoring
- **Intelligence Veille Dashboard**: Threat overview, menaces récentes, orchestrator status, logs
- **Catalog Dashboard**: Advanced search & filtering across the 653-threat database

### ⚙️ Automation
- **Task Scheduling**: the `schedule` library (daily/weekly/hourly jobs) — see [Known Limitations](#known-limitations)
- **Orchestrator System**: pipeline automation with per-source error handling (logged and skipped; no automatic retry yet)
- **Monitoring & Logging**: Full audit trail, metrics, and health checks
- **2/2 Recorded Runs Succeeded** (2026-03-28) — not yet operated continuously, see [Known Limitations](#known-limitations)

### 🔐 Security
- **Open-Source**: Fully transparent, reproducible research (AGPL-3.0)
- **Local Processing**: Control over all data (no cloud dependencies)
- **SQLite Database**: 653 threats with rich metadata
- **Extensible Architecture**: Modular design for custom integrations

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Windows/macOS/Linux
- 4GB RAM minimum (8GB recommended)
- Internet connection (for CTI feeds)

### Installation (5 minutes)

```bash
# 1. Clone repository
git clone https://github.com/Mavchris/Agent_Security_Framework.git
cd Agent_security_framework

# 2. Create virtual environment
python -m venv .venv

# Windows PowerShell
.venv\Scripts\Activate.ps1
# Or Git Bash
source .venv/Scripts/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API keys (optional, for some sources)
cp .env.example config/.env.local
# Edit config/.env.local with your Censys API credentials
```

### Run Dashboard (2 minutes)

```bash
# Launch main navigation hub
streamlit run dashboard/main.py

# Then select from:
# - Operations: Test agents & monitor production
# - Intelligence: Threat overview & veille automation
# - Catalog: Search 653 threats

# Opens at: http://localhost:8501
```

### Run CLI Scanner (5-10 minutes)

```bash
# Scan MockAgent (fast, for testing)
python testing/cli.py --scan-agent mock --verbose

# Scan custom agent
python testing/cli.py --scan-agent mistral --output audit.json

# Export results
# → audit.json created with vulnerability breakdown
```

### Start Orchestrator (Continuous)

```bash
# Runs pipeline automatically
python orchestrator.py

# Scheduled:
# - Daily: 02:00 UTC (collect threats)
# - Weekly: Monday 10:00 UTC (validate, deduplicate, report)
# - Hourly: Health checks

# View status anytime
python orchestrator.py --status
```

---

## 📚 Documentation

All documentation files live at the repository root, alongside this README (there is no `docs/` folder).

| Document | Purpose |
|----------|---------|
| [INSTALLATION.md](INSTALLATION.md) | Detailed setup guide |
| [USAGE_GUIDE.md](USAGE_GUIDE.md) | How to use dashboards & CLI |
| [API_DOCUMENTATION.md](API_DOCUMENTATION.md) | REST API reference |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System design |
| [SCRAPERS_DOCUMENTATION.md](SCRAPERS_DOCUMENTATION.md) | CTI scrapers documentation |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Production deployment guide |
| [DATA_SOURCES.md](DATA_SOURCES.md) | CTI sources documentation |
| [SECURITY.md](SECURITY.md) | Security practices & roadmap |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |
| [ROADMAP.md](ROADMAP.md) | Near-term priorities |
| [ACADEMIC.md](ACADEMIC.md) | Academic/thesis context |

---

## 🏗️ Architecture

### System Overview

```
┌─────────────────────────────────────────────────────┐
│                  DASHBOARDS (Streamlit)             │
│  ├─ Operations (Test Agents + Monitor Production)  │
│  ├─ Intelligence Veille (Overview + Logs)          │
│  └─ Catalog (Search 653 Threats)                   │
└─────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────┐
│                 API REST (FastAPI)                  │
│  ├─ /threats (threat database)                      │
│  ├─ /stats (aggregated statistics)                  │
│  ├─ /monitoring (agent health)                      │
│  └─ /scan (vulnerability scanning)                  │
└─────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────┐
│              CORE SERVICES (Python)                 │
│  ├─ Scanner: Threat testing engine                  │
│  ├─ Classifier: 9-category threat classifier       │
│  ├─ Wrappers: 7 agent engines support              │
│  ├─ Orchestrator: Automated pipeline (`schedule`)  │
│  └─ Monitor: Real-time threat detection            │
└─────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────┐
│              DATA PIPELINE (ETL)                    │
│  ├─ Extract: 9 CTI sources (CVE, GitHub, etc.)     │
│  ├─ Transform: classify, dedup on insert (UNIQUE)  │
│  └─ Load: SQLite database (653 threats)            │
└─────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────┐
│              DATABASE & STORAGE                     │
│  ├─ data/threats.db (SQLite, 653 threats)          │
│  ├─ logs/orchestrator.log (audit trail)            │
│  ├─ logs/orchestrator_metrics.json (metrics)       │
│  └─ data/*.json (raw CTI feeds)                    │
└─────────────────────────────────────────────────────┘
```

### Key Components

| Component | Purpose | Status |
|-----------|---------|--------|
| **Scanner** | Nessus-like vulnerability testing | ✅ Complete |
| **Classifier** | 9-category threat classification | ✅ Complete (13/13 tests) |
| **Orchestrator** | Automated pipeline scheduling | ⚠️ Implemented; 2 recorded runs (2026-03-28) |
| **Dashboards** | Real-time visualization | ✅ 3 production dashboards |
| **API** | REST interface | ✅ 10+ endpoints |
| **Multi-Agent** | 7 LLM engine support | ✅ Complete |
| **Monitoring** | Health & alerts (basic) | ⚠️ Partial (alerts coming soon) |
| **Authentication** | User access control | ❌ Planned for v2.0 |

---

## 📊 Results & Metrics

### Data Collection
```
Total Threats Collected:    653 (live count, 2026-08-24 — check /stats for current)
Sources (CTI):              9 wired (7 confirmed real, 2 still synthetic - see below)
├─ GitHub Security:         151
├─ ArXiv (Research):        103
├─ NVD (NIST):              100
├─ EUVD (ENISA):            86
├─ MITRE ATT&CK:            51
├─ JVN (Japan, via CIRCL):  25
├─ FSTEC/BDU (Russia):      25
├─ Censys:                  25 (synthetic - see Known Limitations)
├─ CNVD (China, via CIRCL): 25
├─ CERT-FR (France):        25
├─ CVE (via CIRCL cve-search): 22
└─ OpenCTI:                 15 (synthetic - see Known Limitations)

Data Quality:               Dedup on insert (SQLite UNIQUE constraint on threat_id,
                             exact-match only - see Known Limitations for the
                             cross-source duplicate gap)
Last Update:                Scheduled daily (02:00 UTC) — see Known Limitations for real run history
```

### Classification Results

Taxonomy revised 2026-08-24 (post-thesis-defense iteration) to align with the OWASP Top 10 for LLM Applications (2025 v2.0) — see [Known Limitations](#known-limitations) for why, and DATA_SOURCES.md for the full data-driven methodology.

```
Total Classified:           653 threats
Categories:                 9 (+ "other" fallback when no keyword matches)

Distribution:
├─ other:                        405 (62.0%)
├─ prompt_injection:             159 (24.3%)
├─ sensitive_info_disclosure:     31 (4.7%)
├─ excessive_agency:              24 (3.7%)
├─ supply_chain:                  11 (1.7%)
├─ unbounded_consumption:         10 (1.5%)
├─ improper_output_handling:       8 (1.2%)
├─ model_extraction:               2 (0.3%)
├─ data_poisoning:                 2 (0.3%)
└─ misinformation:                 1 (0.2%)

ai_relevant field:           362/653 (55.4%) true, 291/653 (44.6%) false
  - Of the 405 "other" entries: 114 are ai_relevant=true (AI-adjacent
    content that doesn't fit one of the 9 categories cleanly - e.g. a
    vLLM access-control CVE, or a GitHub repo mentioning ChatGPT) and
    291 are ai_relevant=false (confirmed off-topic - mostly pre-2000
    generic NVD CVEs, classic MITRE ATT&CK techniques, and JVN/FSTEC/
    CNVD vendor bugs with no AI connection at all).

Classification Tests:       13/13 passing ✅ (tests/test_classifier.py)
Confidence Scores:          Not currently computed/stored per threat
```

`ai_relevant` is stored per threat but not yet surfaced anywhere in the dashboards — the intended use is a Catalog/Intelligence filter to separate genuine off-topic noise (broad-coverage sources like NVD/MITRE ATT&CK/JVN returning everything they have) from AI-relevant content, without having to trust the 9-category classification alone. UI wiring is future work, not done in this pass.

### Scanner Performance
```
MockAgent Test:
├─ Threats Tested:          219
├─ Vulnerabilities Found:   218
├─ Vulnerability Score:     99.5%
├─ Execution Time:          ~1 minute
└─ Type:                    Simulation (proof of concept)

Mistral Test (Real LLM):
├─ Threats Tested:          219
├─ Vulnerabilities Found:   ~35-50 (15-25% estimated)
├─ Execution Time:          ~10 minutes
└─ Type:                    Empirical validation

Framework validates scanner works with real agents ✅
```

### Orchestration Reliability
```
Pipeline Executions:        2 recorded (both 2026-03-28); none since
Success Rate:               2/2 (small, non-continuous sample — not "battle-tested")
Average Execution Time:     ~7 seconds (both runs collected 0 new threats)
Error Handling:             Try/except per source — errors are logged and
                             skipped, no automatic retry yet
Monitoring:                 logs/orchestrator_metrics.json + logs/orchestrator.log
Health Checks:              Hourly (while the scheduler process is running)
```

---

## 🛠️ Technology Stack

| Layer | Technology |
|-------|-----------|
| **Dashboard** | Streamlit, Plotly |
| **API** | FastAPI, Uvicorn |
| **Automation** | `schedule` (Python task scheduling library) |
| **Database** | SQLite3 |
| **Language** | Python 3.11 |
| **Agent Support** | Anthropic, OpenAI, Ollama, HuggingFace |
| **Data** | Pandas, JSON |
| **Logging** | Python logging |

### Dependencies
See [requirements.txt](requirements.txt) for complete list.

Key packages:
- `streamlit` - Dashboard UI
- `fastapi` - REST API
- `schedule` - Task scheduling (not currently pinned in requirements.txt — install separately: `pip install schedule`)
- `requests` - HTTP requests
- `beautifulsoup4` - Web scraping
- `pandas` - Data processing
- `plotly` - Interactive charts
- `pydantic` - Data validation

---

## 📁 Project Structure

```
Agent_security_framework/
├─ README.md                    (this file)
├─ requirements.txt             (dependencies)
├─ orchestrator.py              (main automation)
│
├─ dashboard/                   (Streamlit dashboards)
│  ├─ main.py                   (navigation hub)
│  ├─ utils/style.py            (shared theming: icons, KPI cards, Plotly theme)
│  └─ pages/
│     ├─ operations.py          (test agents + monitor)
│     ├─ intelligence.py        (overview + veille)
│     └─ catalog.py             (threat database)
│
├─ testing/                     (agent testing)
│  ├─ agent_scanner.py          (vulnerability scanner)
│  ├─ agent_wrappers.py         (7 LLM engines)
│  ├─ agent_tester.py           (test harness)
│  └─ cli.py                    (command-line interface)
│
├─ core/                        (core services)
│  └─ classifier.py             (threat classifier - 9 categories; keyword
│                                 lists live in the `self.keywords` dict)
│
├─ pipeline/                    (ETL pipeline)
│  └─ process.py                (extract, transform, load)
│
├─ scrapers/                    (CTI data collection)
│  ├─ cve_scraper.py
│  ├─ nvd_scraper.py
│  ├─ github_scraper.py
│  ├─ arxiv_scraper.py
│  ├─ mitre_scraper.py
│  ├─ censys_scraper.py
│  ├─ opencti_scraper.py
│  └─ misp_scraper.py           (exists, not called by pipeline/process.py yet)
│
├─ api/                         (REST API)
│  └─ app.py                    (FastAPI routes)
│
├─ data/                        (databases & storage)
│  ├─ threats.db                (SQLite - 653 threats)
│  └─ raw_*.json                (scraped data)
│
├─ logs/                        (logs & metrics)
│  ├─ orchestrator.log          (audit trail)
│  ├─ orchestrator_metrics.json (performance metrics)
│  └─ weekly_report_*.json      (weekly reports)
│
├─ config/                      (configuration)
│  └─ .env.local                (API keys - git ignored)
│
├─ .env.example                 (API key template, at repo root — copy to
│                                 config/.env.local)
│
├─ tests/                       (unit tests)
│  ├─ test_classifier.py        (13/13 passing ✅)
│  └─ test_*.py
│
└─ *.md                         (all documentation, at repo root next to
                                  README.md — no separate docs/ folder)
```

---

<a name="status-roadmap"></a>
## 🚦 Status & Roadmap

### Current Status: v2.0 - Production Ready (65/100)

✅ **Completed (Session 2)**
- Orchestrator with daily/weekly/hourly scheduling (via the `schedule` library)
- Intelligence Veille dashboard (merged overview + monitoring)
- 2/2 recorded orchestrator runs succeeded (2026-03-28)
- Complete multi-agent support (7 engines)
- 653 threats from 9 wired CTI sources (7 confirmed making real network calls)
- 9-category threat classifier + `other` fallback (13/13 tests passing)
- 3 production dashboards

<a name="known-limitations"></a>
### ⚠️ Known Limitations (as of 2026-08-24)

Documentation-vs-code audit findings, listed plainly rather than left implicit:

- **CTI sources**: 9 scrapers are wired into `pipeline/process.py` (CVE via `cve.circl.lu`, GitHub, ArXiv, MITRE ATT&CK, NVD, OpenCTI, Censys, plus CIRCL Vulnerability-Lookup and EUVD). Of these, **Censys and OpenCTI still return synthetic/hardcoded placeholder data** rather than calling their real APIs — Censys because the stored credentials return `401 Unauthorized` when tested against the real endpoint, OpenCTI because it requires a hosted/authenticated instance rather than a simple public API. `scrapers/misp_scraper.py` exists but isn't called by the pipeline at all.
- **Cross-source deduplication**: only exact-match on `threat_id`, via a SQLite `UNIQUE` constraint. Each scraper builds its own ID format (`NVD-CVE-2026-4182` vs `CVE-2026-4182` vs `CNVD-2026-32003` can all reference the *same* CVE), so the same vulnerability reported by multiple sources is stored as separate rows rather than merged. Confirmed, not yet fixed — needs a design decision on a canonical dedup key.
- **Retry logic**: a shared `request_with_retry` helper (`scrapers/retry.py`, exponential backoff, 3 attempts) exists and is used by the CIRCL and EUVD scrapers. The other 7 scrapers still use a plain try/except that logs and skips on failure — not yet retrofitted.
- **SQLite mode**: default journal mode; WAL is not enabled.
- **Task scheduling**: implemented with the `schedule` library, not APScheduler.
- **Automation track record**: the orchestrator has now completed a real run collecting genuine new data (2026-08-24: +297 threats, all 9 sources succeeded, 0 crashes) after fixing a `UnicodeEncodeError` that previously crashed `run_pipeline()` before any scraper could execute on Windows (the root cause of the earlier "0 new threats" runs). Still short on long-term unattended track record.
- **Classification**: keyword-based by design (see roadmap below, this isn't hidden). The taxonomy was revised 2026-08-24 (9 categories aligned to OWASP LLM Top 10 2025 v2.0, plus a new `ai_relevant` boolean field) after a data-driven review of the 440/653 (67.4%) threats that were landing in `other` under the original 8-category taxonomy from the defended thesis report — see DATA_SOURCES.md for the corpus analysis. After reclassifying the full database, `other` is **405/653 (62.0%)** — a real but modest improvement, not the 35-45% initially guessed before verifying against the full corpus. Of those 405, 114 are `ai_relevant=true` (genuine AI-adjacent content that doesn't fit one of the 9 categories cleanly) and 291 are `ai_relevant=false` (confirmed off-topic: pre-2000 generic NVD CVEs, classic non-AI MITRE ATT&CK techniques, JVN/FSTEC/CNVD vendor bugs unrelated to AI). Roughly half the "other" rate is a structural property of broad-coverage sources like NVD/MITRE/JVN returning everything they have, not a taxonomy gap.

⚠️ **In Progress**
- Documentation (README, guides, API docs)
- Security hardening (authentication, RBAC)
- Deployment guides (Docker, Kubernetes)

❌ **Planned (v2.1 - 3-4 weeks)**
- Authentication & user management
- Email/Slack alerts
- Advanced monitoring
- Deployment automation

❌ **Future (v2.2+ - 2-6 months)**
- ML-based classification (replace keyword-based)
- Real-time threat detection (webhooks)
- Advanced analytics dashboard
- Commercial SaaS launch
- Docker/Kubernetes support

See [ROADMAP.md](ROADMAP.md) for detailed timeline.

---

## 💻 Usage Examples

### Example 1: Test an Agent

```bash
# Test MockAgent (fast, for framework validation)
python testing/cli.py --scan-agent mock --verbose

# Test Mistral (real LLM, 10 min)
python testing/cli.py --scan-agent mistral --output audit.json

# Test custom agent
python testing/cli.py --scan-agent custom --output results.json
```

### Example 2: Use REST API

```bash
# Get all threats
curl http://localhost:8000/threats

# Get specific threat
curl http://localhost:8000/threats/prompt_injection_001

# Get statistics
curl http://localhost:8000/stats

# View agent health
curl http://localhost:8000/monitoring/health/my_agent
```

### Example 3: Launch Dashboards

```bash
# Main navigation hub (redirects to dashboards)
streamlit run dashboard/main.py

# Or launch specific dashboard
streamlit run dashboard/pages/operations.py
streamlit run dashboard/pages/intelligence.py
streamlit run dashboard/pages/catalog.py
```

### Example 4: Export Threat Dataset

```bash
# Via CLI
python testing/cli.py --scan-agent mock --output threats.json

# Via Dashboard
# → Intelligence tab → Menaces Récentes → Download CSV/JSON

# Via API
curl http://localhost:8000/threats?format=json > threats.json
```

See [USAGE_GUIDE.md](USAGE_GUIDE.md) for more examples.

---

## 🔐 Security & Privacy

### What This Framework Does
✅ Tests AI agents for vulnerabilities
✅ Collects threat intelligence from public sources
✅ Stores threats in local SQLite database
✅ Provides visibility into agent security posture

### What It Doesn't Do (Yet)
⚠️ Authenticate users (planned for v2.0)
⚠️ Encrypt sensitive data (planned)
⚠️ Provide real-time alerts (planned)
⚠️ HIPAA/SOC 2 compliance (future)

### Data Privacy
- **Local Processing**: All data stays on your machine (no cloud)
- **No Telemetry**: Framework doesn't phone home
- **Open Source**: Fully transparent code
- **Data Retention**: You control database

For security best practices, see [SECURITY.md](SECURITY.md).

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:
- How to report bugs
- How to suggest features
- How to submit pull requests
- Code style guidelines

Quick start for developers:
```bash
# Fork & clone
git clone https://github.com/YOUR_FORK/Agent_Security_Framework.git

# Create feature branch
git checkout -b feature/my-feature

# Make changes & test
python -m pytest tests/

# Commit & push
git push origin feature/my-feature

# Create pull request
```

---

## 📄 License

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).

This means you are free to use, study, modify, and redistribute this software, 
including for commercial purposes — provided that any modified version, including 
one deployed as a network service (SaaS), is also made available under the same 
license with its corresponding source code.

See the [LICENSE](LICENSE) file for the full legal text, or 
<https://www.gnu.org/licenses/agpl-3.0.html> for a plain-language summary.

**Copyright (C) 2026 Christian Ngiamba**

---

<a name="academic-work"></a>
## 📖 Academic Work

This project is also a Master's thesis at a French university.

**Thesis Structure:**
- Chapter 1: Literature Review & State of Art (15-18 pages)
- Chapter 2: Design & Implementation (18-22 pages)
- Chapter 3: Results & Perspectives (12-15 pages)

**Status:** In progress (framework complete, thesis writing in progress)

**Note on the classification taxonomy:** the defended thesis report documents an 8-category taxonomy. The framework's classifier was revised on 2026-08-24 to 9 categories aligned with the OWASP Top 10 for LLM Applications (2025 v2.0), plus a new `ai_relevant` field — a natural post-defense iteration driven by analysis of real corpus content, not a contradiction of what was defended. See [Known Limitations](#known-limitations) and DATA_SOURCES.md for the methodology and before/after numbers.

See [ACADEMIC.md](ACADEMIC.md) for research context.

---

## 🎯 Use Cases

### Enterprise Security Teams
- Evaluate custom/in-house AI agents
- Identify vulnerabilities before production
- Track threat landscape evolution
- Compliance & risk management

### AI Development Teams
- Secure agent development pipeline
- Pre-deployment security validation
- Threat-aware design decisions
- Security regression testing

### Security Researchers
- Threat taxonomy & classification
- Agent vulnerability research
- CTI data analysis
- Publication-ready datasets

### Educational Institutions
- Teach agent security concepts
- Hands-on security labs
- Research projects
- Open-source learning

---

## ❓ FAQ

**Q: Can I use this with my own agents?**
A: Yes! We support Claude, GPT-4, Llama, Mistral, HuggingFace, and custom agents.

**Q: Do I need API keys?**
A: Optional. Some CTI sources (Censys) require free API keys, but framework works without.

**Q: How often is threat data updated?**
A: Daily at 02:00 UTC automatically, plus weekly maintenance Monday 10:00 UTC.

**Q: Can I run this in production?**
A: Yes, but you'll need Docker, authentication, and hardening. See [DEPLOYMENT.md](DEPLOYMENT.md).

**Q: Is this open source?**
A: Yes, AGPL-3.0 license. Code is on GitHub and fully transparent.

**Q: Can I contribute?**
A: Absolutely! See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 📞 Support

| Issue Type | Where to Report |
|-----------|-----------------|
| Bugs | [GitHub Issues](https://github.com/Mavchris/Agent_Security_Framework/issues) |
| Questions | [GitHub Discussions](https://github.com/Mavchris/Agent_Security_Framework/discussions) |
| Security | [SECURITY.md](SECURITY.md) (responsible disclosure) |
| Feature Requests | [GitHub Issues](https://github.com/Mavchris/Agent_Security_Framework/issues) |

---

## 🙏 Acknowledgments

- **MITRE ATT&CK Framework** for threat taxonomy inspiration
- **NIST** for CVE/vulnerability data
- **GitHub Security** for public advisories
- **ArXiv** for research papers
- **Censys** for internet scan data
- **MISP & OpenCTI** for structured threat intelligence

---

## 📊 Project Metrics

```
Code Lines:          4000+
Test Coverage:       13/13 passing ✅
Documentation:       In progress
Dashboards:          3 (production-ready)
API Endpoints:       10+
CTI Sources:         9
Threats Database:    653
Agents Supported:    7 LLM engines
GitHub Stars:        ⭐ Help us out! 😊
```

---

## 🚀 Getting Started

**New to this framework?**

1. Read this README (you are here! 👋)
2. [Install](INSTALLATION.md) (5 minutes)
3. [Run Quick Start](#quick-start) (2 minutes)
4. [Explore Dashboards](#run-dashboard-2-minutes) (10 minutes)
5. [Read Usage Guide](USAGE_GUIDE.md) (30 minutes)

**Questions?** Create a [GitHub Discussion](https://github.com/Mavchris/Agent_Security_Framework/discussions)

**Found a bug?** Open a [GitHub Issue](https://github.com/Mavchris/Agent_Security_Framework/issues)

---

## 📚 More Documentation

- [Installation Guide](INSTALLATION.md) - Detailed setup
- [Usage Guide](USAGE_GUIDE.md) - How to use everything
- [API Documentation](API_DOCUMENTATION.md) - REST API reference
- [Architecture](ARCHITECTURE.md) - System design & UML
- [Deployment](DEPLOYMENT.md) - Production deployment
- [Data Sources](DATA_SOURCES.md) - CTI feeds info
- [Security](SECURITY.md) - Security practices
- [Contributing](CONTRIBUTING.md) - How to contribute
- [Roadmap](ROADMAP.md) - Future plans

---

<div align="center">

**Made with ❤️ for AI security research**

[⭐ Star on GitHub](https://github.com/Mavchris/Agent_Security_Framework) | [🐛 Report Bug](https://github.com/Mavchris/Agent_Security_Framework/issues) | [💡 Suggest Feature](https://github.com/Mavchris/Agent_Security_Framework/issues) | [📖 Read Docs](#-documentation)

</div>

---

**Last Updated:** August 24, 2026 (geographic CTI sources + real automation run) | **Version:** 2.0 | **Status:** Production Ready (65/100)
