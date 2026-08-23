# Installation Guide

Complete step-by-step guide to install and configure the Agent Security Intelligence Framework.

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [System Requirements](#system-requirements)
3. [Installation Steps](#installation-steps)
4. [Configuration](#configuration)
5. [Verification](#verification)
6. [Troubleshooting](#troubleshooting)
7. [First Run](#first-run)
8. [Next Steps](#next-steps)

---

## Prerequisites

Before you begin, ensure you have:

- ✅ Git installed ([Download Git](https://git-scm.com))
- ✅ Python 3.11+ installed ([Download Python](https://www.python.org/downloads/))
- ✅ Internet connection (for CTI data collection)
- ✅ Code editor (VS Code, PyCharm, or similar - optional)
- ✅ 30 minutes for complete setup

### Verify Prerequisites

```bash
# Check Git version
git --version
# Should show: git version 2.x.x or higher

# Check Python version
python --version
# Should show: Python 3.11.x or higher
# Note: On some systems use 'python3' instead of 'python'

# Check pip is installed
pip --version
# Should show: pip 23.x.x or higher
```

If any are missing, install them before continuing.

---

## System Requirements

### Minimum Requirements
- **OS**: Windows 10+, macOS 10.14+, Linux (Ubuntu 18.04+)
- **CPU**: Dual-core processor
- **RAM**: 4GB minimum (8GB recommended)
- **Disk**: 2GB free space
- **Internet**: Required for CTI data collection

### Recommended Specifications
- **OS**: Windows 11, macOS 12+, Ubuntu 20.04+
- **CPU**: 4-core processor
- **RAM**: 8GB or more
- **Disk**: 5GB free space (for database growth)
- **GPU**: Optional (for local LLM inference with Ollama)

### Platform-Specific Notes

#### Windows
- PowerShell 5.0+ or Windows Terminal recommended
- May need to run: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`
- Git Bash works well as alternative to PowerShell

#### macOS
- Requires Xcode Command Line Tools: `xcode-select --install`
- Homebrew is optional but recommended: `brew install python@3.11`

#### Linux
- Ubuntu/Debian: `sudo apt-get update && sudo apt-get install python3.11 python3.11-venv`
- Fedora: `sudo dnf install python3.11`
- CentOS: `sudo yum install python3.11`

---

## Installation Steps

### Step 1: Clone Repository

```bash
# Navigate to your projects directory
cd ~/projects
# Or: cd C:\Users\YourName\projects  (Windows)

# Clone the repository
git clone https://github.com/Mavchris/Agent_Security_Framework.git

# Enter the directory
cd Agent_security_framework

# Verify you're in right location
pwd  # Linux/macOS
cd   # Windows (shows current directory)
```

Expected output:
```
~/projects/Agent_security_framework$
```

### Step 2: Create Virtual Environment

A virtual environment isolates project dependencies from system Python.

#### Windows (PowerShell)

```powershell
# Create virtual environment
python -m venv .venv

# Activate virtual environment
.venv\Scripts\Activate.ps1

# If you get an execution policy error:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Then activate again:
.venv\Scripts\Activate.ps1
```

You should see `(.venv)` at start of your command prompt.

#### Windows (Git Bash)

```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
source .venv/Scripts/activate
```

#### macOS & Linux

```bash
# Create virtual environment
python3.11 -m venv .venv

# Activate virtual environment
source .venv/bin/activate
```

You should see `(.venv)` at start of your terminal.

**Verify activation:**
```bash
# Check Python path points to .venv
which python  # Linux/macOS
where python  # Windows PowerShell

# Should show path containing ".venv"
```

### Step 3: Upgrade pip

```bash
# Ensure pip is latest version
python -m pip install --upgrade pip

# Verify pip version
pip --version
# Should show: pip 23.x.x or higher
```

### Step 4: Install Dependencies

```bash
# Install all required packages
pip install -r requirements.txt

# This will install:
# - requests, beautifulsoup4 (web scraping)
# - pandas, numpy (data processing)
# - streamlit, plotly (dashboards)
# - fastapi, uvicorn (REST API)
# - schedule (task scheduling)
# - pydantic (data validation)
# - python-dotenv (environment variables)
# - anthropic, openai, ollama (LLM libraries)
# - and 20+ more...

# Verify installation
pip list
# Should show all packages listed in requirements.txt
```

Expected time: 2-5 minutes depending on internet speed.

### Step 5: Create Configuration Files

#### Create .env.local for API Keys

```bash
# From the project root, copy the example env file into config/
cp .env.example config/.env.local
# Or on Windows:
copy .env.example config\.env.local

# Edit with your text editor
# Open: config/.env.local
```

**File content template:**
```ini
# Censys API Credentials (optional, for internet scan data)
CENSYS_API_ID=your_api_id_here
CENSYS_API_SECRET=your_api_secret_here

# Optional: Anthropic API Key (for Claude agent testing)
ANTHROPIC_API_KEY=your_api_key_here

# Optional: OpenAI API Key (for GPT-4 agent testing)
OPENAI_API_KEY=your_api_key_here

# Database
DATABASE_URL=../data/threats.db

# Logging
LOG_LEVEL=INFO

# Scheduler
SCHEDULER_ENABLED=true
SCHEDULER_TIMEZONE=UTC
```

**How to get API keys (optional):**

- **Censys**: Free account at https://censys.io
  - Email verification required
  - API ID & Secret in account settings
  - Optional (framework works without)

- **Anthropic**: Get at https://console.anthropic.com
  - Required only if testing with Claude
  - Optional (can test with Mock agent instead)

- **OpenAI**: Get at https://platform.openai.com
  - Required only if testing with GPT-4
  - Optional (can test with other agents)

**Important:** Don't commit .env.local to Git! It's already in .gitignore.

### Step 6: Initialize Database

```bash
# Create data directory if needed
mkdir -p data
mkdir -p logs

# Verify directories exist
ls -la data/
ls -la logs/
```

The database will be created automatically on first run.

### Step 7: Verify Installation

```bash
# Check all required directories exist
python -c "
import os
dirs = ['dashboard', 'testing', 'core', 'pipeline', 'scrapers', 'api', 'data', 'logs', 'config']
for d in dirs:
    if os.path.exists(d):
        print(f'✓ {d}/')
    else:
        print(f'✗ {d}/ MISSING')
"

# Check Python packages
python -c "
packages = ['streamlit', 'fastapi', 'pandas', 'schedule', 'requests', 'pydantic']
for pkg in packages:
    try:
        __import__(pkg)
        print(f'✓ {pkg}')
    except ImportError:
        print(f'✗ {pkg} MISSING')
"
```

Should show all ✓ (checks passed).

---

## Configuration

### Required Configuration

Minimal setup to get framework running:

```bash
# 1. Virtual environment activated
# (should see (.venv) in prompt)

# 2. API keys (optional but recommended for full features)
# Edit: config/.env.local
```

### Optional Configuration

#### For Claude Agent Testing

```bash
# 1. Get API key from https://console.anthropic.com
# 2. Add to config/.env.local:
ANTHROPIC_API_KEY=sk-ant-v4-xxxxx...

# 3. Test with CLI:
python testing/cli.py --scan-agent claude
```

#### For GPT-4 Agent Testing

```bash
# 1. Get API key from https://platform.openai.com
# 2. Add to config/.env.local:
OPENAI_API_KEY=sk-proj-xxxxx...

# 3. Test with CLI:
python testing/cli.py --scan-agent gpt4
```

#### For Local LLM (Mistral via Ollama)

```bash
# 1. Download Ollama from https://ollama.ai
# 2. Pull Mistral model:
ollama pull mistral

# 3. Start Ollama server (in separate terminal):
ollama serve

# 4. Test with CLI:
python testing/cli.py --scan-agent mistral
```

#### For Censys Internet Scan Data

```bash
# 1. Create free account at https://censys.io
# 2. Get API ID & Secret from Settings
# 3. Add to config/.env.local:
CENSYS_API_ID=your_id
CENSYS_API_SECRET=your_secret

# 4. Pipeline will now collect Censys data
python pipeline/process.py
```

### Environment Variables Reference

| Variable | Required | Default | Example |
|----------|----------|---------|---------|
| `CENSYS_API_ID` | No | N/A | `xxxxx` |
| `CENSYS_API_SECRET` | No | N/A | `xxxxx` |
| `ANTHROPIC_API_KEY` | No | N/A | `sk-ant-v4-xxxxx` |
| `OPENAI_API_KEY` | No | N/A | `sk-proj-xxxxx` |
| `DATABASE_URL` | No | `data/threats.db` | `data/threats.db` |
| `LOG_LEVEL` | No | `INFO` | `DEBUG`, `INFO`, `WARNING` |
| `SCHEDULER_ENABLED` | No | `true` | `true`, `false` |
| `SCHEDULER_TIMEZONE` | No | `UTC` | `UTC`, `America/New_York` |

---

## Verification

### Quick Verification (2 minutes)

```bash
# Verify Python works
python --version

# Verify virtual environment is active
which python  # Should show path with .venv

# Verify packages installed
pip list | grep -E "streamlit|fastapi|schedule"

# Verify directories exist
ls -la | grep -E "dashboard|testing|data|logs"
```

All checks should pass ✓

### Full Verification (5 minutes)

```bash
# 1. Run unit tests
python -m pytest tests/test_classifier.py -v
# Should show: 11 passed

# 2. Check database can be created
python -c "import sqlite3; conn = sqlite3.connect('data/threats.db'); print('✓ Database OK')"

# 3. Test imports
python -c "from core.classifier import ImprovedThreatClassifier; print('✓ Classifier imports OK')"
python -c "from testing.agent_wrappers import get_agent_wrapper; print('✓ Wrappers import OK')"

# 4. Test CLI works
python testing/cli.py --help
# Should show CLI options

# 5. Check orchestrator config
python orchestrator.py --status
# Should show scheduler status
```

All verifications should pass ✓

### Dashboard Verification (1 minute)

```bash
# Start main navigation hub
streamlit run dashboard/main.py

# Open browser: http://localhost:8501
# Should see:
# - Welcome message
# - 3 navigation buttons:
#   ✓ Operations
#   ✓ Intelligence
#   ✓ Catalog

# Press Ctrl+C to stop
```

---

## Troubleshooting

### Issue: Python not found

**Error:**
```
'python' is not recognized as an internal or external command
```

**Solution:**
```bash
# Try python3 instead
python3 --version

# If that works, use 'python3' for all commands:
python3 -m venv .venv
python3 -m pip install -r requirements.txt
python3 testing/cli.py --help

# Or add Python to PATH:
# Windows: https://docs.python.org/3/using/windows.html#setting-path-and-pythonhome
```

### Issue: Virtual environment not activating

**Error:**
```
(.venv) not showing in prompt
```

**Solution:**
```bash
# Windows PowerShell - try:
.venv\Scripts\Activate.ps1

# If that fails, check execution policy:
Get-ExecutionPolicy

# If restricted, run:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Then activate:
.venv\Scripts\Activate.ps1

# Windows CMD (alternative):
.venv\Scripts\activate.bat

# Linux/macOS:
source .venv/bin/activate
```

### Issue: Dependencies installation fails

**Error:**
```
ERROR: Could not find a version that satisfies the requirement...
```

**Solution:**
```bash
# 1. Update pip first
python -m pip install --upgrade pip

# 2. Clear pip cache
pip cache purge

# 3. Try installing again
pip install -r requirements.txt

# 4. If specific package fails, try installing individually
pip install streamlit==1.28.1
pip install fastapi==0.104.1

# 5. Check if you have internet connection
ping google.com
```

### Issue: Port 8501 already in use (Streamlit)

**Error:**
```
Address already in use: ('127.0.0.1', 8501)
```

**Solution:**
```bash
# Option 1: Use different port
streamlit run dashboard/main.py --server.port 8502

# Option 2: Kill process using port 8501
# Windows:
netstat -ano | findstr :8501
taskkill /PID <PID> /F

# Linux/macOS:
lsof -i :8501
kill -9 <PID>
```

### Issue: Port 8000 already in use (API)

**Error:**
```
Address already in use: ('127.0.0.1', 8000)
```

**Solution:**
```bash
# Use different port
python api/app.py --port 8001

# Or kill existing process (see above)
```

### Issue: SQLite database locked

**Error:**
```
database is locked
```

**Solution:**
```bash
# 1. Stop all running instances
# Ctrl+C in all terminals running framework

# 2. Wait 5 seconds

# 3. Delete lock file if exists
rm -f data/threats.db-wal
rm -f data/threats.db-shm

# 4. Restart
streamlit run dashboard/main.py
```

### Issue: API keys not working

**Error:**
```
Authentication failed for Censys
Invalid API key for OpenAI
```

**Solution:**
```bash
# 1. Verify .env.local exists
cat config/.env.local

# 2. Check API keys are correct
# - Censys: https://censys.io/api (copy ID and Secret exactly)
# - OpenAI: https://platform.openai.com/api-keys
# - Anthropic: https://console.anthropic.com/api/keys

# 3. Check .env.local has no extra spaces
ANTHROPIC_API_KEY=sk-ant-xxxxx  # No spaces!

# 4. Restart framework (restart picks up new env vars)
# Stop: Ctrl+C
# Start: streamlit run dashboard/main.py

# 5. If still fails, try without API keys
# Framework still works with 6/7 CTI sources
```

### Issue: Tests failing

**Error:**
```
FAILED tests/test_classifier.py::test_prompt_injection
```

**Solution:**
```bash
# 1. Check database exists
ls -la data/threats.db

# 2. Run with verbose output
python -m pytest tests/test_classifier.py -v -s

# 3. Check log output
tail -f logs/test.log

# 4. Reinstall test dependencies
pip install pytest pytest-cov

# 5. Run individual test
python -m pytest tests/test_classifier.py::test_classification -v

# 6. If all else fails, reset database
rm -f data/threats.db
python pipeline/process.py  # Recreate database
python -m pytest tests/test_classifier.py -v
```

### Issue: Slow performance

**Problem:** Dashboard is slow, scanner takes too long

**Solution:**
```bash
# 1. Check system resources
# RAM usage: Should be < 1GB
# CPU usage: Should be < 50%

# 2. Close other applications
# Streamlit + SQLite don't need much, but close browsers if possible

# 3. Reduce dashboard refresh rate
# Edit dashboard/.py file:
# st.set_page_config(initial_sidebar_state="collapsed")

# 4. For scanner, use MockAgent instead of real LLM
python testing/cli.py --scan-agent mock
# (Fast: 1 minute vs 10 minutes for Mistral)

# 5. Check database size
ls -lh data/threats.db
# If > 1GB, backup and reset:
# cp data/threats.db data/threats.db.backup
# rm data/threats.db
# python pipeline/process.py
```

### Issue: Permission denied errors

**Error:**
```
Permission denied: 'config/.env.local'
PermissionError: [Errno 13] Permission denied: 'data/threats.db'
```

**Solution:**
```bash
# Linux/macOS: Fix file permissions
chmod 644 config/.env.local
chmod 755 data/
chmod 644 data/threats.db

# Windows: Right-click file → Properties → Security → Edit → Grant permissions

# Or run terminal as administrator:
# Windows: Win+X → Command Prompt (Admin) or PowerShell (Admin)
# macOS: sudo python testing/cli.py --help
```

### Issue: Unicode/Encoding errors (Windows)

**Error:**
```
UnicodeEncodeError: 'cp1252' codec can't encode character...
```

**Solution:**
```bash
# This is cosmetic on Windows (emoji in logs)
# Framework still works fine

# To fix: Set UTF-8 encoding
set PYTHONIOENCODING=utf-8

# Or in PowerShell:
$env:PYTHONIOENCODING="utf-8"

# Then restart:
streamlit run dashboard/main.py
```

### Issue: Git clone fails

**Error:**
```
fatal: could not read Username for 'https://github.com':...
```

**Solution:**
```bash
# Option 1: Use GitHub token
# 1. Create token at https://github.com/settings/tokens
# 2. Clone with token:
git clone https://YOUR_TOKEN@github.com/Mavchris/Agent_Security_Framework.git

# Option 2: Use SSH
# 1. Add SSH key: https://docs.github.com/en/authentication/connecting-to-github-with-ssh
# 2. Clone with SSH:
git clone git@github.com:Mavchris/Agent_Security_Framework.git

# Option 3: Download ZIP
# https://github.com/Mavchris/Agent_Security_Framework/archive/refs/heads/main.zip
```

---

## First Run

### Scenario 1: Quick Start (No Agent Testing)

```bash
# 1. Make sure virtual environment is active
# (should see (.venv) in prompt)

# 2. Launch dashboard
streamlit run dashboard/main.py

# 3. Open browser: http://localhost:8501

# 4. Explore:
# - Operations tab: See framework info
# - Intelligence tab: View 240+ threats
# - Catalog tab: Search threats

# 5. Stop: Ctrl+C in terminal
```

**Time:** 2-3 minutes

### Scenario 2: Test with Mock Agent

```bash
# 1. Virtual environment active

# 2. Run CLI scanner
python testing/cli.py --scan-agent mock --verbose

# 3. View results
# Terminal shows:
# - Threats tested: 219
# - Vulnerabilities found: 218
# - Vulnerability score: 99.5%

# 4. Export results
python testing/cli.py --scan-agent mock --output mock_audit.json

# 5. Review JSON output
cat mock_audit.json
```

**Time:** 5-10 minutes

### Scenario 3: Test with Real LLM (Mistral)

```bash
# Prerequisites:
# 1. Install Ollama: https://ollama.ai
# 2. Download Mistral:
#    ollama pull mistral
# 3. Start Ollama server (separate terminal):
#    ollama serve

# Then:
# 1. Run scanner with Mistral
python testing/cli.py --scan-agent mistral --verbose --output mistral_audit.json

# 2. Wait 10-15 minutes for completion
# (240 threats × ~3-4 sec per threat)

# 3. View results
cat mistral_audit.json

# 4. Compare with mock:
# Mock: 99.5% vulnerabilities (simulation)
# Mistral: 15-25% vulnerabilities (real behavior)
```

**Time:** 15-20 minutes

### Scenario 4: Start Automation

```bash
# 1. Virtual environment active

# 2. Start orchestrator (runs continuously)
python orchestrator.py

# 3. You'll see:
# [2026-03-28 14:30:00] Starting Pipeline Orchestrator
# [2026-03-28 14:30:00] Next daily pipeline: 2026-03-29 02:00 UTC
# [2026-03-28 14:30:00] Next weekly pipeline: 2026-03-29 10:00 UTC

# 4. Pipeline runs automatically on schedule:
# - Daily: 02:00 UTC (collect from 7 sources)
# - Weekly: Monday 10:00 UTC (validate & report)
# - Hourly: Health checks

# 5. Stop: Ctrl+C when ready
# (Won't break anything, just stops scheduling)

# 6. To restart:
python orchestrator.py
```

**Time:** Continuous (stop anytime with Ctrl+C)

---

## Next Steps

After successful installation:

### 1. Read Documentation

```bash
# Quick overview (5 min)
cat README.md

# Usage guide (30 min)
cat USAGE_GUIDE.md

# API reference (20 min)
cat API_DOCUMENTATION.md
```

### 2. Explore Features

```bash
# Launch dashboards
streamlit run dashboard/main.py

# Test CLI scanner
python testing/cli.py --scan-agent mock

# View threat database
python -c "
import sqlite3
conn = sqlite3.connect('data/threats.db')
cursor = conn.cursor()
cursor.execute('SELECT COUNT(*) FROM threats')
print(f'Total threats: {cursor.fetchone()[0]}')
"
```

### 3. Configure (Optional)

```bash
# Add API keys for full CTI coverage
nano config/.env.local  # or edit in text editor

# Configure for your environment
# Timezon, log levels, scheduler settings, etc.
```

### 4. Customize (Optional)

```bash
# Add custom agent wrapper
# Edit: testing/agent_wrappers.py
# Add your LLM integration

# Add custom CTI source
# Create: scrapers/my_source_scraper.py
# Update: pipeline/process.py to include it

# Modify threat categories
# Edit: the self.keywords dictionary in core/classifier.py
# (ImprovedThreatClassifier.__init__ holds the keyword lists for all 9 categories)
```

### 5. Run Tests

```bash
# Verify everything works
python -m pytest tests/test_classifier.py -v

# Should show: 11 passed ✓
```

### 6. Deploy (Optional)

```bash
# For production deployment, see:
cat DEPLOYMENT.md

# Includes:
# - Docker containerization
# - Kubernetes deployment
# - Environment setup for production
# - Security hardening
```

---

## Getting Help

| Issue | Solution |
|-------|----------|
| **Installation stuck** | See [Troubleshooting](#troubleshooting) section |
| **Command not found** | Ensure virtual environment is active: `source .venv/bin/activate` |
| **Import errors** | Reinstall packages: `pip install -r requirements.txt` |
| **Database errors** | Reset database: `rm data/threats.db` then `python pipeline/process.py` |
| **Slow performance** | Use MockAgent for testing (10x faster than real LLM) |
| **API key issues** | Restart framework after updating `.env.local` |

### Online Resources

- **GitHub Issues**: https://github.com/Mavchris/Agent_Security_Framework/issues
- **GitHub Discussions**: https://github.com/Mavchris/Agent_Security_Framework/discussions
- **Python Docs**: https://docs.python.org/3.11/
- **Streamlit Docs**: https://docs.streamlit.io/
- **FastAPI Docs**: https://fastapi.tiangolo.com/

---

## Summary Checklist

Complete installation in order:

- [ ] Install Git & Python 3.11+
- [ ] Clone repository: `git clone https://github.com/Mavchris/Agent_Security_Framework.git`
- [ ] Create virtual environment: `python -m venv .venv`
- [ ] Activate virtual environment: `source .venv/bin/activate`
- [ ] Upgrade pip: `python -m pip install --upgrade pip`
- [ ] Install dependencies: `pip install -r requirements.txt`
- [ ] Copy .env template: `cp .env.example config/.env.local`
- [ ] Configure API keys (optional): `nano config/.env.local`
- [ ] Create data/logs directories: `mkdir -p data logs`
- [ ] Run verification: `python testing/cli.py --help`
- [ ] Launch dashboard: `streamlit run dashboard/main.py`
- [ ] Explore and test!

---

## Uninstallation

To remove the framework:

```bash
# Backup data first (if needed)
cp data/threats.db data/threats.db.backup

# Deactivate virtual environment
deactivate

# Remove project directory
rm -rf Agent_security_framework

# Or on Windows:
rmdir /s Agent_security_framework
```

---

## Version Info

- **Framework Version**: 2.0
- **Python Minimum**: 3.11
- **Last Updated**: March 28, 2026
- **Status**: Production Ready (65/100)

---

**Need help?** Create an issue on [GitHub Issues](https://github.com/Mavchris/Agent_Security_Framework/issues)

**Questions?** Ask on [GitHub Discussions](https://github.com/Mavchris/Agent_Security_Framework/discussions)

**Ready to deploy?** See [DEPLOYMENT.md](DEPLOYMENT.md)

**Want to contribute?** See [CONTRIBUTING.md](CONTRIBUTING.md)
