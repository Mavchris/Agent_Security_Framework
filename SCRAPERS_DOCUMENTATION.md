# Scrapers Documentation

## Overview

The scraper module collects threat intelligence from three main sources:
- **CVE**: Official vulnerability database
- **GitHub**: Real-world exploits and proof-of-concepts
- **ArXiv**: Academic research papers on LLM security

All scrapers follow the same pattern:
1. Fetch data from source API
2. Parse and normalize data
3. Save to JSON files
4. Return structured threat objects

---

## CVE Scraper

### Purpose
Collects official CVE (Common Vulnerabilities and Exposures) records related to LLM/AI agents.

### Location
`scrapers/cve_scraper.py`

### Class
`CVEScraper`

### Methods

#### `fetch_cves(keywords=None, max_results=50)`
Fetches CVE-like threat data.

**Parameters:**
- `keywords` (list): Keywords to search for (default: ["llm", "prompt", "injection", "agent", "chatgpt", "claude"])
- `max_results` (int): Maximum number of CVEs to collect (default: 50)

**Returns:**
- `list`: List of threat objects with fields: `threat_id`, `title`, `description`, `source`, `url`, `collected_at`

**Example:**
```python
scraper = CVEScraper()
threats = scraper.fetch_cves(max_results=100)
# Returns 9 mock CVEs (since real LLM CVEs are still rare)
```

#### `save_to_json(filename='data/raw_cves.json')`
Saves collected CVEs to JSON file.

**Parameters:**
- `filename` (str): Output file path

**Example:**
```python
scraper.save_to_json('data/cves.json')
```

#### `get_stats()`
Prints collection statistics.

---

## GitHub Scraper

### Purpose
Collects GitHub repositories related to LLM exploits, security tools, and proof-of-concepts.

### Location
`scrapers/github_scraper.py`

### Class
`GitHubScraper`

### Methods

#### `fetch_exploits(queries=None, max_per_query=30)`
Searches GitHub for exploit repositories.

**Parameters:**
- `queries` (list): Search queries (default: ["prompt injection", "jailbreak llm", "llm security", "agent attack", "ai exploit"])
- `max_per_query` (int): Max repos per query (default: 30)

**Returns:**
- `list`: List of threat objects with fields: `threat_id`, `title`, `description`, `source`, `url`, `stars`, `language`, `collected_at`

**Rate Limiting:**
- GitHub API has a limit of 60 requests/hour without authentication
- Use GitHub token for increased limits (5,000 requests/hour)

**Example:**
```python
scraper = GitHubScraper()
threats = scraper.fetch_exploits(max_per_query=25)
# Returns ~125 GitHub repos
```

#### `save_to_json(filename='data/raw_github.json')`
Saves collected repos to JSON file.

#### `get_stats()`
Prints statistics including top programming languages.

---

## ArXiv Scraper

### Purpose
Collects academic research papers on LLM security, adversarial attacks, and agent safety from ArXiv.

### Location
`scrapers/arxiv_scraper.py`

### Class
`ArxivScraper`

### Methods

#### `fetch_papers(queries=None, max_per_query=30)`
Searches ArXiv for relevant papers.

**Parameters:**
- `queries` (list): Search queries (default: ["prompt injection", "jailbreak language model", "llm security", "adversarial attack language model", "agent safety"])
- `max_per_query` (int): Max papers per query (default: 30)

**Returns:**
- `list`: List of threat objects with fields: `threat_id`, `title`, `description`, `authors`, `source`, `url`, `published`, `collected_at`

**API:**
- Uses official ArXiv API (no authentication required)
- Very reliable, no rate limits

**Example:**
```python
scraper = ArxivScraper()
threats = scraper.fetch_papers(max_per_query=20)
# Returns ~100 papers
```

#### `save_to_json(filename='data/raw_arxiv.json')`
Saves collected papers to JSON file.

#### `get_stats()`
Prints statistics including date range of papers.

---

## ETL Pipeline

### Purpose
Complete pipeline combining all scrapers, classifier, and database storage.

### Location
`pipeline/process.py`

### Usage
```python
from pipeline.process import run_pipeline

run_pipeline()
```

### Steps
1. **Scrape**: Collect threats from all 3 sources
2. **Classify**: Categorize each threat (6 categories)
3. **Store**: Insert into SQLite database

### Output
- JSON files: `data/raw_cves.json`, `data/raw_github.json`, `data/raw_arxiv.json`
- Database: `data/threats.db` with 240 threats (live count; check the `/stats` API endpoint for the current value)

---

## Testing

Run all scraper tests:
```bash
python -m unittest tests.test_scrapers -v
```

**Test Coverage:**
- CVE Scraper: 5 tests (object structure, data collection, JSON export)
- GitHub Scraper: 2 tests (initialization, method availability)
- ArXiv Scraper: 5 tests (object structure, data collection, JSON export)

All tests passing: ✅

---

## Data Format

### Threat Object Structure
```python
{
    "threat_id": "CVE-2024-1001",  # Unique identifier
    "title": "Prompt injection vulnerability",  # Short description
    "description": "Detailed description...",  # Full description
    "source": "CVE",  # Source: CVE, GitHub, or ArXiv
    "url": "https://...",  # Link to original
    "collected_at": "2024-03-15T10:30:00",  # ISO timestamp
    
    # Optional fields by source
    "severity": "high",  # CVE only
    "stars": 150,  # GitHub only
    "language": "Python",  # GitHub only
    "authors": "John Doe, Jane Smith",  # ArXiv only
    "published": "2024-03-10"  # ArXiv only
}
```

---

## Performance

| Scraper | Time | Threats | Rate |
|---------|------|---------|------|
| CVE | ~1s | 9 | Fast |
| GitHub | ~5s | 125 | Medium (rate limited) |
| ArXiv | ~10s | 100 | Slow (API dependent) |
| **Total Pipeline** | ~20s | 234 | Good |

---

## Troubleshooting

### GitHub Rate Limit Error
```
403 Client Error: rate limit exceeded
```
**Solution:** Use GitHub authentication token or wait 1 hour.

### ArXiv Connection Timeout
```
requests.exceptions.Timeout
```
**Solution:** ArXiv API can be slow. Increase timeout or retry.

### Missing Data Fields
Ensure `description` is not `None` before processing:
```python
text = threat.get('title', '') + ' ' + (threat.get('description', '') or '')
```

---

## Future Enhancements

- [ ] Add GitHub token authentication for higher rate limits
- [ ] Add incremental scraping (only new threats since last run)
- [ ] Add scraper for Twitter/Reddit threat mentions
- [ ] Add caching to avoid re-scraping
- [ ] Add scraper scheduling (automatic daily runs)