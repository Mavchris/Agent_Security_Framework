# CTI Data Sources

## Active (wired into `pipeline/process.py`, 7 sources)

| Source | Scraper | What it collects |
|--------|---------|-------------------|
| CVE | `scrapers/cve_scraper.py` | Published CVE records |
| NVD | `scrapers/nvd_scraper.py` | NIST National Vulnerability Database entries |
| GitHub Security | `scrapers/github_scraper.py` | Public security advisories / exploit PoCs |
| ArXiv | `scrapers/arxiv_scraper.py` | Research papers on AI/agent security |
| MITRE ATT&CK | `scrapers/mitre_scraper.py` | Adversarial techniques |
| Censys | `scrapers/censys_scraper.py` | Internet-exposed service/endpoint data (requires a free API key in `config/.env.local`) |
| OpenCTI | `scrapers/opencti_scraper.py` | Structured threat intelligence |

## Not currently active

- **MISP** (`scrapers/misp_scraper.py`) — the scraper file exists but is not imported or called by `pipeline/process.py`. No MISP data is currently in `data/threats.db`.

Live per-source counts are available via the `/stats` API endpoint or the Catalog dashboard rather than hardcoded here, since they change every time the pipeline runs.
