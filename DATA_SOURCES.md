# CTI Data Sources

## Active (wired into `pipeline/process.py`, 8 sources)

All sources below make real network calls with no authentication required, except where noted.

| Source | Scraper | What it collects |
|--------|---------|-------------------|
| CVE | `scrapers/cve_scraper.py` | CVEs for AI/LLM vendors and products, via the CIRCL cve-search public API (`cve.circl.lu`) |
| NVD | `scrapers/nvd_scraper.py` | NIST National Vulnerability Database entries |
| GitHub Security | `scrapers/github_scraper.py` | Public security advisories / exploit PoCs |
| ArXiv | `scrapers/arxiv_scraper.py` | Research papers on AI/agent security, via the official ArXiv API |
| MITRE ATT&CK | `scrapers/mitre_scraper.py` | Adversarial techniques |
| OpenCTI | `scrapers/opencti_scraper.py` | Structured threat intelligence |
| **CIRCL Vulnerability-Lookup** | `scrapers/circl_vulnerability_lookup_scraper.py` | Recent vulnerabilities from **CNVD (China), FSTEC/BDU (Russia), JVN (Japan) and CERT-FR (France)**, via CIRCL's public aggregator (`vulnerability.circl.lu`). Extends coverage beyond the mostly Anglo-American sources above; entries are kept in their original language (Chinese/Russian/French), except JVN which JVN itself publishes in English. |
| **EUVD** | `scrapers/euvd_scraper.py` | The EU Vulnerability Database, operated by ENISA (EU cybersecurity agency) under the NIS2 directive (`euvdservices.enisa.europa.eu`) |

## Not currently active

- **MISP** (`scrapers/misp_scraper.py`) — the scraper file exists but is not imported or called by `pipeline/process.py`. No MISP data is currently in `data/threats.db`.
- **Censys** (`scrapers/censys_scraper.py`) — the method the pipeline calls (`fetch_exposures`) generates synthetic placeholder entries and never contacts the real Censys API. A second method, `fetch_real_censys_data`, does call the real API but isn't wired into the pipeline, and the credentials currently in `config/.env.local` return `401 Unauthorized` when tested directly against it.

## Known limitation: cross-source deduplication is by exact ID only

Deduplication is a SQLite `UNIQUE` constraint on `threat_id` (see [Known Limitations](README.md#known-limitations)). Each scraper builds its own `threat_id` format (e.g. `NVD-CVE-2026-4182` vs `CVE-2026-4182` vs `CNVD-2026-32003`, which can all reference the *same* underlying CVE). This means the same vulnerability reported by multiple sources is stored as multiple separate rows rather than being merged — confirmed with CIRCL/EUVD, but this predates this vague (NVD and CVE already used incompatible ID schemes for the same CVE). No fix has been applied; it needs a design decision (e.g. deduplicate on an extracted canonical CVE ID when one exists) rather than a quick patch.

Live per-source counts are available via the `/stats` API endpoint or the Catalog dashboard rather than hardcoded here, since they change every time the pipeline runs.
