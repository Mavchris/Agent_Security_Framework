"""
EUVD Scraper - European Union Vulnerability Database
Real vulnerability data from ENISA (EU cybersecurity agency), mandated
under the NIS2 directive. Public API, no authentication required.
"""

from datetime import datetime

import requests

from scrapers.base_scraper import BaseScraper

BASE_URL = "https://euvdservices.enisa.europa.eu/api/search"


def _parse_date(value):
    """EUVD dates look like 'Aug 19, 2026, 9:58:51 PM' - normalize to
    YYYY-MM-DD to match the format used by the other scrapers."""
    if not value:
        return ""
    try:
        return datetime.strptime(value, "%b %d, %Y, %I:%M:%S %p").strftime("%Y-%m-%d")
    except ValueError:
        return value[:10]


def _severity_from_score(score):
    """Map a CVSS base score to this project's severity scale"""
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


class EUVDScraper(BaseScraper):
    """Scrapes real vulnerability data from the EU Vulnerability Database (ENISA)"""

    SOURCE_NAME = "EUVD"
    ITEM_LABEL = "EUVD entries"
    DEFAULT_OUTPUT_FILE = "data/raw_euvd.json"

    def __init__(self):
        super().__init__(base_url=BASE_URL)

    def fetch_vulnerabilities(self, queries=None, max_per_query=25):
        """
        Fetch real vulnerabilities from EUVD matching AI/LLM-relevant terms.

        Args:
            queries (list): Free-text search terms. Defaults to a set of
                AI/agent security terms (vendor names alone are too broad -
                see Vague 3a diagnostic: "openai" matched an unrelated CVE
                that merely credited OpenAI's security team).
            max_per_query (int): Max results requested per query.

        Returns:
            list: List of threat objects.
        """

        if queries is None:
            queries = [
                "prompt injection",
                "jailbreak language model",
                "large language model",
                "AI agent vulnerability",
                "LLM security",
            ]

        print(f"[EU] Fetching EUVD vulnerabilities ({len(queries)} queries)...")

        seen_ids = {threat["threat_id"] for threat in self.data}

        for idx, query in enumerate(queries, 1):
            print(f"    - Searching: '{query}'...")

            try:
                response = self.request_with_retry(
                    lambda q=query: self._get(q, max_per_query)
                )
                payload = response.json()
                items = payload.get("items", [])
                total = payload.get("total", len(items))
                found = 0

                for item in items:
                    euvd_id = item.get("id")
                    if not euvd_id or euvd_id in seen_ids:
                        continue

                    self.data.append(self._to_threat(item, query))
                    seen_ids.add(euvd_id)
                    found += 1

                print(f"      Found {found} new entries ({len(items)} of {total} total)")

            except Exception as e:
                self._record_error(e)

        print(f"\nTotal EUVD entries collected: {len(self.data)}")
        return self.data

    def _get(self, query, size):
        response = requests.get(
            self.base_url,
            params={"text": query, "size": size, "page": 0},
            timeout=15,
        )
        response.raise_for_status()
        return response

    @staticmethod
    def _to_threat(item, query):
        euvd_id = item["id"]
        description = item.get("description", "") or "No description available"

        references = [r for r in (item.get("references") or "").split("\n") if r.strip()]
        aliases = [a for a in (item.get("aliases") or "").split("\n") if a.strip()]

        vendors = [v.get("vendor", {}).get("name") for v in (item.get("enisaIdVendor") or [])]
        products = [p.get("product", {}).get("name") for p in (item.get("enisaIdProduct") or [])]
        keywords = [k for k in vendors + products if k]

        return {
            "threat_id": euvd_id,
            "title": f"{euvd_id}: {description[:80].rsplit(' ', 1)[0]}",
            "description": description[:1000],
            "test_payload": f"Verify agent resilience to known issue: {description[:150]}",
            "detection_keywords": keywords or query.split(),
            "severity": _severity_from_score(item.get("baseScore")),
            "source": "EUVD",
            "url": f"https://euvd.enisa.europa.eu/enisa/{euvd_id}",
            "cve_aliases": aliases,
            "epss": item.get("epss"),
            "references": references,
            "published": _parse_date(item.get("datePublished")),
            "collected_at": datetime.now().isoformat(),
        }


# Test
if __name__ == "__main__":
    import sys
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    scraper = EUVDScraper()
    scraper.fetch_vulnerabilities(max_per_query=10)
    scraper.save_to_json()
    scraper.get_stats()
