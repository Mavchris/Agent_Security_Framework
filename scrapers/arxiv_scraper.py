"""
ArXiv Scraper with Test Payloads
Collects research papers on LLM security with test cases
"""

import requests
import xml.etree.ElementTree as ET
from datetime import datetime
import time

from scrapers.base_scraper import BaseScraper

ATOM_NS = {"atom": "http://www.w3.org/2005/Atom"}


class ArxivScraper(BaseScraper):
    """
    Scrapes ArXiv papers related to LLM/AI agent security
    Each paper enriched with test_payload and severity
    """

    SOURCE_NAME = "ARXIV"
    ITEM_LABEL = "ArXiv papers with test payloads"
    DEFAULT_OUTPUT_FILE = "data/raw_arxiv.json"

    def __init__(self):
        super().__init__(base_url="http://export.arxiv.org/api/query")

    def fetch_papers(self, queries=None, max_per_query=30):
        """
        Fetch papers from ArXiv on LLM security
        Each paper enriched with test_payload and severity

        Args:
            queries (list): Search queries
            max_per_query (int): Max papers per query

        Returns:
            list: List of threat objects with test payloads
        """

        if queries is None:
            queries = [
                "prompt injection",
                "jailbreak language model",
                "llm security",
                "adversarial attack language model",
                "agent safety"
            ]

        print(f"Searching ArXiv for papers ({len(queries)} queries)...")

        seen_ids = {threat["threat_id"] for threat in self.data}

        for idx, query in enumerate(queries, 1):
            print(f"    - Searching: '{query}'...")

            try:
                response = requests.get(
                    self.base_url,
                    params={
                        "search_query": f"all:{query}",
                        "start": 0,
                        "max_results": max_per_query,
                        "sortBy": "relevance",
                    },
                    timeout=15,
                )
                response.raise_for_status()

                root = ET.fromstring(response.content)
                entries = root.findall("atom:entry", ATOM_NS)
                found = 0

                for entry in entries:
                    arxiv_url = entry.findtext("atom:id", default="", namespaces=ATOM_NS).strip()
                    arxiv_id = arxiv_url.rsplit("/abs/", 1)[-1]
                    threat_id = f"ARX-{arxiv_id}"

                    if not arxiv_id or threat_id in seen_ids:
                        continue

                    title = " ".join(
                        entry.findtext("atom:title", default="", namespaces=ATOM_NS).split()
                    )
                    summary = " ".join(
                        entry.findtext("atom:summary", default="", namespaces=ATOM_NS).split()
                    )
                    authors = [
                        author.findtext("atom:name", default="", namespaces=ATOM_NS)
                        for author in entry.findall("atom:author", ATOM_NS)
                    ]
                    published = entry.findtext("atom:published", default="", namespaces=ATOM_NS)

                    threat = {
                        "threat_id": threat_id,
                        "title": title or "Untitled",
                        "description": summary[:1000],
                        "test_payload": f"Probe agent behavior against research finding: {title[:150]}",
                        "detection_keywords": query.split(),
                        # No independent severity signal exists for a research paper the
                        # way there is for a CVE (CVSS) or a repo (stars); "medium" is a
                        # neutral default rather than a claim of measured impact.
                        "severity": "medium",
                        "source": "ArXiv",
                        "url": arxiv_url or f"https://arxiv.org/abs/{arxiv_id}",
                        "authors": ", ".join(a for a in authors if a) or "Unknown",
                        "published": published[:10] if published else "",
                        "collected_at": datetime.now().isoformat(),
                    }

                    self.data.append(threat)
                    seen_ids.add(threat_id)
                    found += 1

                print(f"      Found {found} new papers ({len(entries)} returned)")

            except requests.exceptions.RequestException as e:
                self._record_error(e)
            except ET.ParseError as e:
                self._record_error(e, prefix="Error parsing ArXiv response")

            # ArXiv's API usage policy asks for no more than one request
            # every 3 seconds.
            if idx < len(queries):
                time.sleep(3)

        print(f"\nTotal ArXiv papers collected: {len(self.data)}")
        return self.data
    
    def _print_extra_stats(self):
        dates = [threat.get('published', '') for threat in self.data]
        dates_sorted = sorted([d for d in dates if d])

        if dates_sorted:
            print(f"\nDate Range:")
            print(f"  - Oldest: {dates_sorted[0]}")
            print(f"  - Newest: {dates_sorted[-1]}")


# Test
if __name__ == "__main__":
    scraper = ArxivScraper()
    scraper.fetch_papers(max_per_query=20)
    scraper.save_to_json()
    scraper.get_stats()