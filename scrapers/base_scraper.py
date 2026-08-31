"""
Shared base class for CTI scrapers.

Factors out what's genuinely identical across the 9 active scrapers
(init bookkeeping, save_to_json, the common part of get_stats, and
access to the retry helper) - see Vague 3c diagnostic. Each scraper's
fetch/parse logic stays in the subclass; there's no shared "fetch()"
since the request shape, response format and auth differ per source.
"""

import json
import os

from core.retry import request_with_retry as _request_with_retry


class BaseScraper:
    """Common bookkeeping and stats/persistence for CTI scrapers"""

    #: Human-readable label used in the "=== X SCRAPER STATS ===" banner
    #: and the "Saved N <ITEM_LABEL> to <file>" message. Subclasses must
    #: set this.
    SOURCE_NAME = "SCRAPER"

    #: Plural noun describing one collected item, used in the save
    #: confirmation message (e.g. "CVEs with test payloads", "ArXiv papers").
    ITEM_LABEL = "items"

    #: Default output path for save_to_json() when no filename is given.
    DEFAULT_OUTPUT_FILE = None

    def __init__(self, base_url=None):
        self.base_url = base_url
        self.data = []
        self.error_count = 0

    def request_with_retry(self, request_fn, **kwargs):
        """Call request_fn() with exponential-backoff retry (core/retry.py)"""
        return _request_with_retry(request_fn, **kwargs)

    def _record_error(self, error, prefix="Error"):
        """Log a scraper error consistently and bump the error counter"""
        print(f"      [ERROR] {prefix}: {error}")
        self.error_count += 1

    def save_to_json(self, filename=None):
        """Save collected data to JSON, preserving non-ASCII text as-is"""
        filename = filename or self.DEFAULT_OUTPUT_FILE
        os.makedirs(os.path.dirname(filename) or ".", exist_ok=True)

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)

        print(f"Saved {len(self.data)} {self.ITEM_LABEL} to {filename}")

    def get_stats(self):
        """Print collection statistics: banner, totals, severity breakdown,
        then any scraper-specific extras via _print_extra_stats()"""
        print(f"\n=== {self.SOURCE_NAME} SCRAPER STATS ===")
        print(f"Total collected: {len(self.data)}")
        print(f"Errors: {self.error_count}")

        if not self.data:
            return

        severity_count = {}
        for threat in self.data:
            severity = threat.get("severity", "unknown")
            severity_count[severity] = severity_count.get(severity, 0) + 1

        print("\nBy Severity:")
        for severity, count in sorted(severity_count.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {severity:<10} : {count}")

        self._print_extra_stats()

    def _print_extra_stats(self):
        """Hook for scraper-specific stats beyond the severity breakdown.
        No-op by default; overridden by scrapers that have real extra
        fields to report (e.g. GitHub stars/languages, MITRE tactics)."""
        pass
