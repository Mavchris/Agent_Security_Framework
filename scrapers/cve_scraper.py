"""
CVE Scraper with Test Payloads
Collects CVEs for AI/LLM vendors and products via the CIRCL cve-search
public API (cve.circl.lu) - free, no authentication required.
Each CVE includes test_payload and detection_keywords for testing
"""

import requests
import json
from datetime import datetime
import time

# CVSS baseSeverity values are already uppercase words (LOW/MEDIUM/HIGH/CRITICAL);
# normalize to the lowercase convention used across this project.
_CVSS_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")


class CVEScraper:
    def __init__(self):
        self.base_url = "https://cve.circl.lu/api/search"
        self.data = []
        self.error_count = 0

    def fetch_cves(self, keywords=None, max_results=50):
        """
        Fetch real CVEs for AI/LLM vendor-product pairs from cve.circl.lu

        Args:
            keywords (list): vendor/product pairs as "vendor/product" strings.
                Defaults to a curated list of AI vendors and their products.
            max_results (int): Maximum number of CVEs to fetch

        Returns:
            list: List of CVE threat objects with test payloads
        """

        if keywords is None:
            keywords = [
                "openai/chatgpt",
                "anthropic/claude",
                "google/gemini",
                "meta/llama",
                "microsoft/copilot",
                "huggingface/transformers",
            ]

        print(f"🔍 Fetching CVEs with Test Payloads (limit: {max_results})...")
        print(f"   Keywords: {', '.join(keywords[:3])}...")

        seen_ids = {threat["threat_id"] for threat in self.data}

        for idx, pair in enumerate(keywords, 1):
            vendor, _, product = pair.partition("/")
            if not product:
                continue

            print(f"   └─ Searching: '{vendor}/{product}'...")

            try:
                response = requests.get(
                    f"{self.base_url}/{vendor}/{product}",
                    timeout=10,
                )
                response.raise_for_status()

                results = response.json().get("results", {})
                records = [rec for source in results.values() for _, rec in source]
                found = 0

                for record in records:
                    if len(seen_ids) >= max_results:
                        break

                    cve_id = record.get("cveMetadata", {}).get("cveId")
                    if not cve_id or cve_id in seen_ids:
                        continue

                    threat = self._to_threat(record, cve_id, vendor, product)
                    self.data.append(threat)
                    seen_ids.add(cve_id)
                    found += 1

                print(f"      ✅ Found {found} new CVEs ({len(records)} returned)")

            except requests.exceptions.RequestException as e:
                print(f"      ❌ Error: {e}")
                self.error_count += 1

            # Be a reasonable citizen of a free public API.
            if idx < len(keywords):
                time.sleep(1)

        print(f"✅ Collected {len(self.data)} CVE threats with test payloads")
        return self.data

    @staticmethod
    def _to_threat(record, cve_id, vendor, product):
        """Convert a CIRCL/CVE_RECORD-shaped record into this project's threat schema"""

        cna = record.get("containers", {}).get("cna", {})
        descriptions = cna.get("descriptions", [])
        description = descriptions[0]["value"] if descriptions else "No description available"

        severity = "unknown"
        metric_sources = list(cna.get("metrics", []))
        for adp in record.get("containers", {}).get("adp", []):
            metric_sources.extend(adp.get("metrics", []))
        for metric in metric_sources:
            for key in _CVSS_KEYS:
                if key in metric and "baseSeverity" in metric[key]:
                    severity = metric[key]["baseSeverity"].lower()
                    break
            if severity != "unknown":
                break

        references = cna.get("references", [])
        url = references[0]["url"] if references else f"https://www.cve.org/CVERecord?id={cve_id}"

        title_snippet = description[:80].rsplit(" ", 1)[0] if len(description) > 80 else description
        return {
            "threat_id": cve_id,
            "title": f"{cve_id}: {title_snippet}",
            "description": description[:1000],
            "test_payload": f"Verify agent resilience to known issue: {description[:150]}",
            "detection_keywords": [vendor, product],
            "severity": severity,
            "source": "CVE",
            "url": url,
            "published": record.get("cveMetadata", {}).get("datePublished", "")[:10],
            "collected_at": datetime.now().isoformat(),
        }
    
    def save_to_json(self, filename='data/raw_cves.json'):
        """Save collected data to JSON"""
        import os
        os.makedirs(os.path.dirname(filename) or '.', exist_ok=True)
        
        with open(filename, 'w') as f:
            json.dump(self.data, f, indent=2)
        print(f"💾 Saved {len(self.data)} CVEs with test payloads to {filename}")
    
    def get_stats(self):
        """Print collection statistics"""
        
        print("\n=== CVE SCRAPER STATS ===")
        print(f"Total collected: {len(self.data)}")
        print(f"Errors: {self.error_count}")
        
        if len(self.data) + self.error_count > 0:
            success_rate = (len(self.data) / (len(self.data) + self.error_count)) * 100
            print(f"Success rate: {success_rate:.1f}%")
        
        # Count by severity
        severity_count = {}
        for threat in self.data:
            severity = threat.get('severity', 'unknown')
            severity_count[severity] = severity_count.get(severity, 0) + 1
        
        print("\nBy Severity:")
        for severity, count in sorted(severity_count.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {severity:<10} : {count}")


# Test
if __name__ == "__main__":
    scraper = CVEScraper()
    scraper.fetch_cves(max_results=100)
    scraper.save_to_json()
    scraper.get_stats()