"""
NVD Scraper - National Vulnerability Database
Scrapes real CVE data from NIST NVD
100% FREE API - No authentication required
"""

import requests
from datetime import datetime

from scrapers.base_scraper import BaseScraper

class NVDScraper(BaseScraper):
    """
    Scrapes real CVE data from NVD API
    Focus on CVEs related to LLM/AI agents
    """

    SOURCE_NAME = "NVD"
    ITEM_LABEL = "NVD CVEs"
    DEFAULT_OUTPUT_FILE = "data/raw_nvd.json"

    def __init__(self):
        super().__init__(base_url="https://services.nvd.nist.gov/rest/json/cves/2.0")
    
    def fetch_cves(self, keywords=None, max_results=100):
        """
        Fetch REAL CVEs from NVD API
        Élargi pour capturer plus de menaces potentielles
        """
        
        if keywords is None:
            # Keywords plus larges
            keywords = [
                "injection", "bypass", "authentication", 
                "code execution", "rce", "access control",
                "information disclosure", "dos", "remote"
            ]
        
        print(f"Fetching REAL CVEs from NVD API...")
        print(f"   Keywords: {', '.join(keywords[:5])}...\n")
        
        params = {
            "startIndex": 0,
            "resultsPerPage": 200  # Fetch max 200 at once
        }
        
        try:
            response = requests.get(self.base_url, params=params, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            
            print(f"   Found {len(vulnerabilities)} CVEs from NVD")
            
            # Process ALL vulnerabilities (not just filtered)
            count = 0
            for vuln in vulnerabilities:
                if count >= max_results:
                    break
                
                try:
                    cve_id = vuln.get('cve', {}).get('id', '')
                    
                    # Get description
                    descriptions = vuln.get('cve', {}).get('descriptions', [])
                    description = ""
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')
                            break
                    
                    if not description:
                        continue
                    
                    # Create threat object
                    threat = {
                        "threat_id": f"NVD-{cve_id}",
                        "title": cve_id,
                        "description": description[:500],
                        "test_payload": f"Test mitigation for {cve_id}",
                        "detection_keywords": [cve_id],  # Use CVE ID as keyword
                        "severity": self._get_severity(vuln),
                        "source": "NVD",
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        "collected_at": datetime.now().isoformat(),
                    }
                    
                    self.data.append(threat)
                    count += 1
                    
                    if count % 20 == 0:
                        print(f"   Processed {count} CVEs...")
                
                except Exception as e:
                    continue
            
            print(f"   Collected {len(self.data)} REAL NVD CVEs\n")
            return self.data
        
        except requests.exceptions.RequestException as e:
            self._record_error(e, prefix="Error fetching from NVD")
            return []
    
    def _get_severity(self, vuln: dict) -> str:
        """Extract severity from NVD data"""
        
        metrics = vuln.get('cve', {}).get('metrics', {})
        
        # Try CVSS v3.1 first
        cvss_v3 = metrics.get('cvssMetricV31', [])
        if cvss_v3:
            severity = cvss_v3[0].get('cvssData', {}).get('baseSeverity', 'medium')
            return severity.lower()
        
        # Fallback to CVSS v3.0
        cvss_v3_0 = metrics.get('cvssMetricV30', [])
        if cvss_v3_0:
            severity = cvss_v3_0[0].get('cvssData', {}).get('baseSeverity', 'medium')
            return severity.lower()
        
        return 'unknown'
    


# Test
if __name__ == "__main__":
    scraper = NVDScraper()
    scraper.fetch_cves(max_results=100)
    scraper.save_to_json()
    scraper.get_stats()