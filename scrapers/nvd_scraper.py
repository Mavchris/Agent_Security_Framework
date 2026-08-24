"""
NVD Scraper - National Vulnerability Database
Scrapes real CVE data from NIST NVD
100% FREE API - No authentication required
"""

import requests
import json
from datetime import datetime

class NVDScraper:
    """
    Scrapes real CVE data from NVD API
    Focus on CVEs related to LLM/AI agents
    """
    
    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.data = []
        self.error_count = 0
    
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
            print(f"   [ERROR] Error fetching from NVD: {e}")
            self.error_count += 1
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
    
    def save_to_json(self, filename='data/raw_nvd.json'):
        """Save collected CVEs to JSON"""
        import os
        os.makedirs(os.path.dirname(filename) or '.', exist_ok=True)
        
        with open(filename, 'w') as f:
            json.dump(self.data, f, indent=2)
        
        print(f"Saved {len(self.data)} NVD CVEs to {filename}")
    
    def get_stats(self):
        """Print collection statistics"""
        
        print("\n=== NVD SCRAPER STATS ===")
        print(f"Total collected: {len(self.data)}")
        print(f"Errors: {self.error_count}")
        
        if len(self.data) > 0:
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
    scraper = NVDScraper()
    scraper.fetch_cves(max_results=100)
    scraper.save_to_json()
    scraper.get_stats()