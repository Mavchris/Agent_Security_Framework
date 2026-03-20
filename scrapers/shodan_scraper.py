"""
Shodan Scraper
Collects information about compromised/exposed agents
Shodan is a search engine for internet-connected devices
"""

import json
from datetime import datetime

class ShodanScraper:
    """
    Scrapes Shodan for information about exposed AI agents
    Focus on misconfigurations and exposures
    """
    
    def __init__(self):
        self.base_url = "https://www.shodan.io"
        self.data = []
        self.error_count = 0
    
    def fetch_exposures(self, max_results=50):
        """
        Fetch information about exposed AI agents and APIs
        
        Args:
            max_results (int): Max findings to collect
            
        Returns:
            list: List of threat objects
        """
        
        print(f"🔍 Fetching Shodan exposures (limit: {max_results})...")
        
        # Mock Shodan data (in real scenario, would use Shodan API with key)
        mock_shodan_findings = [
            {
                "finding_id": "SHODAN-001",
                "title": "Exposed LLM API without authentication",
                "description": "OpenAI-like API exposed publicly without API key requirement",
                "test_payload": "Try to access API without authentication headers",
                "detection_keywords": ["exposed", "unauthenticated", "api", "public"],
                "severity": "critical",
                "exposure_type": "Authentication"
            },
            {
                "finding_id": "SHODAN-002",
                "title": "LLM Agent with verbose error messages",
                "description": "Agent reveals internal structure in error responses",
                "test_payload": "Send malformed requests to trigger verbose errors",
                "detection_keywords": ["error disclosure", "verbose", "information leak"],
                "severity": "high",
                "exposure_type": "Information Disclosure"
            },
            {
                "finding_id": "SHODAN-003",
                "title": "Unencrypted agent communication",
                "description": "Agent API exposed over HTTP instead of HTTPS",
                "test_payload": "Monitor network traffic for unencrypted prompts",
                "detection_keywords": ["http", "unencrypted", "mitm", "sniffing"],
                "severity": "critical",
                "exposure_type": "Encryption"
            },
            {
                "finding_id": "SHODAN-004",
                "title": "Agent with default credentials",
                "description": "Agent accessible with default username/password",
                "test_payload": "Attempt login with common default credentials",
                "detection_keywords": ["default credentials", "weak password"],
                "severity": "critical",
                "exposure_type": "Weak Credentials"
            },
            {
                "finding_id": "SHODAN-005",
                "title": "Debug mode enabled in production",
                "description": "Agent running with debug/verbose logging enabled",
                "test_payload": "Check for debug endpoints and verbose logging",
                "detection_keywords": ["debug", "verbose logging", "dev mode"],
                "severity": "high",
                "exposure_type": "Configuration"
            },
            {
                "finding_id": "SHODAN-006",
                "title": "Missing rate limiting on agent",
                "description": "Agent API has no rate limiting protection",
                "test_payload": "Send rapid requests to agent API",
                "detection_keywords": ["rate limit", "dos", "brute force"],
                "severity": "high",
                "exposure_type": "DoS"
            },
            {
                "finding_id": "SHODAN-007",
                "title": "Agent exposes internal IP addresses",
                "description": "Agent responses reveal internal network IPs",
                "test_payload": "Analyze responses for internal IP patterns",
                "detection_keywords": ["internal ip", "172.16", "192.168", "10.0"],
                "severity": "medium",
                "exposure_type": "Information Disclosure"
            },
            {
                "finding_id": "SHODAN-008",
                "title": "Outdated agent framework version",
                "description": "Agent running known vulnerable version",
                "test_payload": "Check version headers and fingerprint agent",
                "detection_keywords": ["outdated", "vulnerable", "version"],
                "severity": "high",
                "exposure_type": "Patching"
            },
        ]
        
        print(f"🔍 Processing {len(mock_shodan_findings)} Shodan findings...")
        
        for finding in mock_shodan_findings[:max_results]:
            threat = {
                "threat_id": finding['finding_id'],
                "title": finding['title'],
                "description": finding['description'],
                "test_payload": finding['test_payload'],
                "detection_keywords": finding['detection_keywords'],
                "severity": finding['severity'],
                "source": "Shodan",
                "url": "https://www.shodan.io",
                "exposure_type": finding['exposure_type'],
                "collected_at": datetime.now().isoformat(),
            }
            
            self.data.append(threat)
        
        print(f"✅ Collected {len(self.data)} Shodan exposures")
        return self.data
    
    def save_to_json(self, filename='data/raw_shodan.json'):
        """Save collected findings to JSON"""
        import os
        os.makedirs(os.path.dirname(filename) or '.', exist_ok=True)
        
        with open(filename, 'w') as f:
            json.dump(self.data, f, indent=2)
        
        print(f"💾 Saved {len(self.data)} Shodan findings to {filename}")
    
    def get_stats(self):
        """Print collection statistics"""
        
        print("\n=== SHODAN SCRAPER STATS ===")
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
            
            # Count by exposure type
            exposure_count = {}
            for threat in self.data:
                exposure = threat.get('exposure_type', 'unknown')
                exposure_count[exposure] = exposure_count.get(exposure, 0) + 1
            
            print("\nBy Exposure Type:")
            for exposure, count in sorted(exposure_count.items(), key=lambda x: x[1], reverse=True):
                print(f"  - {exposure:<30} : {count}")


# Test
if __name__ == "__main__":
    scraper = ShodanScraper()
    scraper.fetch_exposures(max_results=50)
    scraper.save_to_json()
    scraper.get_stats()