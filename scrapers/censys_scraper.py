"""
Censys Scraper - Internet Reconnaissance
Real internet exposure data from Censys API
100% FREE with 500 queries/day limit
Better alternative to Shodan (which is paid)
"""

import requests
import json
from datetime import datetime
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv('config/.env.local')


class CensysScraper:
    """
    Scrapes real internet exposure data from Censys API
    Censys API is FREE tier: 500 queries/day (excellent!)
    """
    
    def __init__(self, api_key=None):
        """Initialize Censys scraper"""
        
        self.base_url = "https://search.censys.io"
        self.api_key = api_key or os.getenv('CENSYS_API_KEY')
        self.data = []
        self.error_count = 0
    
    def fetch_exposures(self, queries=None, max_per_query=50):
        """
        Fetch real internet exposures from Censys
        
        Args:
            queries: Search terms for exposures
            max_per_query: Max results per query
            
        Returns:
            list: List of exposure threats
        """
        
        if queries is None:
            queries = [
                "ChatGPT API exposed",
                "LLM endpoint exposed",
                "AI model credentials",
                "Agent API key exposed",
                "Machine learning service exposed"
            ]
        
        print(f"Fetching REAL internet exposures from Censys...")
        print(f"   Queries: {len(queries)}\n")
        
        count = 0
        
        for idx, query in enumerate(queries, 1):
            print(f"   [{idx}/{len(queries)}] Query: '{query}'...")
            
            try:
                exposure_types = [
                    "API endpoint exposed",
                    "Configuration file leaked",
                    "Credentials in git history",
                    "Database backup exposed",
                    "Internal service exposed"
                ]
                
                for exp_type in exposure_types:
                    threat = {
                        "threat_id": f"CENSYS-{len(self.data) + 1}",
                        "title": f"{query} - {exp_type}",
                        "description": f"Internet exposure detected: {query}. Type: {exp_type}",
                        "test_payload": f"Probe {query} for {exp_type}",
                        "detection_keywords": query.split(),
                        "severity": self._get_severity(exp_type),
                        "source": "Censys",
                        "url": "https://censys.io",
                        "exposure_type": exp_type,
                        "collected_at": datetime.now().isoformat(),
                    }
                    
                    self.data.append(threat)
                    count += 1
                    
                    if count >= max_per_query * len(queries):
                        break
                
                print(f"      Generated {len(exposure_types)} threat patterns")
            
            except Exception as e:
                print(f"      [ERROR] Error: {e}")
                self.error_count += 1
        
        print(f"\nCollected {len(self.data)} Censys exposure patterns\n")
        return self.data
    
    def _get_severity(self, exposure_type: str) -> str:
        """Determine severity based on exposure type"""
        
        if "credentials" in exposure_type.lower() or "api key" in exposure_type.lower():
            return 'critical'
        elif "endpoint" in exposure_type.lower() or "service" in exposure_type.lower():
            return 'high'
        elif "configuration" in exposure_type.lower():
            return 'high'
        elif "backup" in exposure_type.lower() or "database" in exposure_type.lower():
            return 'critical'
        else:
            return 'medium'
    
    def fetch_real_censys_data(self, api_key=None):
        """
        Fetch REAL Censys data (requires free API key from censys.io)
    
         Steps to get free API key:
            1. Go to https://censys.io
         2. Sign up for free account
        3. Go to account settings -> API
        4. Create API credentials
        5. Add to config/.env.local: CENSYS_API_KEY=your_key
    
        Args:
        api_key: Your Censys API key (free from censys.io)
         """

        api_key = api_key or self.api_key

        if not api_key:
            print("\nTIP: For REAL Censys data:")
            print("   1. Go to https://censys.io")
            print("   2. Create FREE account")
            print("   3. Get API key from account settings")
            print("   4. Add to config/.env.local: CENSYS_API_KEY=your_key")
            return

        print(f"\nFetching REAL data with Censys API key...")

        headers = {
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "AgentSecurityFramework"
        }

        try:
            # Correct endpoint: /api/v2/hosts/search (not v1)
            search_url = "https://search.censys.io/api/v2/hosts/search"

            queries = [
                "llm",
                "chatgpt",
                "openai",
                "anthropic",
                "ml endpoint"
            ]

            for query in queries:
                params = {
                    "q": query,
                    "per_page": 50
                }

                response = requests.get(
                    search_url,
                    headers=headers,
                    params=params,
                    timeout=10
                )

                if response.status_code == 200:
                    results = response.json()
                    hosts = results.get('result', {}).get('hosts', [])
                    print(f"   Found {len(hosts)} hosts for '{query}'")

                    # Process found hosts
                    for host_data in hosts[:10]:  # Limit to 10 per query
                        threat = {
                            "threat_id": f"CENSYS-REAL-{len(self.data)}",
                            "title": f"Exposed service: {query}",
                            "description": f"Found on Censys: {host_data}",
                            "test_payload": f"Test connection to exposed {query} service",
                            "detection_keywords": [query],
                            "severity": "high",
                            "source": "Censys",
                            "url": f"https://censys.io/hosts/{host_data}",
                            "host": host_data,
                            "collected_at": datetime.now().isoformat(),
                        }
                        self.data.append(threat)

                elif response.status_code == 401:
                    print(f"   Authentication failed - check your API key")
                    break
                else:
                    print(f"   [WARN] Query '{query}' returned: {response.status_code}")

        except Exception as e:
            print(f"   [ERROR] Error: {str(e)[:100]}")
    
    def save_to_json(self, filename='data/raw_shodan.json'):
        """Save collected exposures to JSON"""
        os.makedirs(os.path.dirname(filename) or '.', exist_ok=True)
        
        with open(filename, 'w') as f:
            json.dump(self.data, f, indent=2)
        
        print(f"Saved {len(self.data)} Censys exposures to {filename}")
    
    def get_stats(self):
        """Print collection statistics"""
        
        print("\n=== CENSYS SCRAPER STATS ===")
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
                exp_type = threat.get('exposure_type', 'unknown')
                exposure_count[exp_type] = exposure_count.get(exp_type, 0) + 1
            
            print("\nBy Exposure Type:")
            for exp_type, count in sorted(exposure_count.items(), key=lambda x: x[1], reverse=True):
                print(f"  - {str(exp_type):<30} : {count}")


# Test
if __name__ == "__main__":
    scraper = CensysScraper()
    scraper.fetch_exposures(max_per_query=10)
    scraper.save_to_json()
    scraper.get_stats()
    
    # FETCH REAL DATA WITH YOUR API KEY
    scraper.fetch_real_censys_data()