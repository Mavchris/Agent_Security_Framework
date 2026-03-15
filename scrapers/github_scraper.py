"""
GitHub Scraper
Collecte les repos mentionnant prompt injection, jailbreak, exploits LLM
"""

import requests
import json
from datetime import datetime

class GitHubScraper:
    """
    Scrapes GitHub repos related to LLM exploits/security
    """
    
    def __init__(self, token=None):
        self.base_url = "https://api.github.com"
        self.token = token
        self.headers = {
            "Accept": "application/vnd.github.v3+json"
        }
        if token:
            self.headers["Authorization"] = f"token {token}"
        
        self.data = []
        self.error_count = 0
    
    def fetch_exploits(self, queries=None, max_per_query=30):
        """
        Fetch GitHub repos related to LLM exploits
        
        Args:
            queries (list): Search queries for exploits
            max_per_query (int): Max repos per query
            
        Returns:
            list: List of threat objects
        """
        
        if queries is None:
            queries = [
                "prompt injection",
                "jailbreak llm",
                "llm security",
                "agent attack",
                "ai exploit"
            ]
        
        print(f"🔍 Searching GitHub for exploits ({len(queries)} queries)...")
        
        for query in queries:
            print(f"   └─ Searching: '{query}'...")
            
            try:
                params = {
                    "q": f"{query} stars:>5",
                    "sort": "stars",
                    "order": "desc",
                    "per_page": max_per_query
                }
                
                response = requests.get(
                    f"{self.base_url}/search/repositories",
                    headers=self.headers,
                    params=params,
                    timeout=10
                )
                response.raise_for_status()
                
                results = response.json()
                
                for repo in results.get('items', []):
                    threat = {
                        "threat_id": f"GH-{repo['id']}",
                        "title": repo['name'],
                        "description": repo.get('description', ''),
                        "url": repo['html_url'],
                        "stars": repo['stargazers_count'],
                        "language": repo.get('language', 'Unknown'),
                        "source": "GitHub",
                        "collected_at": datetime.now().isoformat(),
                    }
                    
                    self.data.append(threat)
                
                print(f"      ✅ Found {len(results.get('items', []))} repos")
                
            except requests.exceptions.RequestException as e:
                print(f"      ❌ Error: {e}")
                self.error_count += 1
        
        print(f"\n✅ Total GitHub repos collected: {len(self.data)}")
        return self.data
    
    def save_to_json(self, filename='data/raw_github.json'):
        """Save collected repos to JSON file"""
        
        import os
        os.makedirs(os.path.dirname(filename) or '.', exist_ok=True)
        
        with open(filename, 'w') as f:
            json.dump(self.data, f, indent=2)
        
        print(f"💾 Saved {len(self.data)} GitHub repos to {filename}")
    
    def get_stats(self):
        """Print collection statistics"""
        
        print("\n=== GITHUB SCRAPER STATS ===")
        print(f"Total collected: {len(self.data)}")
        print(f"Errors: {self.error_count}")
        
        if len(self.data) > 0:
            print(f"\nTop languages:")
            languages = {}
            for threat in self.data:
                lang = threat.get('language', 'Unknown')
                languages[lang] = languages.get(lang, 0) + 1
            
            for lang, count in sorted(languages.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"  - {lang}: {count}")


# Test
if __name__ == "__main__":
    scraper = GitHubScraper()
    scraper.fetch_exploits(max_per_query=20)
    scraper.save_to_json()
    scraper.get_stats()