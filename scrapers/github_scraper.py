"""
GitHub Scraper - Real GitHub API
Scrapes ACTUAL GitHub repositories related to security
Uses official GitHub API (100% FREE)
"""

import requests
from datetime import datetime

from scrapers.base_scraper import BaseScraper

class GitHubScraper(BaseScraper):
    """
    Scrapes REAL GitHub repositories related to security
    Using official GitHub API (free tier)

    Rate limits:
    - Without token: 60 requests/hour (still FREE!)
    - With token: 5,000 requests/hour (also FREE!)
    """

    SOURCE_NAME = "GITHUB"
    ITEM_LABEL = "GitHub repos with test payloads"
    DEFAULT_OUTPUT_FILE = "data/raw_github.json"

    def __init__(self, token=None):
        """
        Initialize with optional GitHub token

        Args:
            token: GitHub personal access token (free to create at github.com/settings/tokens)
                   If None, uses unauthenticated API (60 req/hour)
        """
        super().__init__(base_url="https://api.github.com")
        self.token = token
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "AgentSecurityFramework"
        }
        if token:
            self.headers["Authorization"] = f"token {token}"
    
    def fetch_exploits(self, queries=None, max_per_query=30):
        """
        Fetch REAL GitHub repos related to security exploits
        
        Args:
            queries: Search queries for exploits
            max_per_query: Max repos per query
            
        Returns:
            list: List of threat objects from real repos
        """
        
        if queries is None:
            queries = [
                "prompt injection attack",
                "llm jailbreak",
                "chatgpt exploit",
                "ai security vulnerability",
                "agent attack"
            ]
        
        print(f"Searching GitHub for exploits ({len(queries)} queries)...")
        
        for idx, query in enumerate(queries, 1):
            print(f"    - Searching: '{query}'...")
            
            try:
                # Search GitHub repos
                search_url = f"{self.base_url}/search/repositories"
                params = {
                    "q": query,
                    "sort": "stars",
                    "order": "desc",
                    "per_page": max_per_query
                }
                
                response = requests.get(
                    search_url,
                    headers=self.headers,
                    params=params,
                    timeout=10
                )
                response.raise_for_status()
                
                results = response.json()
                repos = results.get('items', [])
                
                print(f"      Found {len(repos)} repos")
                
                # Process each repo
                for repo in repos:
                    try:
                        threat = {
                            "threat_id": f"GH-{repo['id']}",
                            "title": repo['name'],
                            "description": repo.get('description', 'No description')[:500] or "Security-related repository",
                            "test_payload": f"Analyze {repo['name']} security implementation",
                            "detection_keywords": query.split(),
                            "severity": self._estimate_severity(repo),
                            "source": "GitHub",
                            "url": repo['html_url'],
                            "stars": repo.get('stargazers_count', 0),
                            "language": repo.get('language', 'Unknown'),
                            "collected_at": datetime.now().isoformat(),
                        }
                        
                        self.data.append(threat)
                    
                    except Exception as e:
                        continue
            
            except requests.exceptions.RequestException as e:
                self._record_error(str(e)[:50])
        
        print(f"\nTotal GitHub repos collected: {len(self.data)}")
        return self.data
    
    def _estimate_severity(self, repo: dict) -> str:
        """
        Estimate severity based on repo characteristics
        
        Higher stars = more widely-known exploit = higher severity
        """
        stars = repo.get('stargazers_count', 0)
        
        if stars > 1000:
            return 'critical'
        elif stars > 500:
            return 'high'
        elif stars > 100:
            return 'medium'
        else:
            return 'low'
    
    def _print_extra_stats(self):
        # Average stars
        avg_stars = sum(t.get('stars', 0) for t in self.data) / len(self.data)
        print(f"\nAverage Stars: {avg_stars:.1f}")

        # Languages
        languages = {}
        for threat in self.data:
            lang = threat.get('language', 'Unknown')
            languages[lang] = languages.get(lang, 0) + 1

        print("\nTop Languages:")
        for lang, count in sorted(languages.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  - {str(lang):<15} : {count}")


# Test
if __name__ == "__main__":
    scraper = GitHubScraper()
    scraper.fetch_exploits(max_per_query=20)
    scraper.save_to_json()
    scraper.get_stats()