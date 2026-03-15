"""
ArXiv Scraper
Collecte les papers de recherche sur la sécurité des LLM/Agents
"""

import requests
import xml.etree.ElementTree as ET
from datetime import datetime
import json

class ArxivScraper:
    """
    Scrapes ArXiv papers related to LLM/AI agent security
    Uses official ArXiv API (very reliable, no auth needed)
    """
    
    def __init__(self):
        self.base_url = "http://export.arxiv.org/api/query"
        self.data = []
        self.error_count = 0
    
    def fetch_papers(self, queries=None, max_per_query=30):
        """
        Fetch papers from ArXiv
        
        Args:
            queries (list): Search queries
            max_per_query (int): Max papers per query
            
        Returns:
            list: List of threat objects (papers)
        """
        
        if queries is None:
            queries = [
                "prompt injection",
                "jailbreak language model",
                "llm security",
                "adversarial attack language model",
                "agent safety"
            ]
        
        print(f"📚 Searching ArXiv for papers ({len(queries)} queries)...")
        
        for query in queries:
            print(f"   └─ Searching: '{query}'...")
            
            try:
                params = {
                    "search_query": f"(cat:cs.CY OR cat:cs.CR OR cat:cs.AI) AND {query}",
                    "sortBy": "submittedDate",
                    "sortOrder": "descending",
                    "max_results": max_per_query
                }
                
                response = requests.get(
                    self.base_url,
                    params=params,
                    timeout=15
                )
                response.raise_for_status()
                
                # Parse XML response
                root = ET.fromstring(response.content)
                ns = {'atom': 'http://www.w3.org/2005/Atom'}
                
                entries = root.findall('atom:entry', ns)
                
                for entry in entries:
                    try:
                        paper_id = entry.find('atom:id', ns).text.split('/abs/')[-1]
                        title = entry.find('atom:title', ns).text.replace('\n', ' ').strip()
                        summary = entry.find('atom:summary', ns).text.replace('\n', ' ').strip()
                        published = entry.find('atom:published', ns).text
                        
                        # Get authors
                        authors = []
                        for author in entry.findall('atom:author', ns):
                            author_name = author.find('atom:name', ns)
                            if author_name is not None:
                                authors.append(author_name.text)
                        
                        threat = {
                            "threat_id": f"ARX-{paper_id}",
                            "title": title,
                            "description": summary[:500],  # First 500 chars
                            "authors": ", ".join(authors[:3]),  # First 3 authors
                            "url": f"https://arxiv.org/abs/{paper_id}",
                            "published": published,
                            "source": "ArXiv",
                            "collected_at": datetime.now().isoformat(),
                        }
                        
                        self.data.append(threat)
                    
                    except Exception as e:
                        self.error_count += 1
                        continue
                
                print(f"      ✅ Found {len(entries)} papers")
                
            except requests.exceptions.RequestException as e:
                print(f"      ❌ Error: {e}")
                self.error_count += 1
        
        print(f"\n✅ Total ArXiv papers collected: {len(self.data)}")
        return self.data
    
    def save_to_json(self, filename='data/raw_arxiv.json'):
        """Save collected papers to JSON file"""
        
        import os
        os.makedirs(os.path.dirname(filename) or '.', exist_ok=True)
        
        with open(filename, 'w') as f:
            json.dump(self.data, f, indent=2)
        
        print(f"💾 Saved {len(self.data)} ArXiv papers to {filename}")
    
    def get_stats(self):
        """Print collection statistics"""
        
        print("\n=== ARXIV SCRAPER STATS ===")
        print(f"Total collected: {len(self.data)}")
        print(f"Errors: {self.error_count}")
        
        if len(self.data) > 0:
            # Date range
            dates = [threat.get('published', '')[:10] for threat in self.data]
            dates_sorted = sorted(dates)
            print(f"\nDate range:")
            print(f"  - Oldest: {dates_sorted[0]}")
            print(f"  - Newest: {dates_sorted[-1]}")


# Test
if __name__ == "__main__":
    scraper = ArxivScraper()
    scraper.fetch_papers(max_per_query=20)
    scraper.save_to_json()
    scraper.get_stats()