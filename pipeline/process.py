"""
Complete ETL Pipeline: Scrape → Classify → Store
"""

import json
import sqlite3
from datetime import datetime
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scrapers.cve_scraper import CVEScraper
from scrapers.github_scraper import GitHubScraper
from scrapers.arxiv_scraper import ArxivScraper
from core.threat_classifier import ThreatClassifier


def create_database():
    """Create database tables if they don't exist"""
    
    conn = sqlite3.connect('data/threats.db')
    cursor = conn.cursor()
    
    # Create threats table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_id TEXT UNIQUE,
        title TEXT,
        description TEXT,
        threat_type TEXT,
        source TEXT,
        url TEXT,
        collected_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    conn.commit()
    conn.close()
    print("✅ Database tables created/verified")


def run_pipeline():
    """
    Complete ETL pipeline:
    1. Scrape from 3 sources
    2. Classify each threat
    3. Store in database
    """
    
    print("="*60)
    print("🚀 STARTING AGENT SECURITY INTELLIGENCE PIPELINE")
    print("="*60)
    
    # Create database
    create_database()
    
    # STEP 1: SCRAPE FROM ALL SOURCES
    print("\n[STEP 1/3] SCRAPING FROM ALL SOURCES...")
    print("-" * 60)
    
    all_data = []
    
    # CVE Scraper
    print("\n🔍 CVE Scraper...")
    cve_scraper = CVEScraper()
    cve_data = cve_scraper.fetch_cves(max_results=100)
    cve_scraper.save_to_json()
    all_data.extend(cve_data)
    
    # GitHub Scraper
    print("\n🔍 GitHub Scraper...")
    github_scraper = GitHubScraper()
    github_data = github_scraper.fetch_exploits(max_per_query=25)
    github_scraper.save_to_json()
    all_data.extend(github_data)
    
    # ArXiv Scraper
    print("\n🔍 ArXiv Scraper...")
    arxiv_scraper = ArxivScraper()
    arxiv_data = arxiv_scraper.fetch_papers(max_per_query=20)
    arxiv_scraper.save_to_json()
    all_data.extend(arxiv_data)
    
    print(f"\n✅ SCRAPING COMPLETE")
    print(f"   Total threats collected: {len(all_data)}")
    
    # STEP 2: CLASSIFY
    print("\n[STEP 2/3] CLASSIFYING THREATS...")
    print("-" * 60)
    
    classifier = ThreatClassifier()
    
    classified_data = []
    for threat in all_data:
        # Combine title + description for classification
        text = threat.get('title', '') + ' ' + (threat.get('description', '') or '')
        threat_type = classifier.classify(text)
        threat['threat_type'] = threat_type
        classified_data.append(threat)
    
    # Count by type
    types_count = {}
    for threat in classified_data:
        t = threat.get('threat_type', 'other')
        types_count[t] = types_count.get(t, 0) + 1
    
    print(f"✅ CLASSIFICATION COMPLETE")
    print(f"   Total classified: {len(classified_data)}")
    print(f"\n   Distribution:")
    for threat_type, count in sorted(types_count.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / len(classified_data)) * 100
        print(f"      - {threat_type:<25} : {count:3d} ({percentage:5.1f}%)")
    
    # STEP 3: STORE IN DATABASE
    print("\n[STEP 3/3] STORING IN DATABASE...")
    print("-" * 60)
    
    conn = sqlite3.connect('data/threats.db')
    cursor = conn.cursor()
    
    success = 0
    duplicates = 0
    
    for threat in classified_data:
        try:
            cursor.execute('''
        INSERT INTO threats (threat_id, title, description, threat_type, source, url, collected_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
         threat.get('threat_id', ''),
         threat.get('title', '')[:200],
         (threat.get('description', '') or '')[:1000],
         threat.get('threat_type', 'other'),
         threat.get('source', 'Unknown'),
         threat.get('url', ''),
         threat.get('collected_at', datetime.now().isoformat())
        ))
        
        except sqlite3.IntegrityError:
            duplicates += 1
    
    conn.commit()
    conn.close()
    
    print(f"✅ DATABASE STORAGE COMPLETE")
    print(f"   Inserted: {success}")
    print(f"   Duplicates (skipped): {duplicates}")
    
    # FINAL SUMMARY
    print("\n" + "="*60)
    print("✅ PIPELINE EXECUTION COMPLETE !")
    print("="*60)
    print(f"\n📊 FINAL STATISTICS:")
    print(f"   Total threats: {len(classified_data)}")
    print(f"   Sources: CVE ({len(cve_data)}), GitHub ({len(github_data)}), ArXiv ({len(arxiv_data)})")
    print(f"   Stored in DB: {success}")
    print(f"\n💾 Output files:")
    print(f"   - data/raw_cves.json")
    print(f"   - data/raw_github.json")
    print(f"   - data/raw_arxiv.json")
    print(f"   - data/threats.db")
    print("\n" + "="*60)


if __name__ == "__main__":
    run_pipeline()