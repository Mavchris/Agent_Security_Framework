"""
Complete ETL Pipeline: Scrape → Classify → Store
Enhanced with MITRE ATT&CK, Shodan, and OpenCTI sources
"""

import json
import sqlite3
from datetime import datetime
import sys
import os

# Force UTF-8 output: on Windows, sys.stdout/stderr default to the system
# codepage (cp1252), which cannot encode the emoji used throughout this
# pipeline's console messages. Only reconfigure when run directly
# (python pipeline/process.py) — when imported by orchestrator.py, that
# entry point has already reconfigured the process-wide streams.
if __name__ == "__main__":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scrapers.cve_scraper import CVEScraper
from scrapers.github_scraper import GitHubScraper
from scrapers.arxiv_scraper import ArxivScraper
from scrapers.mitre_scraper import MitreAttackScraper
from scrapers.censys_scraper import CensysScraper
from scrapers.opencti_scraper import OpenCTIScraper
from scrapers.nvd_scraper import NVDScraper
from core.classifier import ImprovedThreatClassifier


def create_database():
    """Create database tables if they don't exist"""
    
    conn = sqlite3.connect('data/threats.db')
    cursor = conn.cursor()
    
    # Create threats table with extended fields
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_id TEXT UNIQUE,
        title TEXT,
        description TEXT,
        test_payload TEXT,
        detection_keywords TEXT,
        threat_type TEXT,
        severity TEXT,
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
    1. Scrape from 6 sources
    2. Classify each threat
    3. Store in database
    """
    
    print("=" * 70)
    print("🚀 STARTING AGENT SECURITY INTELLIGENCE PIPELINE (ENHANCED)")
    print("=" * 70)
    
    # Create database
    create_database()
    
    # STEP 1: SCRAPE FROM ALL SOURCES
    print("\n[STEP 1/3] SCRAPING FROM ALL SOURCES (7 SOURCES)...")
    print("-" * 70)
    
    all_threats = []
    source_counts = {}
    
    # CVE Scraper
    print("\n🔍 CVE Scraper...")
    try:
        cve_scraper = CVEScraper()
        cve_threats = cve_scraper.fetch_cves(max_results=100)
        cve_scraper.save_to_json()
        all_threats.extend(cve_threats)
        source_counts['CVE'] = len(cve_threats)
        print(f"   ✅ Collected {len(cve_threats)} CVE threats")
    except Exception as e:
        print(f"   ❌ Error: {e}")
        source_counts['CVE'] = 0
    
    # GitHub Scraper
    print("\n🔍 GitHub Scraper...")
    try:
        github_scraper = GitHubScraper()
        github_threats = github_scraper.fetch_exploits(max_per_query=25)
        github_scraper.save_to_json()
        all_threats.extend(github_threats)
        source_counts['GitHub'] = len(github_threats)
        print(f"   ✅ Collected {len(github_threats)} GitHub threats")
    except Exception as e:
        print(f"   ❌ Error: {e}")
        source_counts['GitHub'] = 0
    
    # ArXiv Scraper
    print("\n📚 ArXiv Scraper...")
    try:
        arxiv_scraper = ArxivScraper()
        arxiv_threats = arxiv_scraper.fetch_papers(max_per_query=20)
        arxiv_scraper.save_to_json()
        all_threats.extend(arxiv_threats)
        source_counts['ArXiv'] = len(arxiv_threats)
        print(f"   ✅ Collected {len(arxiv_threats)} ArXiv threats")
    except Exception as e:
        print(f"   ❌ Error: {e}")
        source_counts['ArXiv'] = 0
    
    # MITRE ATT&CK Scraper
    print("\n🎯 MITRE ATT&CK Scraper...")
    try:
        mitre_scraper = MitreAttackScraper()
        mitre_threats = mitre_scraper.fetch_techniques(max_results=50)
        mitre_scraper.save_to_json()
        all_threats.extend(mitre_threats)
        source_counts['MITRE ATT&CK'] = len(mitre_threats)
        print(f"   ✅ Collected {len(mitre_threats)} MITRE ATT&CK techniques")
    except Exception as e:
        print(f"   ❌ Error: {e}")
        source_counts['MITRE ATT&CK'] = 0
    
    # Censys Scraper
    print("\n🔍 Censys Scraper...")
    try:
        censys_scraper = CensysScraper()
        censys_threats = censys_scraper.fetch_exposures(max_per_query=10)
        censys_scraper.save_to_json()
        all_threats.extend(censys_threats)
        source_counts['Censys'] = len(censys_threats)
        print(f"   ✅ Collected {len(censys_threats)} Censys exposures")
    except Exception as e:
        print(f"   ❌ Error: {e}")
        source_counts['Censys'] = 0
    
    # NVD Scraper
    print("\n🛡️ NVD Scraper...")
    try:
        nvd_scraper = NVDScraper()
        nvd_threats = nvd_scraper.fetch_cves(max_results=100)
        nvd_scraper.save_to_json()
        all_threats.extend(nvd_threats)
        source_counts['NVD'] = len(nvd_threats)
        print(f"   ✅ Collected {len(nvd_threats)} NVD threats")
    except Exception as e:
        print(f"   ❌ Error: {e}")
        source_counts['NVD'] = 0

    # OpenCTI Scraper
    print("\n🌐 OpenCTI Scraper...")
    try:
        opencti_scraper = OpenCTIScraper()
        opencti_threats = opencti_scraper.fetch_threats(max_results=50)
        opencti_scraper.save_to_json()
        all_threats.extend(opencti_threats)
        source_counts['OpenCTI'] = len(opencti_threats)
        print(f"   ✅ Collected {len(opencti_threats)} OpenCTI threats")
    except Exception as e:
        print(f"   ❌ Error: {e}")
        source_counts['OpenCTI'] = 0
    
    print(f"\n✅ SCRAPING COMPLETE")
    print(f"   Total threats collected: {len(all_threats)}")
    print(f"\n   Sources breakdown:")
    for source, count in sorted(source_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"      - {source:<20} : {count:3d}")
    
    # STEP 2: CLASSIFY
    print("\n[STEP 2/3] CLASSIFYING THREATS...")
    print("-" * 70)
    
    classifier = ImprovedThreatClassifier()
    
    classified_threats = []
    for threat in all_threats:
        # Use the improved classifier with dict input
        threat_type = classifier.classify(threat)
        threat['threat_type'] = threat_type
        classified_threats.append(threat)
    
    # Count by type
    types_count = {}
    for threat in classified_threats:
        t = threat.get('threat_type', 'other')
        types_count[t] = types_count.get(t, 0) + 1
    
    print(f"✅ CLASSIFICATION COMPLETE")
    print(f"   Total classified: {len(classified_threats)}")
    print(f"\n   Distribution:")
    for threat_type, count in sorted(types_count.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / len(classified_threats)) * 100 if classified_threats else 0
        print(f"      - {threat_type:<25} : {count:3d} ({percentage:5.1f}%)")
    
    # STEP 3: STORE IN DATABASE
    print("\n[STEP 3/3] STORING IN DATABASE...")
    print("-" * 70)
    
    conn = sqlite3.connect('data/threats.db')
    cursor = conn.cursor()
    
    success = 0
    duplicates = 0
    
    for threat in classified_threats:
        try:
            # Prepare data
            threat_id = threat.get('threat_id', 'UNKNOWN-' + str(success))
            title = threat.get('title', '')[:200]
            description = (threat.get('description', '') or '')[:1000]
            test_payload = (threat.get('test_payload', '') or '')[:500]
            detection_keywords = json.dumps(threat.get('detection_keywords', []))
            threat_type = threat.get('threat_type', 'other')
            severity = threat.get('severity', 'unknown')
            source = threat.get('source', 'Unknown')
            url = threat.get('url', '')
            collected_at = threat.get('collected_at', datetime.now().isoformat())
            
            cursor.execute('''
            INSERT INTO threats 
            (threat_id, title, description, test_payload, detection_keywords, 
             threat_type, severity, source, url, collected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                threat_id,
                title,
                description,
                test_payload,
                detection_keywords,
                threat_type,
                severity,
                source,
                url,
                collected_at
            ))
            
            success += 1
        
        except sqlite3.IntegrityError:
            duplicates += 1
        except Exception as e:
            print(f"   Error inserting {threat.get('threat_id', 'unknown')}: {e}")
    
    conn.commit()
    conn.close()
    
    print(f"✅ DATABASE STORAGE COMPLETE")
    print(f"   Inserted: {success}")
    print(f"   Duplicates (skipped): {duplicates}")
    
    # FINAL SUMMARY
    print("\n" + "=" * 70)
    print("✅ PIPELINE EXECUTION COMPLETE !")
    print("=" * 70)
    print(f"\n📊 FINAL STATISTICS:")
    print(f"   Total threats: {len(classified_threats)}")
    print(f"   Total stored: {success}")
    print(f"\n   Sources: {', '.join([f'{s}({c})' for s,c in source_counts.items()])}")
    print(f"\n💾 Output files:")
    print(f"   - data/raw_cves.json")
    print(f"   - data/raw_github.json")
    print(f"   - data/raw_arxiv.json")
    print(f"   - data/raw_mitre.json")
    print(f"   - data/raw_nvd.json")
    print(f"   - data/raw_opencti.json")
    print(f"   - data/threats.db")
    print("\n" + "=" * 70)


if __name__ == "__main__":
    run_pipeline()