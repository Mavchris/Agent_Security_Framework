"""
MITRE ATT&CK Scraper - Real Data
Downloads MITRE ATT&CK framework from official GitHub
100% FREE & OPEN SOURCE
"""

import requests
import json
from datetime import datetime

class MitreAttackScraper:
    """
    Scrapes REAL MITRE ATT&CK techniques from official GitHub
    Downloads enterprise-attack.json containing 1000+ techniques
    100% free, no authentication needed
    """
    
    def __init__(self):
        # Official MITRE GitHub repository
        self.base_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack"
        self.data = []
        self.error_count = 0
    
    def fetch_techniques(self, max_results=200):
        """
        Fetch REAL MITRE ATT&CK techniques from official GitHub
        
        Args:
            max_results: Max techniques to collect
            
        Returns:
            list: List of real ATT&CK techniques
        """
        
        print(f"🎯 Fetching REAL MITRE ATT&CK techniques from GitHub...")
        
        try:
            # Download enterprise-attack.json (1000+ techniques)
            url = f"{self.base_url}/enterprise-attack.json"
            
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            
            attack_data = response.json()
            objects = attack_data.get('objects', [])
            
            print(f"   Downloaded {len(objects)} total ATT&CK objects")
            
            # Filter for techniques only
            techniques = [obj for obj in objects if obj.get('type') == 'attack-pattern']
            
            print(f"   Found {len(techniques)} attack techniques\n")
            
            # Process techniques
            count = 0
            for technique in techniques:
                if count >= max_results:
                    break
                
                try:
                    technique_id = technique.get('external_references', [{}])[0].get('external_id', 'UNKNOWN')
                    
                    threat = {
                        "threat_id": f"MITRE-{technique_id}",
                        "title": technique.get('name', 'Unknown')[:100],
                        "description": technique.get('description', '')[:500],
                        "test_payload": f"Test detection for {technique_id}",
                        "detection_keywords": technique.get('x_mitre_detection', '').split()[:5] if technique.get('x_mitre_detection') else [technique_id],
                        "severity": self._get_severity(technique),
                        "source": "MITRE ATT&CK",
                        "url": f"https://attack.mitre.org/techniques/{technique_id}/",
                        "tactic": self._get_tactic(technique),
                        "platforms": technique.get('x_mitre_platforms', []),
                        "collected_at": datetime.now().isoformat(),
                    }
                    
                    self.data.append(threat)
                    count += 1
                    
                    if count % 50 == 0:
                        print(f"   ✓ Processed {count} techniques...")
                
                except Exception as e:
                    continue
            
            print(f"   ✅ Collected {len(self.data)} REAL MITRE ATT&CK techniques\n")
            return self.data
        
        except requests.exceptions.RequestException as e:
            print(f"   ❌ Error fetching MITRE ATT&CK: {e}")
            self.error_count += 1
            return []
    
    def _get_severity(self, technique: dict) -> str:
        """Estimate severity based on technique type"""
        
        # If it affects multiple platforms, it's more critical
        platforms = technique.get('x_mitre_platforms', [])
        
        if len(platforms) >= 3:
            return 'critical'
        elif len(platforms) >= 2:
            return 'high'
        else:
            return 'medium'
    
    def _get_tactic(self, technique: dict) -> str:
        """Extract tactic/phase from technique"""
        
        kill_chain = technique.get('kill_chain_phases', [])
        if kill_chain:
            return kill_chain[0].get('phase_name', 'unknown')
        return 'unknown'
    
    def save_to_json(self, filename='data/raw_mitre.json'):
        """Save collected techniques to JSON"""
        import os
        os.makedirs(os.path.dirname(filename) or '.', exist_ok=True)
        
        with open(filename, 'w') as f:
            json.dump(self.data, f, indent=2)
        
        print(f"💾 Saved {len(self.data)} MITRE ATT&CK techniques to {filename}")
    
    def get_stats(self):
        """Print collection statistics"""
        
        print("\n=== MITRE ATT&CK SCRAPER STATS ===")
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
            
            # Count by tactic
            tactic_count = {}
            for threat in self.data:
                tactic = threat.get('tactic', 'unknown')
                tactic_count[tactic] = tactic_count.get(tactic, 0) + 1
            
            print("\nTop Tactics:")
            for tactic, count in sorted(tactic_count.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"  - {str(tactic):<30} : {count}")


# Test
if __name__ == "__main__":
    scraper = MitreAttackScraper()
    scraper.fetch_techniques(max_results=200)
    scraper.save_to_json()
    scraper.get_stats()