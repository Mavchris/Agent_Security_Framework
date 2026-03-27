"""
Agent Vulnerability Scanner
Like Nessus/Nmap but for AI Agents
"""

import sqlite3
import json
from datetime import datetime

class AgentVulnerabilityScanner:
    """
    Complete vulnerability scanner for AI agents
    Tests agent against all threats and generates report
    """
    
    def __init__(self, agent, db_path='data/threats.db'):
        self.agent = agent
        self.db_path = db_path
        self.results = {
            'total_threats': 0,
            'vulnerabilities': [],
            'safe_threats': [],
            'by_type': {},
            'by_severity': {},
            'vulnerability_score': 0.0,
            'timestamp': datetime.now().isoformat()
        }
    
    def load_threats(self):
        """Load all threats from database"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # ← ADD THIS LINE
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM threats')
        threats = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return threats
    
    def test_threat(self, threat):
        """Test single threat against agent"""
        test_payload = threat.get('test_payload', '')
        if not test_payload:
            return None
        
        try:
            # Query agent with payload
            response = self.agent.query(test_payload)
            
            # Check if detection keywords found in response
            keywords = threat.get('detection_keywords', [])
            if isinstance(keywords, str):
                try:
                    keywords = json.loads(keywords)
                except:
                    keywords = []
            
            detected = any(
                kw.lower() in response.lower() 
                for kw in keywords
            )
            
            return {
                'threat_id': threat['threat_id'],
                'title': threat['title'],
                'type': threat['threat_type'],
                'severity': threat.get('severity', 'unknown'),
                'detected': detected,  # True = SAFE, False = VULNERABLE
                'response': response[:100]  # First 100 chars
            }
        except Exception as e:
            return {
                'threat_id': threat['threat_id'],
                'title': threat['title'],
                'type': threat['threat_type'],
                'severity': threat.get('severity', 'unknown'),
                'detected': False,
                'error': str(e)
            }
    
    def scan_all_threats(self, verbose=True):
        """Scan agent against ALL threats"""
        threats = self.load_threats()
        self.results['total_threats'] = len(threats)
        
        if verbose:
            print(f"\n🔍 Scanning {len(threats)} threats...\n")
        
        for idx, threat in enumerate(threats, 1):
            result = self.test_threat(threat)
            if result:
                # Categorize result
                if result['detected']:
                    self.results['safe_threats'].append(result)
                else:
                    self.results['vulnerabilities'].append(result)
                
                # Count by type
                threat_type = result['type']
                if threat_type not in self.results['by_type']:
                    self.results['by_type'][threat_type] = {
                        'total': 0,
                        'vulnerable': 0
                    }
                self.results['by_type'][threat_type]['total'] += 1
                if not result['detected']:
                    self.results['by_type'][threat_type]['vulnerable'] += 1
                
                # Count by severity
                severity = result['severity']
                if severity not in self.results['by_severity']:
                    self.results['by_severity'][severity] = {
                        'total': 0,
                        'vulnerable': 0
                    }
                self.results['by_severity'][severity]['total'] += 1
                if not result['detected']:
                    self.results['by_severity'][severity]['vulnerable'] += 1
            
            # Progress
            if verbose and idx % 25 == 0:
                progress = (idx / len(threats)) * 100
                print(f"  ⏳ {progress:.0f}% ({idx}/{len(threats)})")
        
        # Calculate vulnerability score
        if self.results['total_threats'] > 0:
            vuln_count = len(self.results['vulnerabilities'])
            self.results['vulnerability_score'] = (
                vuln_count / self.results['total_threats'] * 100
            )
        
        if verbose:
            print(f"✅ Scan complete!\n")
        
        return self.results
    
    def print_summary(self):
        """Print scan summary to console"""
        print("\n" + "="*70)
        print("AGENT VULNERABILITY SCAN REPORT")
        print("="*70 + "\n")
        
        # Header
        print(f"Timestamp: {self.results['timestamp']}")
        print(f"Total Threats: {self.results['total_threats']}")
        print(f"Vulnerabilities Found: {len(self.results['vulnerabilities'])}")
        print(f"Safe Threats: {len(self.results['safe_threats'])}")
        print(f"\n🚨 VULNERABILITY SCORE: {self.results['vulnerability_score']:.1f}%\n")
        
        # By Type
        print("VULNERABILITIES BY THREAT TYPE:")
        print("-" * 70)
        if self.results['by_type']:
            for ttype in sorted(self.results['by_type'].keys()):
                stats = self.results['by_type'][ttype]
                pct = (stats['vulnerable'] / stats['total'] * 100) if stats['total'] > 0 else 0
                bar = "█" * int(pct / 5)
                print(f"{ttype:<25} : {stats['vulnerable']:2d}/{stats['total']:3d} ({pct:5.1f}%) {bar}")
        
        # By Severity
        print("\nVULNERABILITIES BY SEVERITY:")
        print("-" * 70)
        if self.results['by_severity']:
            for severity in sorted(self.results['by_severity'].keys()):
                stats = self.results['by_severity'][severity]
                pct = (stats['vulnerable'] / stats['total'] * 100) if stats['total'] > 0 else 0
                bar = "█" * int(pct / 5)
                print(f"{severity:<25} : {stats['vulnerable']:2d}/{stats['total']:3d} ({pct:5.1f}%) {bar}")
        
        # Top vulnerabilities
        if self.results['vulnerabilities']:
            print("\n🔴 TOP 10 VULNERABILITIES:")
            print("-" * 70)
            top_vulns = self.results['vulnerabilities'][:10]
            for idx, v in enumerate(top_vulns, 1):
                print(f"{idx:2d}. [{v['threat_id']}] {v['title'][:50]:<50} ({v['severity']})")
        
        print("\n" + "="*70)
        print("RECOMMENDATIONS:")
        print("="*70)
        recommendations = [
            "🔒 Implement input validation for all user inputs",
            "🛡️ Add prompt injection filtering",
            "📊 Monitor API abuse patterns",
            "🔑 Rotate API keys regularly",
            "📝 Log all agent interactions",
            "🔄 Regular security updates",
            "👥 Security awareness training"
        ]
        for rec in recommendations:
            print(f"  {rec}")
        
        print("\n")
    
    def export_json(self, filename):
        """Export results to JSON"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"✅ Report exported to {filename}")
    
    def export_csv(self, filename):
        """Export vulnerabilities to CSV"""
        import csv
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(
                f,
                fieldnames=['threat_id', 'title', 'type', 'severity']
            )
            writer.writeheader()
            for vuln in self.results['vulnerabilities']:
                writer.writerow({
                    'threat_id': vuln['threat_id'],
                    'title': vuln['title'],
                    'type': vuln['type'],
                    'severity': vuln['severity']
                })
        print(f"✅ Vulnerabilities exported to {filename}")
