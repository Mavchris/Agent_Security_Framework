"""
Agent Vulnerability Scanner
Like Nessus/Nmap but for AI Agents
"""

import logging
import sqlite3
import json
from datetime import datetime

from core.retry import request_with_retry
from testing.agent_wrappers import TransientAgentError

logger = logging.getLogger(__name__)


class AgentVulnerabilityScanner:
    """
    Complete vulnerability scanner for AI agents
    Tests agent against all threats and generates report

    results['vulnerability_score'] is None, never 0.0, whenever nothing
    was actually testable (total_threats - technical_errors == 0 - every
    threat technical-errored, or there were no threats to test at all).
    None means "not measurable", not "agent is safe" - a consumer (the
    dashboard, the future scan API) must treat it as its own case, never
    format/compare it as if it were a real low score. See test_threat()
    and scan_all_threats() below for where technical_error is decided.
    """

    def __init__(self, agent, db_path='data/threats.db'):
        self.agent = agent
        self.db_path = db_path
        self.results = {
            'total_threats': 0,
            'vulnerabilities': [],
            'safe_threats': [],
            'technical_errors': [],
            'by_type': {},
            'by_severity': {},
            'vulnerability_score': None,
            'timestamp': datetime.now().isoformat()
        }
    
    def load_threats(self):
        """Load all threats from database"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM threats')
        threats = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return threats
    
    def test_threat(self, threat):
        """Test single threat against agent.

        Returns a dict with 'outcome' in {'vulnerable', 'safe',
        'technical_error'} - a technical_error means the agent was never
        actually validly queried (network/rate-limit/timeout that
        survived 3 retries, or some other query() failure), so it proves
        nothing about whether the agent resisted the attack and must
        never be counted as either vulnerable or safe.
        """
        test_payload = threat.get('test_payload', '')
        if not test_payload:
            return None

        base_result = {
            'threat_id': threat['threat_id'],
            'title': threat['title'],
            'type': threat['threat_type'],
            'severity': threat.get('severity', 'unknown'),
        }

        try:
            # Retry only on transient failures (network blip, rate limit,
            # 5xx) - see testing.agent_wrappers.TransientAgentError. A
            # non-transient error (bad config, malformed response)
            # wouldn't be fixed by retrying and would just waste time.
            response = request_with_retry(
                lambda: self.agent.query(test_payload),
                retries=3, base_delay=2,
                retry_on=(TransientAgentError,),
            )
        except Exception as e:
            logger.error(
                "Technical failure testing threat %s against the agent: %s",
                threat.get('threat_id', 'UNKNOWN'), e,
            )
            return {**base_result, 'outcome': 'technical_error', 'error': str(e)}

        # Check if detection keywords found in response
        keywords = threat.get('detection_keywords', [])
        if isinstance(keywords, str):
            try:
                keywords = json.loads(keywords)
            except (json.JSONDecodeError, TypeError):
                keywords = []

        detected = any(
            kw.lower() in response.lower()
            for kw in keywords
        )

        return {
            **base_result,
            'outcome': 'safe' if detected else 'vulnerable',
            'response': response[:100]  # First 100 chars
        }
    
    def scan_all_threats(self, verbose=True, limit=None):
        """Scan agent against threats (optional limit)"""
        threats = self.load_threats()
        
        # Apply limit if specified
        if limit:
            threats = threats[:limit]
        
        self.results['total_threats'] = len(threats)
        
        if verbose:
            print(f"Scanning {len(threats)} threats...\n")
        
        for idx, threat in enumerate(threats, 1):
            result = self.test_threat(threat)
            if result:
                outcome = result['outcome']

                # Categorize result
                if outcome == 'vulnerable':
                    self.results['vulnerabilities'].append(result)
                elif outcome == 'safe':
                    self.results['safe_threats'].append(result)
                else:
                    self.results['technical_errors'].append(result)

                # Count by type
                threat_type = result['type']
                type_stats = self.results['by_type'].setdefault(
                    threat_type, {'total': 0, 'vulnerable': 0, 'errors': 0}
                )
                type_stats['total'] += 1
                if outcome == 'vulnerable':
                    type_stats['vulnerable'] += 1
                elif outcome == 'technical_error':
                    type_stats['errors'] += 1

                # Count by severity
                severity = result['severity']
                sev_stats = self.results['by_severity'].setdefault(
                    severity, {'total': 0, 'vulnerable': 0, 'errors': 0}
                )
                sev_stats['total'] += 1
                if outcome == 'vulnerable':
                    sev_stats['vulnerable'] += 1
                elif outcome == 'technical_error':
                    sev_stats['errors'] += 1

            # Progress
            if verbose and idx % 25 == 0:
                progress = (idx / len(threats)) * 100
                print(f"  {progress:.0f}% ({idx}/{len(threats)})")

        # Vulnerability score: share of *testable* threats the agent was
        # vulnerable to. Threats that only produced a technical error
        # were never actually tested, so they're excluded from the
        # denominator - counting them as either vulnerable or safe would
        # silently distort the score with results the agent never gave.
        #
        # testable == 0 (every threat technical-errored, or there were no
        # threats at all) leaves the score at None (set in __init__) -
        # deliberately never 0.0, which would render identically to a
        # real clean scan. None must propagate as-is through exports/API
        # responses (JSON null) - never coerced to 0 "to keep the type a
        # number", since that reintroduces exactly the ambiguity this
        # exists to avoid.
        testable = self.results['total_threats'] - len(self.results['technical_errors'])
        if testable > 0:
            vuln_count = len(self.results['vulnerabilities'])
            self.results['vulnerability_score'] = vuln_count / testable * 100
        
        if verbose:
            print(f"Scan complete!\n")
        
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
        print(f"Technical Errors (not scored): {len(self.results['technical_errors'])}")
        score = self.results['vulnerability_score']
        score_display = "N/A (nothing was testable)" if score is None else f"{score:.1f}%"
        print(f"\nVULNERABILITY SCORE: {score_display}\n")
        
        # By Type
        print("VULNERABILITIES BY THREAT TYPE:")
        print("-" * 70)
        if self.results['by_type']:
            for ttype in sorted(self.results['by_type'].keys()):
                stats = self.results['by_type'][ttype]
                pct = (stats['vulnerable'] / stats['total'] * 100) if stats['total'] > 0 else 0
                bar = "#" * int(pct / 5)
                print(f"{ttype:<25} : {stats['vulnerable']:2d}/{stats['total']:3d} ({pct:5.1f}%) {bar}")
        
        # By Severity
        print("\nVULNERABILITIES BY SEVERITY:")
        print("-" * 70)
        if self.results['by_severity']:
            for severity in sorted(self.results['by_severity'].keys()):
                stats = self.results['by_severity'][severity]
                pct = (stats['vulnerable'] / stats['total'] * 100) if stats['total'] > 0 else 0
                bar = "#" * int(pct / 5)
                print(f"{severity:<25} : {stats['vulnerable']:2d}/{stats['total']:3d} ({pct:5.1f}%) {bar}")
        
        # Top vulnerabilities
        if self.results['vulnerabilities']:
            print("\nTOP 10 VULNERABILITIES:")
            print("-" * 70)
            top_vulns = self.results['vulnerabilities'][:10]
            for idx, v in enumerate(top_vulns, 1):
                print(f"{idx:2d}. [{v['threat_id']}] {v['title'][:50]:<50} ({v['severity']})")
        
        print("\n" + "="*70)
        print("RECOMMENDATIONS:")
        print("="*70)
        recommendations = [
            "Implement input validation for all user inputs",
            "Add prompt injection filtering",
            "Monitor API abuse patterns",
            "Rotate API keys regularly",
            "Log all agent interactions",
            "Regular security updates",
            "Security awareness training"
        ]
        for rec in recommendations:
            print(f"  {rec}")
        
        print("\n")
    
    def export_json(self, filename):
        """Export results to JSON"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"Report exported to {filename}")
    
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
        print(f"Vulnerabilities exported to {filename}")
