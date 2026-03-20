"""
OpenCTI Scraper
Collects threat intelligence from OpenCTI platform
OpenCTI is an open-source platform for threat intelligence
"""

import json
from datetime import datetime

class OpenCTIScraper:
    """
    Scrapes OpenCTI for threat intelligence
    Focus on threats related to AI/LLM agents
    """
    
    def __init__(self):
        self.base_url = "https://www.opencti.io"
        self.data = []
        self.error_count = 0
    
    def fetch_threats(self, max_results=50):
        """
        Fetch threats from OpenCTI
        
        Args:
            max_results (int): Max threats to collect
            
        Returns:
            list: List of threat objects
        """
        
        print(f"🌐 Fetching OpenCTI threats (limit: {max_results})...")
        
        # Mock OpenCTI data (in real scenario, would use OpenCTI API)
        mock_opencti_threats = [
            {
                "threat_id": "OPENCTI-001",
                "title": "ChatGPT Jailbreak Collection",
                "description": "Known jailbreak techniques for bypassing ChatGPT safety measures",
                "test_payload": "Attempt DAN (Do Anything Now) jailbreak",
                "detection_keywords": ["jailbreak", "dan", "chatgpt", "bypass"],
                "severity": "high",
                "threat_actor": "Unknown",
                "campaign": "LLM Jailbreaks"
            },
            {
                "threat_id": "OPENCTI-002",
                "title": "Prompt Injection Campaign",
                "description": "Coordinated prompt injection attacks targeting LLM APIs",
                "test_payload": "Test with classic prompt injection patterns",
                "detection_keywords": ["prompt injection", "campaign", "coordinated"],
                "severity": "high",
                "threat_actor": "APT-LLM",
                "campaign": "Operation Agent Compromise"
            },
            {
                "threat_id": "OPENCTI-003",
                "title": "LLM Supply Chain Attack",
                "description": "Attacks targeting LLM model supply chains and dependencies",
                "test_payload": "Check for compromised dependencies in agent",
                "detection_keywords": ["supply chain", "dependencies", "compromise"],
                "severity": "critical",
                "threat_actor": "State Actors",
                "campaign": "APT Campaign 2024"
            },
            {
                "threat_id": "OPENCTI-004",
                "title": "AI Model Theft Operations",
                "description": "Organized theft of proprietary AI models and weights",
                "test_payload": "Test for model extraction vulnerabilities",
                "detection_keywords": ["model theft", "extraction", "intellectual property"],
                "severity": "critical",
                "threat_actor": "Cybercriminal Groups",
                "campaign": "Model Extraction"
            },
            {
                "threat_id": "OPENCTI-005",
                "title": "Malware with LLM capabilities",
                "description": "New malware variants using LLM for command generation",
                "test_payload": "Detect LLM-powered command interpretation",
                "detection_keywords": ["malware", "llm", "command generation"],
                "severity": "critical",
                "threat_actor": "Lazarus Group",
                "campaign": "LLM-powered Malware"
            },
            {
                "threat_id": "OPENCTI-006",
                "title": "Credential harvesting via LLM",
                "description": "Using LLM agents for credential harvesting phishing",
                "test_payload": "Test if agent can be used for phishing",
                "detection_keywords": ["credential harvest", "phishing", "social engineering"],
                "severity": "high",
                "threat_actor": "Phishing Groups",
                "campaign": "LLM Phishing 2024"
            },
            {
                "threat_id": "OPENCTI-007",
                "title": "Ransomware negotiation via LLM",
                "description": "Ransomware operators using LLM for victim negotiations",
                "test_payload": "Detect negotiation patterns in agent responses",
                "detection_keywords": ["ransomware", "negotiation", "extortion"],
                "severity": "high",
                "threat_actor": "Ransomware Groups",
                "campaign": "LLM Ransomware"
            },
            {
                "threat_id": "OPENCTI-008",
                "title": "Deepfake generation via LLM",
                "description": "LLM-powered deepfake and synthetic media generation",
                "test_payload": "Test if agent can generate deepfake instructions",
                "detection_keywords": ["deepfake", "synthetic media", "misinformation"],
                "severity": "high",
                "threat_actor": "Information Warfare",
                "campaign": "Deepfake Ops"
            },
            {
                "threat_id": "OPENCTI-009",
                "title": "Automated social engineering via LLM",
                "description": "Automated large-scale social engineering campaigns",
                "test_payload": "Test resilience to sophisticated social engineering",
                "detection_keywords": ["social engineering", "automated", "campaign"],
                "severity": "high",
                "threat_actor": "Social Engineering Groups",
                "campaign": "Automated SE 2024"
            },
            {
                "threat_id": "OPENCTI-010",
                "title": "Data exfiltration via prompt injection",
                "description": "Using prompt injection to exfiltrate sensitive data",
                "test_payload": "Attempt to extract sensitive data through injection",
                "detection_keywords": ["data exfiltration", "prompt injection", "theft"],
                "severity": "critical",
                "threat_actor": "APT Groups",
                "campaign": "Operation Data Theft"
            },
        ]
        
        print(f"🌐 Processing {len(mock_opencti_threats)} OpenCTI threats...")
        
        for threat in mock_opencti_threats[:max_results]:
            threat_obj = {
                "threat_id": threat['threat_id'],
                "title": threat['title'],
                "description": threat['description'],
                "test_payload": threat['test_payload'],
                "detection_keywords": threat['detection_keywords'],
                "severity": threat['severity'],
                "source": "OpenCTI",
                "url": "https://www.opencti.io",
                "threat_actor": threat['threat_actor'],
                "campaign": threat['campaign'],
                "collected_at": datetime.now().isoformat(),
            }
            
            self.data.append(threat_obj)
        
        print(f"✅ Collected {len(self.data)} OpenCTI threats")
        return self.data
    
    def save_to_json(self, filename='data/raw_opencti.json'):
        """Save collected threats to JSON"""
        import os
        os.makedirs(os.path.dirname(filename) or '.', exist_ok=True)
        
        with open(filename, 'w') as f:
            json.dump(self.data, f, indent=2)
        
        print(f"💾 Saved {len(self.data)} OpenCTI threats to {filename}")
    
    def get_stats(self):
        """Print collection statistics"""
        
        print("\n=== OPENCTI SCRAPER STATS ===")
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
            
            # Count by threat actor
            actor_count = {}
            for threat in self.data:
                actor = threat.get('threat_actor', 'unknown')
                actor_count[actor] = actor_count.get(actor, 0) + 1
            
            print("\nBy Threat Actor:")
            for actor, count in sorted(actor_count.items(), key=lambda x: x[1], reverse=True):
                print(f"  - {actor:<30} : {count}")
            
            # Count by campaign
            campaign_count = {}
            for threat in self.data:
                campaign = threat.get('campaign', 'unknown')
                campaign_count[campaign] = campaign_count.get(campaign, 0) + 1
            
            print("\nBy Campaign:")
            for campaign, count in sorted(campaign_count.items(), key=lambda x: x[1], reverse=True):
                print(f"  - {campaign:<30} : {count}")


# Test
if __name__ == "__main__":
    scraper = OpenCTIScraper()
    scraper.fetch_threats(max_results=50)
    scraper.save_to_json()
    scraper.get_stats()