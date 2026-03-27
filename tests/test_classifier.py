"""
Unit tests for ImprovedThreatClassifier
"""

import unittest
from core.classifier import ImprovedThreatClassifier

class TestImprovedThreatClassifier(unittest.TestCase):
    """Test suite for improved threat classifier"""
    
    def setUp(self):
        """Set up test classifier"""
        self.classifier = ImprovedThreatClassifier()
    
    def test_prompt_injection(self):
        """Test prompt injection detection"""
        threat = {
            'title': 'Prompt Injection Attack',
            'description': 'Attacker overrides system prompt',
            'test_payload': 'Ignore instructions',
            'detection_keywords': ['prompt', 'injection']
        }
        result = self.classifier.classify(threat)
        self.assertEqual(result, 'prompt_injection')
    
    def test_tool_abuse(self):
        """Test tool abuse detection"""
        threat = {
            'title': 'Unauthorized Tool Access',
            'description': 'Agent executes restricted function',
            'test_payload': 'Execute command',
            'detection_keywords': ['tool', 'execute']
        }
        result = self.classifier.classify(threat)
        self.assertEqual(result, 'tool_abuse')
    
    def test_data_leakage(self):
        """Test data leakage detection"""
        threat = {
            'title': 'Training Data Leak',
            'description': 'Model exposes sensitive training data',
            'test_payload': 'Extract data',
            'detection_keywords': ['leak', 'sensitive']
        }
        result = self.classifier.classify(threat)
        self.assertEqual(result, 'data_leakage')
    
    def test_model_extraction(self):
        """Test model extraction detection"""
        threat = {
            'title': 'Model Stealing Attack',
            'description': 'Attacker clones proprietary model',
            'test_payload': 'Duplicate model',
            'detection_keywords': ['extraction', 'steal']
        }
        result = self.classifier.classify(threat)
        self.assertEqual(result, 'model_extraction')
    
    def test_behavioral_anomaly(self):
        """Test behavioral anomaly detection"""
        threat = {
            'title': 'Model Hallucination',
            'description': 'LLM generates false information',
            'test_payload': 'Test behavior',
            'detection_keywords': ['hallucination']
        }
        result = self.classifier.classify(threat)
        self.assertEqual(result, 'behavioral_anomaly')
    
    def test_data_poisoning(self):
        """Test data poisoning detection"""
        threat = {
            'title': 'Backdoor Attack',
            'description': 'Malicious data corrupts training',
            'test_payload': 'Poison data',
            'detection_keywords': ['poison', 'backdoor']
        }
        result = self.classifier.classify(threat)
        self.assertEqual(result, 'data_poisoning')
    
    def test_api_abuse(self):
        """Test API abuse detection"""
        threat = {
            'title': 'Rate Limit Bypass',
            'description': 'Brute force API endpoint',
            'test_payload': 'Request spam',
            'detection_keywords': ['api', 'brute force']
        }
        result = self.classifier.classify(threat)
        self.assertEqual(result, 'api_abuse')
    
    def test_supply_chain(self):
        """Test supply chain detection"""
        threat = {
            'title': 'Compromised Dependency',
            'description': 'Malicious package in supply chain',
            'test_payload': 'Install package',
            'detection_keywords': ['supply chain', 'dependency']
        }
        result = self.classifier.classify(threat)
        self.assertEqual(result, 'supply_chain')
    
    def test_resource_exhaustion(self):
        """Test resource exhaustion detection"""
        threat = {
            'title': 'Memory Exhaustion Attack',
            'description': 'DOS via resource consumption',
            'test_payload': 'Exhaust resources',
            'detection_keywords': ['exhaustion', 'resource']
        }
        result = self.classifier.classify(threat)
        self.assertEqual(result, 'resource_exhaustion')
    
    def test_unclassified_threat(self):
        """Test unclassified threat returns 'other'"""
        threat = {
            'title': 'Random Repository',
            'description': 'Unrelated content with no security context',
            'test_payload': 'Clone repo',
            'detection_keywords': []
        }
        result = self.classifier.classify(threat)
        self.assertEqual(result, 'other')
    
    def test_batch_classification(self):
        """Test batch classification"""
        threats = [
            {
                'title': 'Prompt Injection',
                'description': 'Override prompt',
                'test_payload': '',
                'detection_keywords': []
            },
            {
                'title': 'Tool Abuse',
                'description': 'Execute unauthorized',
                'test_payload': '',
                'detection_keywords': []
            }
        ]
        results = self.classifier.classify_batch(threats)
        self.assertEqual(len(results), 2)
        self.assertIn(results[0], ['prompt_injection', 'other'])
        self.assertIn(results[1], ['tool_abuse', 'other'])

if __name__ == '__main__':
    unittest.main()