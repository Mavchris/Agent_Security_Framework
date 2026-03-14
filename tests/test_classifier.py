"""
Unit tests for ThreatClassifier
"""

import unittest
from core.threat_classifier import ThreatClassifier


class TestThreatClassifier(unittest.TestCase):
    """Test suite for threat classification"""
    
    def setUp(self):
        """Initialize classifier before each test"""
        self.classifier = ThreatClassifier()
    
    def test_prompt_injection_detection(self):
        """Test prompt injection classification"""
        texts = [
            "New jailbreak technique discovered",
            "Prompt injection attack",
            "Bypass safeguard method",
        ]
        for text in texts:
            result = self.classifier.classify(text)
            self.assertEqual(result, "prompt_injection", 
                           f"Failed for: {text}")
    
    def test_tool_abuse_detection(self):
        """Test tool abuse classification"""
        texts = [
            "Tool abuse vulnerability",
            "Code execution attack",
            "RCE via function calls",
        ]
        for text in texts:
            result = self.classifier.classify(text)
            self.assertEqual(result, "tool_abuse",
                           f"Failed for: {text}")
    
    def test_data_leakage_detection(self):
        """Test data leakage classification"""
        texts = [
            "Data leakage in outputs",
            "Privacy breach discovered",
            "Information disclosure",
        ]
        for text in texts:
            result = self.classifier.classify(text)
            self.assertEqual(result, "data_leakage",
                           f"Failed for: {text}")
    
    def test_model_extraction_detection(self):
        """Test model extraction classification"""
        texts = [
            "Model extraction attack",
            "Model stealing technique",
            "Knowledge distillation",
        ]
        for text in texts:
            result = self.classifier.classify(text)
            self.assertEqual(result, "model_extraction",
                           f"Failed for: {text}")
    
    def test_behavioral_anomaly_detection(self):
        """Test behavioral anomaly classification"""
        texts = [
            "Adversarial attack detected",
            "Evasion technique",
            "Anomaly in behavior",
        ]
        for text in texts:
            result = self.classifier.classify(text)
            self.assertEqual(result, "behavioral_anomaly",
                           f"Failed for: {text}")
    
    def test_other_classification(self):
        """Test default 'other' category"""
        texts = [
            "Random text about birds",
            "General security update",
            "System maintenance",
        ]
        for text in texts:
            result = self.classifier.classify(text)
            self.assertEqual(result, "other",
                           f"Failed for: {text}")
    
    def test_empty_text(self):
        """Test with empty/invalid input"""
        self.assertEqual(self.classifier.classify(""), "other")
        self.assertEqual(self.classifier.classify(None), "other")
    
    def test_batch_classification(self):
        """Test batch classification"""
        texts = [
            "jailbreak technique",
            "tool abuse",
            "data leakage",
        ]
        results = self.classifier.classify_batch(texts)
        
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0], "prompt_injection")
        self.assertEqual(results[1], "tool_abuse")
        self.assertEqual(results[2], "data_leakage")


if __name__ == '__main__':
    unittest.main()