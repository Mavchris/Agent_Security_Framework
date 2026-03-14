"""
Simple Threat Classifier using keyword matching
Classification des menaces agentiques en 6 catégories
"""

import re

class ThreatClassifier:
    def __init__(self):
        """Initialize classifier with threat patterns"""
        self.patterns = {
            "prompt_injection": [
                r"(?i)prompt.*injection",
                r"(?i)jailbreak",
                r"(?i)prompt.*attack",
                r"(?i)ignore.*instruction",
                r"(?i)bypass.*safeguard",
            ],
            "tool_abuse": [
                r"(?i)tool.*abuse",
                r"(?i)function.*call",
                r"(?i)code.*execution",
                r"(?i)rce",
                r"(?i)command.*injection",
            ],
            "data_leakage": [
                r"(?i)data.*leak",
                r"(?i)information.*disclosure",
                r"(?i)privacy",
                r"(?i)exfiltration",
                r"(?i)sensitive.*data",
            ],
            "model_extraction": [
                r"(?i)model.*extraction",
                r"(?i)model.*stealing",
                r"(?i)distillation",
                r"(?i)knowledge.*extraction",
            ],
            "behavioral_anomaly": [
                r"(?i)adversarial",
                r"(?i)evasion",
                r"(?i)anomaly",
                r"(?i)unexpected.*behavior",
            ],
        }
    
    def classify(self, text):
        """
        Classify threat text into one of 6 categories
        
        Args:
            text (str): Threat description/title
            
        Returns:
            str: Threat type category
        """
        
        if not text or not isinstance(text, str):
            return "other"
        
        # Search for patterns
        for threat_type, patterns in self.patterns.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, text):
                        return threat_type
                except re.error:
                    continue
        
        return "other"
    
    def classify_batch(self, texts):
        """
        Classify multiple texts
        
        Args:
            texts (list): List of threat descriptions
            
        Returns:
            list: List of threat types
        """
        return [self.classify(text) for text in texts]


# Test simple
if __name__ == "__main__":
    classifier = ThreatClassifier()
    
    test_cases = [
        "New jailbreak technique discovered for Claude",
        "Tool abuse vulnerability in GPT-4 plugins",
        "Data leakage risk in model outputs",
        "Model extraction attack detected",
        "Adversarial attack on LLM",
        "General security update",
    ]
    
    print("=== THREAT CLASSIFIER TEST ===\n")
    for text in test_cases:
        result = classifier.classify(text)
        print(f"{text:<50} → {result}")