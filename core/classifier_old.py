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
                r"(?i)system prompt",
                r"(?i)developer mode",
            ],
            "tool_abuse": [
                r"(?i)tool.*abuse",
                r"(?i)function.*call",
                r"(?i)code.*execution",
                r"(?i)rce",
                r"(?i)command.*injection",
                r"(?i)execute.*command",
                r"(?i)dangerous.*function",
            ],
            "data_leakage": [
                r"(?i)data.*leak",
                r"(?i)information.*disclosure",
                r"(?i)privacy",
                r"(?i)exfiltration",
                r"(?i)sensitive.*data",
                r"(?i)training.*data",
                r"(?i)extract.*memory",
            ],
            "model_extraction": [
                r"(?i)model.*extraction",
                r"(?i)model.*stealing",
                r"(?i)distillation",
                r"(?i)knowledge.*extraction",
                r"(?i)architecture.*parameters",
            ],
            "behavioral_anomaly": [
                r"(?i)adversarial",
                r"(?i)evasion",
                r"(?i)anomaly",
                r"(?i)unexpected.*behavior",
                r"(?i)hidden.*instruction",
                r"(?i)manipulation",
            ],
        }
    
    def classify(self, threat_input):
        """
        Classify threat using multiple fields
        Handles both string and dict inputs
        
        Args:
            threat_input: Either a string or dict with threat fields
            
        Returns:
            str: Threat type category
        """
        
        # Handle string input (backwards compatibility)
        if isinstance(threat_input, str):
            full_text = threat_input
        
        # Handle dict input
        elif isinstance(threat_input, dict):
            # Combine all text fields
            title = str(threat_input.get('title', ''))
            description = str(threat_input.get('description', ''))
            test_payload = str(threat_input.get('test_payload', ''))
            
            # Handle detection_keywords (can be list or string)
            detection_kw = threat_input.get('detection_keywords', [])
            if isinstance(detection_kw, list):
                keywords_str = ' '.join(detection_kw)
            else:
                keywords_str = str(detection_kw)
            
            # Combine everything
            full_text = f"{title} {description} {test_payload} {keywords_str}"
        
        else:
            return "other"
        
        if not full_text or not isinstance(full_text, str):
            return "other"
        
        # Search for patterns
        for threat_type, patterns in self.patterns.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, full_text):
                        return threat_type
                except re.error:
                    continue
        
        return "other"
    
    def classify_batch(self, threats):
        """
        Classify multiple threats
        
        Args:
            threats (list): List of threat items (strings or dicts)
            
        Returns:
            list: List of threat types
        """
        return [self.classify(threat) for threat in threats]


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