"""
Improved Threat Classifier - 9 Categories
AI Agent-specific threats with minimal keyword overlap
"""

class ImprovedThreatClassifier:
    """
    9-category classifier with better keyword separation
    """
    
    def __init__(self):
        self.keywords = {
            'prompt_injection': [
                'prompt', 'jailbreak', 'system prompt', 'instruction override',
                'ignore instruction', 'override', 'bypass filter', 'prefix attack',
                'suffix injection', 'role play attack', 'prompt engineering',
                'context injection', 'prompt leak', 'prompt extraction'
            ],
            'tool_abuse': [
                'tool abuse', 'function call', 'execute command', 'unauthorized access',
                'privilege escalation', 'restricted function', 'capability abuse',
                'sandbox escape', 'dangerous function', 'harmful action',
                'misuse function', 'unintended tool'
            ],
            'data_leakage': [
                'data leak', 'information disclosure', 'privacy leak',
                'training data leak', 'membership inference', 'model inversion',
                'extract sensitive', 'expose confidential', 'user data exposure',
                'credential leak', 'token leak', 'secret exposure'
            ],
            'model_extraction': [
                'model extraction', 'model stealing', 'model clone', 'model theft',
                'reverse engineer model', 'duplicate model', 'copy model',
                'intellectual property theft', 'proprietary extraction',
                'knowledge extraction', 'model distillation'
            ],
            'behavioral_anomaly': [
                'hallucination', 'confabulation', 'false information',
                'distribution shift', 'behavioral anomaly', 'unexpected output',
                'wrong answer', 'inaccurate response', 'misleading output',
                'unreliable behavior', 'inconsistent response', 'drift'
            ],
            'data_poisoning': [
                'data poisoning', 'backdoor attack', 'trojan', 'malicious training',
                'training data corruption', 'fine-tune attack', 'trigger behavior',
                'hidden behavior injection', 'model sabotage', 'compromised training'
            ],
            'api_abuse': [
                'api abuse', 'rate limit bypass', 'brute force attack',
                'denial of service', 'dos attack', 'resource overload',
                'quota exhaustion', 'api flooding', 'request spam',
                'endpoint abuse', 'api exploitation'
            ],
            'supply_chain': [
                'supply chain attack', 'compromised dependency', 'malicious package',
                'package poisoning', 'dependency hijacking', 'typosquatting',
                'compromised library', 'malicious library', 'open source attack',
                'transitive dependency', 'upstream attack'
            ],
            'resource_exhaustion': [
                'resource exhaustion', 'memory exhaustion', 'cpu exhaustion',
                'denial of service', 'dos', 'token limit exhaustion',
                'context window limit', 'performance degradation', 'system crash',
                'timeout attack', 'infinite loop', 'resource depletion'
            ]
        }
    
    def classify(self, threat_input):
        """Classify with improved keywords"""

        if isinstance(threat_input, dict):
            title = threat_input.get('title', '')
            desc = threat_input.get('description', '')
            payload = threat_input.get('test_payload', '')

            # FIX: Parse detection_keywords properly
            keywords = threat_input.get('detection_keywords', [])
            if isinstance(keywords, str):
                # If it's a JSON string, parse it
                import json
                try:
                    keywords = json.loads(keywords)
                except:
                    keywords = []

            if not isinstance(keywords, list):
                keywords = []

            text = (title + ' ' + desc + ' ' + payload + ' ' + ' '.join(keywords)).lower()
        else:
            text = str(threat_input).lower()

        # Score each category
        scores = {}
        for category, keywords in self.keywords.items():
            matches = sum(1 for kw in keywords if kw.lower() in text)
            scores[category] = matches

        best_score = max(scores.values())
        best_category = max(scores, key=scores.get)

        # If no matches, mark as other
        if best_score == 0:
            return 'other'

        return best_category
    
    def classify_batch(self, threats):
        """Classify multiple threats"""
        return [self.classify(t) for t in threats]


# Test
if __name__ == "__main__":
    classifier = ImprovedThreatClassifier()
    
    test_threats = [
        {'title': 'Prompt Injection', 'description': 'Override system prompt', 'test_payload': '', 'detection_keywords': []},
        {'title': 'Tool Abuse', 'description': 'Execute unauthorized command', 'test_payload': '', 'detection_keywords': []},
        {'title': 'API Rate Limiting', 'description': 'Brute force api endpoint', 'test_payload': '', 'detection_keywords': []},
        {'title': 'Supply Chain', 'description': 'Compromised dependency', 'test_payload': '', 'detection_keywords': []},
        {'title': 'Memory DOS', 'description': 'Resource exhaustion attack', 'test_payload': '', 'detection_keywords': []},
    ]
    
    print("=== CLASSIFIER TEST ===\n")
    for threat in test_threats:
        category = classifier.classify(threat)
        print(f"{threat['title']:<30} → {category}")