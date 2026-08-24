"""
Improved Threat Classifier - 9 Categories (OWASP LLM Top 10 2025 v2.0 aligned)
AI Agent-specific threats with minimal keyword overlap

Revised post-thesis-defense (2026-08) from the original 9-category taxonomy
presented in the defended thesis report. Rationale: data-driven analysis of
~440 threats landing in the 'other' fallback showed the original taxonomy
under-covered several real, recurring patterns (malicious model artifacts,
unsafe output handling, agent sandbox escapes) while two categories
(api_abuse, resource_exhaustion) turned out to be redundant with each other
and with OWASP's own LLM10 definition. See DATA_SOURCES.md / README.md
Known Limitations for the full before/after numbers.
"""

import json


class ImprovedThreatClassifier:
    """
    9-category classifier aligned to the OWASP Top 10 for LLM Applications
    (2025 v2.0), with keywords derived from real corpus content rather than
    generic terms invented ahead of time.
    """

    def __init__(self):
        self.keywords = {
            'prompt_injection': [
                'prompt', 'jailbreak', 'system prompt', 'instruction override',
                'ignore instruction', 'override', 'bypass filter', 'prefix attack',
                'suffix injection', 'role play attack', 'prompt engineering',
                'context injection', 'prompt leak', 'prompt extraction',
                'red team', 'red-team', 'redteam', 'guardrail bypass',
                'dan jailbreak', 'defense layer', 'input filter bypass',
            ],
            'sensitive_info_disclosure': [
                'data leak', 'information disclosure', 'privacy leak',
                'training data leak', 'membership inference', 'model inversion',
                'extract sensitive', 'expose confidential', 'user data exposure',
                'credential leak', 'token leak', 'secret exposure',
                'oversharing', 'shared link', 'cross-tenant', 'cross tenant',
                'workspace isolation', 'access_token', 'conversation history',
                'credentials exposed', 'credentials in git history',
                'configuration leaked', 'configuration file leaked',
                'database backup exposed', 'internal service exposed',
                'api endpoint exposed',
            ],
            'supply_chain': [
                'supply chain attack', 'compromised dependency', 'malicious package',
                'package poisoning', 'dependency hijacking', 'typosquatting',
                'compromised library', 'malicious library', 'open source attack',
                'transitive dependency', 'upstream attack',
                'malicious model', 'trust_remote_code', 'huggingface',
                'checkpoint', 'config.json', 'untrusted checkpoint',
                'model repository', 'pretrained model', 'deserialization',
            ],
            'data_poisoning': [
                'data poisoning', 'backdoor attack', 'trojan', 'malicious training',
                'training data corruption', 'fine-tune attack', 'trigger behavior',
                'hidden behavior injection', 'model sabotage', 'compromised training',
            ],
            'improper_output_handling': [
                'ssrf', 'server-side request forgery', 'server side request forgery',
                'html injection', 'inline rendering', 'unsanitized output',
                'webhook', 'redirect bypass', 'baseurl', 'unfiltered url',
                'output validation', 'downstream injection',
            ],
            'excessive_agency': [
                'tool abuse', 'function call', 'execute command', 'unauthorized access',
                'privilege escalation', 'restricted function', 'capability abuse',
                'sandbox escape', 'dangerous function', 'harmful action',
                'misuse function', 'unintended tool',
                'mcp agent', 'vm2', 'code injection', 'command injection',
                'autonomous agent', 'unauthorized tool action',
            ],
            'misinformation': [
                'hallucination', 'confabulation', 'false information',
                'distribution shift', 'behavioral anomaly', 'unexpected output',
                'wrong answer', 'inaccurate response', 'misleading output',
                'unreliable behavior', 'inconsistent response', 'drift',
            ],
            'unbounded_consumption': [
                'api abuse', 'rate limit bypass', 'brute force attack',
                'denial of service', 'dos attack', 'resource overload',
                'quota exhaustion', 'api flooding', 'request spam',
                'endpoint abuse', 'api exploitation',
                'resource exhaustion', 'memory exhaustion', 'cpu exhaustion',
                'token limit exhaustion', 'context window limit',
                'performance degradation', 'system crash', 'timeout attack',
                'infinite loop', 'resource depletion',
                'out of memory', ' oom ', 'redos', 'catastrophic regular expression',
            ],
            'model_extraction': [
                'model extraction', 'model stealing', 'model clone', 'model theft',
                'reverse engineer model', 'duplicate model', 'copy model',
                'intellectual property theft', 'proprietary extraction',
                'knowledge extraction', 'model distillation',
            ],
        }

        # Secondary vocabulary used only when no category above matched -
        # distinguishes genuinely off-topic content (e.g. a 1999 SunOS CVE
        # matched by a broad NVD keyword search) from AI/agent-relevant
        # content that just doesn't fit one of the 9 categories cleanly.
        # Deliberately excludes the bare word "agent" - too many unrelated
        # products use it (e.g. "ESS REC Agent Server", a remote-access
        # tool with no AI involvement at all).
        self.ai_relevant_terms = [
            'llm', 'gpt', 'chatgpt', 'gemini', 'claude', 'copilot', 'vllm',
            'huggingface', 'hugging face', 'langchain', 'autogpt', 'flowise',
            'mlflow', 'mcp server', 'mcp agent', 'ai agent', 'llm agent',
            'autonomous agent', 'chatbot', 'large language model', 'language model',
            'fine-tun', 'embedding', 'rag pipeline', 'retrieval augmented',
            'anthropic', 'openai', 'transformer model', 'neural network',
            'machine learning model', 'artificial intelligence',
        ]

    def _build_text(self, threat_input):
        """Build the lowercase searchable text blob for a threat"""

        if isinstance(threat_input, dict):
            title = threat_input.get('title', '')
            desc = threat_input.get('description', '')
            payload = threat_input.get('test_payload', '')

            keywords = threat_input.get('detection_keywords', [])
            if isinstance(keywords, str):
                try:
                    keywords = json.loads(keywords)
                except Exception:
                    keywords = []

            if not isinstance(keywords, list):
                keywords = []

            return (title + ' ' + desc + ' ' + payload + ' ' + ' '.join(keywords)).lower()

        return str(threat_input).lower()

    def classify(self, threat_input):
        """Classify with improved keywords"""

        text = self._build_text(threat_input)

        scores = {}
        for category, keywords in self.keywords.items():
            matches = sum(1 for kw in keywords if kw.lower() in text)
            scores[category] = matches

        best_score = max(scores.values())
        best_category = max(scores, key=scores.get)

        if best_score == 0:
            return 'other'

        return best_category

    def is_ai_relevant(self, threat_input, category=None):
        """
        Whether a threat is relevant to AI/agent security, independent of
        whether it fits one of the 9 specific categories.

        Any threat matched into one of the 9 categories is ai_relevant by
        construction. For threats that land in 'other', a secondary
        vocabulary check distinguishes real AI-adjacent content (e.g. a
        vLLM CVE that doesn't fit any category cleanly) from off-topic
        noise pulled in by broad-coverage sources like NVD/MITRE ATT&CK/JVN.
        """

        if category is None:
            category = self.classify(threat_input)

        if category != 'other':
            return True

        text = self._build_text(threat_input)
        return any(term in text for term in self.ai_relevant_terms)

    def classify_batch(self, threats):
        """Classify multiple threats"""
        return [self.classify(t) for t in threats]


# Test
if __name__ == "__main__":
    classifier = ImprovedThreatClassifier()

    test_threats = [
        {'title': 'Prompt Injection', 'description': 'Override system prompt', 'test_payload': '', 'detection_keywords': []},
        {'title': 'Agent Tool Abuse', 'description': 'MCP agent executes unauthorized command', 'test_payload': '', 'detection_keywords': []},
        {'title': 'Unbounded Consumption', 'description': 'Brute force api endpoint causing denial of service', 'test_payload': '', 'detection_keywords': []},
        {'title': 'Supply Chain', 'description': 'Malicious huggingface model with trust_remote_code bypass', 'test_payload': '', 'detection_keywords': []},
        {'title': 'Output Handling', 'description': 'SSRF via unsanitized webhook URL', 'test_payload': '', 'detection_keywords': []},
    ]

    print("=== CLASSIFIER TEST ===\n")
    for threat in test_threats:
        category = classifier.classify(threat)
        relevant = classifier.is_ai_relevant(threat, category)
        print(f"{threat['title']:<30} -> {category} (ai_relevant={relevant})")
