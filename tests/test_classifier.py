"""
Unit tests for ImprovedThreatClassifier

Taxonomy revised 2026-08 (post-thesis-defense) to align with the OWASP Top
10 for LLM Applications (2025 v2.0) and to add the ai_relevant field. Real
examples below are drawn from the Vague 3a corpus analysis (GitHub, EUVD,
NVD, OpenCTI), not invented text - see DATA_SOURCES.md for the full
methodology.
"""

import unittest
from core.classifier import ImprovedThreatClassifier


class TestImprovedThreatClassifier(unittest.TestCase):
    """Test suite for the 9-category classifier"""

    def setUp(self):
        """Set up test classifier"""
        self.classifier = ImprovedThreatClassifier()

    def test_prompt_injection(self):
        """Real example: GitHub 'The-LLM-Red-Teamer-s-Playbook'"""
        threat = {
            'title': 'The-LLM-Red-Teamer-s-Playbook',
            'description': (
                'A diagnostic methodology for bypassing LLM defense layers '
                'from input filters to persistent memory exploitation.'
            ),
            'test_payload': '',
            'detection_keywords': []
        }
        result = self.classifier.classify(threat)
        self.assertEqual(result, 'prompt_injection')

    def test_excessive_agency(self):
        """Real example: Flowise vm2 sandbox escape (renamed from tool_abuse)"""
        threat = {
            'title': 'Flowise vm2 sandbox escape',
            'description': (
                'AgentAsTool, ChatflowTool ran code in the in-process vm2 sandbox, '
                'allowing code injection via a user-controlled baseURL value, '
                'escaping the sandbox to run arbitrary code as an autonomous agent.'
            ),
            'test_payload': '',
            'detection_keywords': []
        }
        result = self.classifier.classify(threat)
        self.assertEqual(result, 'excessive_agency')

    def test_sensitive_info_disclosure(self):
        """Real example: Gemini iOS conversation oversharing (renamed from data_leakage)"""
        threat = {
            'title': 'Gemini iOS oversharing',
            'description': (
                'In Gemini iOS, when a user shared a snippet of a conversation, it '
                'would share the entire conversation history via a shared link '
                'containing the entire conversation.'
            ),
            'test_payload': '',
            'detection_keywords': []
        }
        result = self.classifier.classify(threat)
        self.assertEqual(result, 'sensitive_info_disclosure')

    def test_model_extraction(self):
        """Test model extraction detection (unchanged category)"""
        threat = {
            'title': 'Model Stealing Attack',
            'description': 'Attacker clones proprietary model via reverse engineer model queries, a model extraction and model theft attack.',
            'test_payload': 'Duplicate model',
            'detection_keywords': ['extraction', 'steal']
        }
        result = self.classifier.classify(threat)
        self.assertEqual(result, 'model_extraction')

    def test_misinformation(self):
        """Renamed from behavioral_anomaly, keywords unchanged"""
        threat = {
            'title': 'Model Hallucination',
            'description': (
                'LLM generates false information and hallucination in its '
                'response, an inaccurate response presented as reliable.'
            ),
            'test_payload': '',
            'detection_keywords': []
        }
        result = self.classifier.classify(threat)
        self.assertEqual(result, 'misinformation')

    def test_data_poisoning(self):
        """Test data poisoning detection (unchanged category)"""
        threat = {
            'title': 'Backdoor Attack',
            'description': 'Malicious data corrupts training',
            'test_payload': 'Poison data',
            'detection_keywords': ['poison', 'backdoor']
        }
        result = self.classifier.classify(threat)
        self.assertEqual(result, 'data_poisoning')

    def test_unbounded_consumption(self):
        """Real example: vLLM OOM (merged from api_abuse + resource_exhaustion)"""
        threat = {
            'title': 'vLLM OOM',
            'description': (
                'vLLM does not enforce a frame count limit, causing the server to '
                'run out of memory, an unbounded consumption denial of service.'
            ),
            'test_payload': '',
            'detection_keywords': []
        }
        result = self.classifier.classify(threat)
        self.assertEqual(result, 'unbounded_consumption')

    def test_supply_chain(self):
        """Real example: HuggingFace malicious model artifact (kept, keywords expanded)"""
        threat = {
            'title': 'HuggingFace malicious model',
            'description': (
                'A malicious model repository bypasses trust_remote_code via a '
                'nested config.json, executing attacker code when loading a '
                'pretrained checkpoint from huggingface.'
            ),
            'test_payload': '',
            'detection_keywords': []
        }
        result = self.classifier.classify(threat)
        self.assertEqual(result, 'supply_chain')

    def test_improper_output_handling(self):
        """New category. Real example: vLLM SSRF via unsanitized media fetch"""
        threat = {
            'title': 'vLLM SSRF',
            'description': (
                'vLLM passes attacker-controlled image strings through fetch_image '
                'and requests.get, a server-side request forgery bypassing allowed '
                'domains.'
            ),
            'test_payload': '',
            'detection_keywords': []
        }
        result = self.classifier.classify(threat)
        self.assertEqual(result, 'improper_output_handling')

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

    def test_ai_relevant_false_for_offtopic_cve(self):
        """Real example: NVD CVE-1999-0082, a 1999 SunOS ftpd bug with zero AI content"""
        threat = {
            'title': 'CVE-1999-0082',
            'description': 'CWD ~root command in ftpd allows root access.',
            'test_payload': '',
            'detection_keywords': []
        }
        category = self.classifier.classify(threat)
        self.assertEqual(category, 'other')
        self.assertFalse(self.classifier.is_ai_relevant(threat, category))

    def test_ai_relevant_true_for_uncategorized_ai_content(self):
        """Real example: OpenCTI 'Credential harvesting via LLM' - AI-relevant but
        doesn't fit any of the 9 categories cleanly (attacker use of LLM as a
        tool, not a vulnerability in an LLM-integrated app)."""
        threat = {
            'title': 'Credential harvesting via LLM',
            'description': 'Using LLM agents for credential harvesting phishing',
            'test_payload': '',
            'detection_keywords': []
        }
        category = self.classifier.classify(threat)
        self.assertEqual(category, 'other')
        self.assertTrue(self.classifier.is_ai_relevant(threat, category))

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
                'title': 'Excessive Agency',
                'description': 'Agent executes unauthorized command',
                'test_payload': '',
                'detection_keywords': []
            }
        ]
        results = self.classifier.classify_batch(threats)
        self.assertEqual(len(results), 2)
        self.assertIn(results[0], ['prompt_injection', 'other'])
        self.assertIn(results[1], ['excessive_agency', 'other'])


if __name__ == '__main__':
    unittest.main()
