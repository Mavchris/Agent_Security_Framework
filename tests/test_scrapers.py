"""
Unit tests for all scrapers.

Network-calling scrapers (CVE, ArXiv, CIRCL, EUVD) are tested against
mocked HTTP responses shaped like real recorded API payloads, so the
suite doesn't depend on internet access or third-party API availability.
Real end-to-end verification against the live APIs is still available
via the @pytest.mark.integration tests (excluded by default - see
pytest.ini - run with `pytest -m integration`).

Censys and OpenCTI don't make real network calls at all (see
DATA_SOURCES.md / README Known Limitations - both are still synthetic
placeholder generators), so their tests just check the output shape.
"""

import json
import os
import unittest
from unittest.mock import MagicMock, patch

import pytest

from scrapers.cve_scraper import CVEScraper
from scrapers.github_scraper import GitHubScraper
from scrapers.arxiv_scraper import ArxivScraper
from scrapers.censys_scraper import CensysScraper
from scrapers.opencti_scraper import OpenCTIScraper
from scrapers.circl_vulnerability_lookup_scraper import CIRCLVulnerabilityLookupScraper
from scrapers.euvd_scraper import EUVDScraper


def _mock_response(json_data=None, content=None, status=200):
    """Build a MagicMock standing in for a requests.Response"""
    resp = MagicMock()
    resp.status_code = status
    if json_data is not None:
        resp.json.return_value = json_data
    if content is not None:
        resp.content = content
    resp.raise_for_status = MagicMock()
    return resp


# ----------------------------------------------------------------------
# CVE (cve.circl.lu) - mocked
# ----------------------------------------------------------------------

def _circl_cve_record(cve_id="CVE-2025-12345", severity="HIGH"):
    return {
        "results": {
            "nvd": [
                [cve_id.lower(), {
                    "cveMetadata": {
                        "cveId": cve_id,
                        "datePublished": "2025-01-15T00:00:00.000Z",
                    },
                    "containers": {
                        "cna": {
                            "descriptions": [{"lang": "en", "value": "Mock description of a vulnerability affecting an LLM library."}],
                            "references": [{"url": "https://example.com/advisory"}],
                            "metrics": [{"cvssV3_1": {"baseSeverity": severity}}],
                        },
                        "adp": [],
                    },
                }]
            ]
        }
    }


class TestCVEScraper(unittest.TestCase):
    """Test CVE Scraper against mocked cve.circl.lu responses"""

    def setUp(self):
        self.scraper = CVEScraper()

    @patch("scrapers.cve_scraper.requests.get")
    def test_fetch_cves_returns_list(self, mock_get):
        mock_get.return_value = _mock_response(json_data=_circl_cve_record())
        result = self.scraper.fetch_cves(keywords=["openai/chatgpt"], max_results=10)
        self.assertIsInstance(result, list)

    @patch("scrapers.cve_scraper.requests.get")
    def test_fetch_cves_collects_data(self, mock_get):
        mock_get.return_value = _mock_response(json_data=_circl_cve_record())
        self.scraper.fetch_cves(keywords=["openai/chatgpt"], max_results=10)
        self.assertGreater(len(self.scraper.data), 0)

    @patch("scrapers.cve_scraper.requests.get")
    def test_cve_object_structure(self, mock_get):
        mock_get.return_value = _mock_response(json_data=_circl_cve_record())
        self.scraper.fetch_cves(keywords=["openai/chatgpt"], max_results=5)

        required_fields = ['threat_id', 'title', 'description', 'source', 'url', 'collected_at']
        for threat in self.scraper.data:
            for field in required_fields:
                self.assertIn(field, threat, f"Missing field: {field}")

    @patch("scrapers.cve_scraper.requests.get")
    def test_source_is_cve(self, mock_get):
        mock_get.return_value = _mock_response(json_data=_circl_cve_record())
        self.scraper.fetch_cves(keywords=["openai/chatgpt"], max_results=5)
        for threat in self.scraper.data:
            self.assertEqual(threat['source'], 'CVE')

    @patch("scrapers.cve_scraper.requests.get")
    def test_severity_extracted_from_cvss(self, mock_get):
        """Real behavior found in the Vague 3a audit: severity comes from
        the CVSS baseSeverity field when present, not a fabricated value"""
        mock_get.return_value = _mock_response(json_data=_circl_cve_record(severity="CRITICAL"))
        self.scraper.fetch_cves(keywords=["openai/chatgpt"], max_results=5)
        self.assertEqual(self.scraper.data[0]['severity'], 'critical')

    @patch("scrapers.cve_scraper.requests.get")
    def test_save_to_json(self, mock_get):
        mock_get.return_value = _mock_response(json_data=_circl_cve_record())
        self.scraper.fetch_cves(keywords=["openai/chatgpt"], max_results=5)
        test_file = 'data/test_cves.json'

        self.scraper.save_to_json(test_file)

        self.assertTrue(os.path.exists(test_file))
        with open(test_file, 'r') as f:
            data = json.load(f)
            self.assertGreater(len(data), 0)
        os.remove(test_file)

    @pytest.mark.integration
    def test_real_api_call(self):
        """Real call against cve.circl.lu - run with: pytest -m integration"""
        result = self.scraper.fetch_cves(keywords=["openai/chatgpt"], max_results=5)
        self.assertIsInstance(result, list)


# ----------------------------------------------------------------------
# GitHub - basic checks only, no network call made either way
# ----------------------------------------------------------------------

class TestGitHubScraperBasic(unittest.TestCase):
    """Test GitHub Scraper - Basic checks only (avoid rate limits)"""

    def setUp(self):
        self.scraper = GitHubScraper()

    def test_scraper_initializes(self):
        """Test that GitHub scraper can be initialized"""
        scraper = GitHubScraper()
        self.assertIsNotNone(scraper)
        self.assertEqual(scraper.data, [])

    def test_scraper_has_required_methods(self):
        """Test that scraper has required methods"""
        scraper = GitHubScraper()
        self.assertTrue(hasattr(scraper, 'fetch_exploits'))
        self.assertTrue(hasattr(scraper, 'save_to_json'))
        self.assertTrue(hasattr(scraper, 'get_stats'))

    @patch("scrapers.github_scraper.requests.get")
    def test_fetch_exploits_mocked(self, mock_get):
        """Mocked real fetch - actual repo-search logic (~150/183 lines,
        per the Vague 1 audit) was never exercised by any test before"""
        mock_get.return_value = _mock_response(json_data={
            "items": [{
                "id": 123456,
                "name": "mock-llm-exploit",
                "description": "A mock repository",
                "html_url": "https://github.com/example/mock-llm-exploit",
                "stargazers_count": 42,
                "language": "Python",
            }]
        })
        result = self.scraper.fetch_exploits(queries=["prompt injection"], max_per_query=5)
        self.assertIsInstance(result, list)
        self.assertEqual(result[0]['source'], 'GitHub')
        self.assertEqual(result[0]['threat_id'], 'GH-123456')

    @pytest.mark.integration
    def test_real_api_call(self):
        """Real call against api.github.com - run with: pytest -m integration"""
        result = self.scraper.fetch_exploits(max_per_query=5)
        self.assertIsInstance(result, list)


# ----------------------------------------------------------------------
# ArXiv (export.arxiv.org) - mocked
# ----------------------------------------------------------------------

_ARXIV_ATOM_RESPONSE = b"""<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <id>http://arxiv.org/abs/2401.12345v1</id>
    <updated>2024-01-15T00:00:00Z</updated>
    <published>2024-01-15T00:00:00Z</published>
    <title>Mock Paper on Prompt Injection Defenses</title>
    <summary>This is a mock abstract about defending language models against prompt injection.</summary>
    <author><name>Jane Doe</name></author>
    <author><name>John Smith</name></author>
  </entry>
</feed>
"""


class TestArxivScraper(unittest.TestCase):
    """Test ArXiv Scraper against mocked export.arxiv.org responses"""

    def setUp(self):
        self.scraper = ArxivScraper()

    @patch("scrapers.arxiv_scraper.requests.get")
    def test_fetch_papers_returns_list(self, mock_get):
        mock_get.return_value = _mock_response(content=_ARXIV_ATOM_RESPONSE)
        result = self.scraper.fetch_papers(queries=["prompt injection"], max_per_query=5)
        self.assertIsInstance(result, list)

    @patch("scrapers.arxiv_scraper.requests.get")
    def test_arxiv_object_structure(self, mock_get):
        mock_get.return_value = _mock_response(content=_ARXIV_ATOM_RESPONSE)
        self.scraper.fetch_papers(queries=["prompt injection"], max_per_query=5)

        required_fields = ['threat_id', 'title', 'source', 'url', 'published']
        for threat in self.scraper.data:
            for field in required_fields:
                self.assertIn(field, threat, f"Missing field: {field}")

    @patch("scrapers.arxiv_scraper.requests.get")
    def test_source_is_arxiv(self, mock_get):
        mock_get.return_value = _mock_response(content=_ARXIV_ATOM_RESPONSE)
        self.scraper.fetch_papers(queries=["prompt injection"], max_per_query=5)
        for threat in self.scraper.data:
            self.assertEqual(threat['source'], 'ArXiv')

    @patch("scrapers.arxiv_scraper.requests.get")
    def test_threat_id_format(self, mock_get):
        """Test that threat_id has correct format (ARX-<real arxiv id>)"""
        mock_get.return_value = _mock_response(content=_ARXIV_ATOM_RESPONSE)
        self.scraper.fetch_papers(queries=["prompt injection"], max_per_query=5)
        for threat in self.scraper.data:
            self.assertTrue(threat['threat_id'].startswith('ARX-'))
        self.assertEqual(self.scraper.data[0]['threat_id'], 'ARX-2401.12345v1')

    @patch("scrapers.arxiv_scraper.requests.get")
    def test_authors_joined_from_entry(self, mock_get):
        mock_get.return_value = _mock_response(content=_ARXIV_ATOM_RESPONSE)
        self.scraper.fetch_papers(queries=["prompt injection"], max_per_query=5)
        self.assertEqual(self.scraper.data[0]['authors'], 'Jane Doe, John Smith')

    @patch("scrapers.arxiv_scraper.requests.get")
    def test_save_to_json(self, mock_get):
        mock_get.return_value = _mock_response(content=_ARXIV_ATOM_RESPONSE)
        self.scraper.fetch_papers(queries=["prompt injection"], max_per_query=5)
        test_file = 'data/test_arxiv.json'

        self.scraper.save_to_json(test_file)

        self.assertTrue(os.path.exists(test_file))
        with open(test_file, 'r') as f:
            data = json.load(f)
            self.assertGreater(len(data), 0)
        os.remove(test_file)

    @pytest.mark.integration
    def test_real_api_call(self):
        """Real call against export.arxiv.org - run with: pytest -m integration"""
        result = self.scraper.fetch_papers(max_per_query=5)
        self.assertIsInstance(result, list)


# ----------------------------------------------------------------------
# CIRCL Vulnerability-Lookup - mocked, one fixture per real source schema
# ----------------------------------------------------------------------

_CIRCL_FIXTURES = {
    "cnvd": [{
        "number": "CNVD-2026-00001",
        "title": "Mock CNVD Title",
        "description": "Mock CNVD description",
        "serverity": "高",  # "High" in Chinese, as CNVD actually publishes it
        "products": {"product": "Mock Product 1.0"},
        "cves": {"cve": {"cveNumber": "CVE-2026-00001", "cveUrl": "https://example.com"}},
        "referenceLink": "https://example.com/cnvd",
        "openTime": "2026-01-01",
    }],
    "fstec": [{
        "Идентификатор": "BDU:2026-00001",
        "Наименование уязвимости": "Mock FSTEC title",
        "Описание уязвимости": "Mock FSTEC description",
        "Вендор ПО": "Mock Vendor",
        "Название ПО": "Mock Product",
        "Уровень опасности уязвимости": "Высокий уровень опасности",
        "Ссылки на источники": "https://example.com/fstec",
        "Дата публикации": "01.01.2026",
    }],
    "jvndb": [{
        "@rdf:about": "https://jvndb.jvn.jp/en/contents/2026/JVNDB-2026-000001.html",
        "title": "Mock JVN Title",
        "link": "https://jvndb.jvn.jp/en/contents/2026/JVNDB-2026-000001.html",
        "description": "Mock JVN description",
        "sec:identifier": "JVNDB-2026-000001",
        "sec:cpe": {"@vendor": "Mock Vendor", "@product": "Mock Product"},
        "sec:cvss": {"@severity": "Medium"},
        "dcterms:issued": "2026-01-01T00:00+09:00",
    }],
    "certfr_avis": [{
        "reference": "CERTFR-2026-AVI-0001",
        "title": "Mock CERT-FR Title",
        "summary": "Mock CERT-FR summary",
        "affected_systems": [{"product": {"vendor": {"name": "Mock Vendor"}}}],
        "initial_release_date": "2026-01-01T00:00:00",
    }],
}


class TestCIRCLVulnerabilityLookupScraper(unittest.TestCase):
    """Test CIRCL Vulnerability-Lookup scraper against mocked per-source responses"""

    def setUp(self):
        self.scraper = CIRCLVulnerabilityLookupScraper()

    def _mock_get(self, source, number):
        return _mock_response(json_data=_CIRCL_FIXTURES[source])

    def test_fetch_all_sources_mocked(self):
        with patch.object(self.scraper, "_get", side_effect=self._mock_get):
            result = self.scraper.fetch_vulnerabilities(max_per_source=5)
        self.assertEqual(len(result), 4)  # one entry per mocked source
        self.assertEqual(self.scraper.error_count, 0)

    def test_cnvd_severity_mapped_from_chinese(self):
        """Real behavior: CNVD severity is a Chinese word, mapped to our scale"""
        with patch.object(self.scraper, "_get", side_effect=self._mock_get):
            self.scraper.fetch_vulnerabilities(sources=["cnvd"], max_per_source=5)
        self.assertEqual(self.scraper.data[0]['severity'], 'high')
        self.assertEqual(self.scraper.data[0]['threat_id'], 'CNVD-2026-00001')

    def test_fstec_cyrillic_preserved_and_severity_mapped(self):
        with patch.object(self.scraper, "_get", side_effect=self._mock_get):
            self.scraper.fetch_vulnerabilities(sources=["fstec"], max_per_source=5)
        threat = self.scraper.data[0]
        self.assertEqual(threat['severity'], 'high')
        self.assertEqual(threat['threat_id'], 'BDU-2026-00001')
        self.assertIn("Mock FSTEC title", threat['title'])  # non-ASCII fields round-trip fine

    def test_certfr_severity_unknown_by_design(self):
        """CERT-FR advisories don't carry a CVSS score - must stay 'unknown', not fabricated"""
        with patch.object(self.scraper, "_get", side_effect=self._mock_get):
            self.scraper.fetch_vulnerabilities(sources=["certfr_avis"], max_per_source=5)
        self.assertEqual(self.scraper.data[0]['severity'], 'unknown')

    def test_all_sources_produce_source_field(self):
        with patch.object(self.scraper, "_get", side_effect=self._mock_get):
            self.scraper.fetch_vulnerabilities(max_per_source=5)
        sources_seen = {t['source'] for t in self.scraper.data}
        self.assertEqual(sources_seen, {'CNVD', 'FSTEC', 'JVN', 'CERT-FR'})

    def test_save_to_json_preserves_non_ascii(self):
        with patch.object(self.scraper, "_get", side_effect=self._mock_get):
            self.scraper.fetch_vulnerabilities(sources=["fstec"], max_per_source=5)
        test_file = 'data/test_circl.json'
        self.scraper.save_to_json(test_file)

        with open(test_file, encoding='utf-8') as f:
            raw = f.read()
        self.assertNotIn('\\u', raw)  # ensure_ascii=False - real Cyrillic, not escapes
        os.remove(test_file)

    @pytest.mark.integration
    def test_real_api_call(self):
        """Real call against vulnerability.circl.lu - run with: pytest -m integration"""
        result = self.scraper.fetch_vulnerabilities(max_per_source=3)
        self.assertIsInstance(result, list)


# ----------------------------------------------------------------------
# EUVD (ENISA) - mocked
# ----------------------------------------------------------------------

def _euvd_response():
    return {
        "items": [{
            "id": "EUVD-2026-00001",
            "description": "Mock vulnerability affecting an LLM serving library.",
            "datePublished": "Jan 15, 2026, 10:00:00 AM",
            "baseScore": 8.5,
            "epss": 0.42,
            "references": "https://example.com/ref1\nhttps://example.com/ref2",
            "aliases": "CVE-2026-00001\nGHSA-xxxx-yyyy-zzzz",
            "enisaIdVendor": [{"vendor": {"name": "Mock Vendor"}}],
            "enisaIdProduct": [{"product": {"name": "Mock Product"}}],
        }],
        "total": 1,
    }


class TestEUVDScraper(unittest.TestCase):
    """Test EUVD scraper against a mocked ENISA API response"""

    def setUp(self):
        self.scraper = EUVDScraper()

    @patch.object(EUVDScraper, "_get")
    def test_fetch_vulnerabilities_returns_list(self, mock_get):
        mock_get.return_value = _mock_response(json_data=_euvd_response())
        result = self.scraper.fetch_vulnerabilities(queries=["prompt injection"], max_per_query=5)
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)

    @patch.object(EUVDScraper, "_get")
    def test_source_is_euvd(self, mock_get):
        mock_get.return_value = _mock_response(json_data=_euvd_response())
        self.scraper.fetch_vulnerabilities(queries=["prompt injection"], max_per_query=5)
        self.assertEqual(self.scraper.data[0]['source'], 'EUVD')

    @patch.object(EUVDScraper, "_get")
    def test_severity_from_cvss_score(self, mock_get):
        mock_get.return_value = _mock_response(json_data=_euvd_response())
        self.scraper.fetch_vulnerabilities(queries=["prompt injection"], max_per_query=5)
        self.assertEqual(self.scraper.data[0]['severity'], 'high')  # 8.5 -> high band

    @patch.object(EUVDScraper, "_get")
    def test_date_parsed_to_iso(self, mock_get):
        """Real bug fixed in Vague 3a: EUVD's human-readable date must be
        parsed to YYYY-MM-DD, not naively truncated"""
        mock_get.return_value = _mock_response(json_data=_euvd_response())
        self.scraper.fetch_vulnerabilities(queries=["prompt injection"], max_per_query=5)
        self.assertEqual(self.scraper.data[0]['published'], '2026-01-15')

    @patch.object(EUVDScraper, "_get")
    def test_cve_aliases_split_from_newline_string(self, mock_get):
        mock_get.return_value = _mock_response(json_data=_euvd_response())
        self.scraper.fetch_vulnerabilities(queries=["prompt injection"], max_per_query=5)
        self.assertEqual(self.scraper.data[0]['cve_aliases'], ['CVE-2026-00001', 'GHSA-xxxx-yyyy-zzzz'])

    @pytest.mark.integration
    def test_real_api_call(self):
        """Real call against euvdservices.enisa.europa.eu - run with: pytest -m integration"""
        result = self.scraper.fetch_vulnerabilities(max_per_query=5)
        self.assertIsInstance(result, list)


# ----------------------------------------------------------------------
# Censys and OpenCTI - synthetic, no network call at all, shape-only checks
# ----------------------------------------------------------------------

class TestCensysScraperSynthetic(unittest.TestCase):
    """Censys's fetch_exposures() is a synthetic generator (see Known
    Limitations) - no network call happens, so no mock is needed, just a
    check that the output shape is coherent."""

    def test_fetch_exposures_shape(self):
        scraper = CensysScraper()
        result = scraper.fetch_exposures(max_per_query=2)
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)
        for threat in result:
            self.assertEqual(threat['source'], 'Censys')
            self.assertIn('threat_id', threat)
            self.assertIn('severity', threat)


class TestOpenCTIScraperSynthetic(unittest.TestCase):
    """OpenCTI's fetch_threats() is a synthetic generator (see Known
    Limitations) - no network call happens, so no mock is needed."""

    def test_fetch_threats_shape(self):
        scraper = OpenCTIScraper()
        result = scraper.fetch_threats(max_results=5)
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)
        for threat in result:
            self.assertEqual(threat['source'], 'OpenCTI')
            self.assertIn('threat_id', threat)


if __name__ == '__main__':
    unittest.main()
