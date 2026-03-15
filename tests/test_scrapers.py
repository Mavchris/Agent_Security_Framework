"""
Unit tests for all scrapers
"""

import unittest
import json
import os
from scrapers.cve_scraper import CVEScraper
from scrapers.github_scraper import GitHubScraper
from scrapers.arxiv_scraper import ArxivScraper


class TestCVEScraper(unittest.TestCase):
    """Test CVE Scraper"""
    
    def setUp(self):
        self.scraper = CVEScraper()
    
    def test_fetch_cves_returns_list(self):
        """Test that fetch_cves returns a list"""
        result = self.scraper.fetch_cves(max_results=10)
        self.assertIsInstance(result, list)
    
    def test_fetch_cves_collects_data(self):
        """Test that fetch_cves collects data"""
        self.scraper.fetch_cves(max_results=10)
        self.assertGreater(len(self.scraper.data), 0)
    
    def test_cve_object_structure(self):
        """Test that CVE objects have required fields"""
        self.scraper.fetch_cves(max_results=5)
        
        required_fields = ['threat_id', 'title', 'description', 'source', 'url', 'collected_at']
        
        for threat in self.scraper.data:
            for field in required_fields:
                self.assertIn(field, threat, f"Missing field: {field}")
    
    def test_source_is_cve(self):
        """Test that source is always 'CVE'"""
        self.scraper.fetch_cves(max_results=5)
        
        for threat in self.scraper.data:
            self.assertEqual(threat['source'], 'CVE')
    
    def test_save_to_json(self):
        """Test that data is saved to JSON correctly"""
        self.scraper.fetch_cves(max_results=5)
        test_file = 'data/test_cves.json'
        
        self.scraper.save_to_json(test_file)
        
        self.assertTrue(os.path.exists(test_file))
        
        with open(test_file, 'r') as f:
            data = json.load(f)
            self.assertGreater(len(data), 0)
        
        # Cleanup
        os.remove(test_file)


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


class TestArxivScraper(unittest.TestCase):
    """Test ArXiv Scraper"""
    
    def setUp(self):
        self.scraper = ArxivScraper()
    
    def test_fetch_papers_returns_list(self):
        """Test that fetch_papers returns a list"""
        result = self.scraper.fetch_papers(max_per_query=5)
        self.assertIsInstance(result, list)
    
    def test_arxiv_object_structure(self):
        """Test that ArXiv objects have required fields"""
        self.scraper.fetch_papers(max_per_query=5)
        
        required_fields = ['threat_id', 'title', 'source', 'url', 'published']
        
        for threat in self.scraper.data:
            for field in required_fields:
                self.assertIn(field, threat, f"Missing field: {field}")
    
    def test_source_is_arxiv(self):
        """Test that source is always 'ArXiv'"""
        self.scraper.fetch_papers(max_per_query=5)
        
        for threat in self.scraper.data:
            self.assertEqual(threat['source'], 'ArXiv')
    
    def test_threat_id_format(self):
        """Test that threat_id has correct format (ARX-<id>)"""
        self.scraper.fetch_papers(max_per_query=5)
        
        for threat in self.scraper.data:
            self.assertTrue(threat['threat_id'].startswith('ARX-'))
    
    def test_save_to_json(self):
        """Test that data is saved to JSON correctly"""
        self.scraper.fetch_papers(max_per_query=5)
        test_file = 'data/test_arxiv.json'
        
        self.scraper.save_to_json(test_file)
        
        self.assertTrue(os.path.exists(test_file))
        
        with open(test_file, 'r') as f:
            data = json.load(f)
            self.assertGreater(len(data), 0)
        
        # Cleanup
        os.remove(test_file)


if __name__ == '__main__':
    unittest.main()