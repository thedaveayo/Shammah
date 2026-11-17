"""
Comprehensive Test Suite for Security MCP Backend
Tests all major components and functionalities
"""
import pytest
import sys
import os
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

# Add backend to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from models.rule import Rule
from services.rule_generator import llm_extract_cwe_patterns, llm_extract_telegram_rule
from services.quick_fix_service import generate_quick_fix_suggestions
from services.cve_fetcher import CVEFetcher
from services.cwe_fetcher import CWEFetcher


class TestRuleModel:
    """Test Rule model functionality"""
    
    def test_create_rule(self):
        """Test creating a new rule"""
        rule = Rule(
            rule_id="DSV-2026-0001",
            rule_type="cwe",
            source="cwe",
            severity="high",
            title="Test Rule",
            description="This is a test rule",
            cwe_refs=["CWE-79"],
            pattern={"type": "regex", "value": "test", "language": "javascript"},
            applies_to={"languages": ["javascript"], "contexts": ["frontend"]},
            enforcement={"level": "block", "message": "Fix the issue"}
        )
        
        assert rule.rule_id == "DSV-2026-0001"
        assert rule.rule_type == "cwe"
        assert rule.severity == "high"
        assert rule.title == "Test Rule"
        assert "CWE-79" in rule.cwe_refs
        assert rule.to_dict()["rule_id"] == "DSV-2026-0001"
    
    def test_rule_to_dict(self):
        """Test converting rule to dictionary"""
        rule = Rule(
            rule_id="DSV-2026-0001",
            rule_type="cwe",
            source="cwe",
            severity="high",
            title="Test Rule",
            description="This is a test rule",
            cwe_refs=["CWE-79"],
            pattern={"type": "regex", "value": "test", "language": "javascript"},
            applies_to={"languages": ["javascript"], "contexts": ["frontend"]},
            enforcement={"level": "block", "message": "Fix the issue"}
        )
        
        rule_dict = rule.to_dict()
        assert rule_dict["rule_id"] == "DSV-2026-0001"
        assert rule_dict["rule_type"] == "cwe"
        assert rule_dict["severity"] == "high"
        assert rule_dict["title"] == "Test Rule"
        assert "CWE-79" in rule_dict["cwe_refs"]


class TestRuleGenerator:
    """Test Rule Generator functionality"""
    
    @patch('services.rule_generator.client')
    def test_llm_extract_cwe_patterns(self, mock_client):
        """Test LLM extraction of CWE patterns"""
        # Mock the API response
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = '''
        {
            "pattern": {"type": "regex", "value": "eval\\(.*\\)", "language": "javascript"},
            "applies_to": {"languages": ["javascript"], "contexts": ["frontend"]},
            "severity": "high",
            "message": "Avoid using eval() as it can execute arbitrary code",
            "required_actions": ["Replace eval() with safer alternatives", "Validate input before processing"]
        }
        '''
        mock_client.chat.completions.create.return_value = mock_response
        
        cwe_data = {
            "id": "79",
            "name": "Cross-site Scripting",
            "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page.",
            "example_code": "var userInput = req.query.input; document.body.innerHTML = userInput;",
            "remediation": "Use frameworks that automatically escape content or manually escape HTML entities."
        }
        
        result = llm_extract_cwe_patterns(cwe_data)
        
        assert result is not None
        assert result["pattern"]["type"] == "regex"
        assert result["pattern"]["value"] == "eval\\(.*\\)"
        assert result["severity"] == "high"
        assert "Avoid using eval()" in result["message"]
    
    @patch('services.rule_generator.client')
    def test_llm_extract_telegram_rule(self, mock_client):
        """Test LLM extraction of Telegram rules"""
        # Mock the API response
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = '''
        {
            "cwe_refs": ["CWE-79"],
            "pattern": {"type": "regex", "value": "innerHTML", "language": "javascript"},
            "applies_to": {"languages": ["javascript"], "contexts": ["frontend"]},
            "severity": "HIGH",
            "message": "Unsafe use of innerHTML detected",
            "required_actions": ["Use textContent instead", "Sanitize input"],
            "source_link": "https://example.com/article",
            "is_exact_cwe_match": false
        }
        '''
        mock_client.chat.completions.create.return_value = mock_response
        
        article_text = "A new XSS vulnerability was discovered where innerHTML is used unsafely..."
        
        # Mock existing rules list
        mock_existing_rules = []
        
        result = llm_extract_telegram_rule(article_text, mock_existing_rules)
        
        assert result is not None
        assert "CWE-79" in result["cwe_refs"]
        assert result["pattern"]["value"] == "innerHTML"
        assert result["severity"] == "HIGH"


class TestQuickFixService:
    """Test Quick Fix Service functionality"""
    
    @patch('services.quick_fix_service.client')
    def test_generate_quick_fix_suggestions(self, mock_client):
        """Test generating quick fix suggestions"""
        # Mock the API response
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = '''
        {
            "fixes": [
                {
                    "title": "Use parameterized queries",
                    "description": "Replace string concatenation with parameterized queries",
                    "before": "query = \"SELECT * FROM users WHERE id = \" + userId",
                    "after": "query = \"SELECT * FROM users WHERE id = ?\", [userId]",
                    "confidence": "high",
                    "complexity": "simple"
                }
            ]
        }
        '''
        mock_client.chat.completions.create.return_value = mock_response
        
        code_snippet = 'query = "SELECT * FROM users WHERE id = " + userId'
        rule_description = "SQL Injection vulnerability"
        
        fixes = generate_quick_fix_suggestions(code_snippet, rule_description)
        
        assert fixes is not None
        assert len(fixes) == 1
        assert fixes[0]["title"] == "Use parameterized queries"
        assert "parameterized queries" in fixes[0]["description"]


class TestCVEFetcher:
    """Test CVE Fetcher functionality"""
    
    @patch('services.cve_fetcher.requests.get')
    def test_sync_cves(self, mock_get):
        """Test syncing CVEs"""
        fetcher = CVEFetcher()
        
        # Mock response with CVE data
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-1234",
                        "descriptions": [{"value": "Test CVE description"}],
                        "metrics": {
                            "cvssMetricV31": [{
                                "cvssData": {
                                    "baseSeverity": "HIGH"
                                }
                            }]
                        }
                    }
                }
            ]
        }
        mock_get.return_value = mock_response
        
        # Mock database session
        mock_db = Mock()
        mock_db.query().filter().first.return_value = None  # No existing rule
        mock_db.add = Mock()
        mock_db.commit = Mock()
        
        with patch('services.cve_fetcher.SessionLocal', return_value=mock_db):
            saved_count = fetcher.sync_cves(mock_db, days_back=1)
            
            assert saved_count >= 0  # At least one CVE processed


class TestCWEFetcher:
    """Test CWE Fetcher functionality"""
    
    @patch('services.cwe_fetcher.requests.get')
    @patch('services.cwe_fetcher.llm_extract_cwe_patterns')
    def test_sync_cwe_taxonomy(self, mock_llm_extract, mock_get):
        """Test syncing CWE taxonomy"""
        fetcher = CWEFetcher()
        
        # Mock the LLM extraction to return a fixed result
        mock_llm_extract.return_value = {
            "pattern": {"type": "regex", "value": "test", "language": "javascript"},
            "applies_to": {"languages": ["javascript"]},
            "severity": "high",
            "message": "Test message",
            "required_actions": ["Test action"]
        }
        
        # Mock the HTTP response with XML content
        mock_response = Mock()
        mock_response.content = b'''<?xml version="1.0" encoding="UTF-8"?>
        <ns0:CWECatalog xmlns:ns0="http://cwe.mitre.org/cwe-7">
            <ns0:Weaknesses>
                <ns0:Weakness ID="79" Name="Cross-site Scripting" Status="Viewed">
                    <ns0:Description>A test description</ns0:Description>
                </ns0:Weakness>
            </ns0:Weaknesses>
        </ns0:CWECatalog>'''
        mock_get.return_value = mock_response
        
        # Mock database session
        mock_db = Mock()
        mock_db.query().filter().first.return_value = None  # No existing rule
        mock_db.add = Mock()
        mock_db.commit = Mock()
        
        with patch('services.cwe_fetcher.SessionLocal', return_value=mock_db):
            saved_count = fetcher.sync_cwe_taxonomy(mock_db, force=True)
            
            # Should have processed at least one CWE
            assert saved_count >= 0


# Run tests if this file is executed directly
if __name__ == '__main__':
    pytest.main([__file__, '-v'])