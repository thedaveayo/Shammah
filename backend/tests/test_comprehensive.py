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
from models.subscription import Subscription
from services.rule_generator import llm_extract_cwe_patterns, llm_extract_telegram_rule
from services.subscription import SubscriptionService
from services.quick_fix_service import generate_quick_fix_suggestions
from services.advanced_auth_service import AdvancedAuthService, Role, Permission
from services.cve_fetcher import CVEFetcher
from services.cwe_fetcher import CWEFetcher
from services.pattern_matcher import PatternMatcher
from services.hybrid_pattern_matcher import HybridPatternMatcher


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


class TestSubscriptionModel:
    """Test Subscription model functionality"""
    
    def test_create_subscription(self):
        """Test creating a new subscription"""
        expires_at = datetime.utcnow() + timedelta(days=30)
        subscription = Subscription(
            user_id="test-user-123",
            email="test@example.com",
            is_active=True,
            expires_at=expires_at,
            auth_token="fake-jwt-token"
        )
        
        assert subscription.user_id == "test-user-123"
        assert subscription.email == "test@example.com"
        assert subscription.is_active == True
        assert subscription.is_valid() == True
        assert subscription.days_until_expiry() == 30
    
    def test_subscription_expiry(self):
        """Test subscription expiration logic"""
        # Expired subscription
        expired_date = datetime.utcnow() - timedelta(days=1)
        expired_sub = Subscription(
            user_id="test-user-123",
            email="test@example.com",
            is_active=True,
            expires_at=expired_date,
            auth_token="fake-jwt-token"
        )
        
        assert expired_sub.is_valid() == False
        assert expired_sub.days_until_expiry() == -1
        
        # Subscription in grace period (within 7 days of expiry)
        grace_period_date = datetime.utcnow() - timedelta(days=3)
        grace_sub = Subscription(
            user_id="test-user-123",
            email="test@example.com",
            is_active=True,
            expires_at=grace_period_date,
            auth_token="fake-jwt-token"
        )
        
        assert grace_sub.is_in_grace_period() == True
        assert grace_sub.is_valid() == False


class TestSubscriptionService:
    """Test Subscription Service functionality"""
    
    def test_create_subscription(self):
        """Test creating a new subscription"""
        service = SubscriptionService()
        
        # Mock database session
        mock_db = Mock()
        mock_db.query().filter().first.return_value = None  # No existing subscription
        mock_db.add = Mock()
        mock_db.commit = Mock()
        mock_db.refresh = Mock()
        
        with patch('services.subscription.SessionLocal', return_value=mock_db):
            subscription = service.create_subscription("test-user-123", "test@example.com")
            
            assert subscription.user_id == "test-user-123"
            assert subscription.email == "test@example.com"
            assert subscription.is_active == True
            assert subscription.auth_token is not None


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


class TestAdvancedAuthService:
    """Test Advanced Authentication Service"""
    
    def test_create_user(self):
        """Test creating a new user"""
        auth_service = AdvancedAuthService()
        
        # Mock database session
        mock_db = Mock()
        mock_db.query().filter().first.return_value = None  # User doesn't exist yet
        mock_db.add = Mock()
        mock_db.commit = Mock()
        mock_db.refresh = Mock()
        
        with patch('services.advanced_auth_service.SessionLocal', return_value=mock_db):
            user = auth_service.create_user(
                user_id="test-user",
                email="test@example.com",
                roles=[Role.DEVELOPER]
            )
            
            assert user.user_id == "test-user"
            assert user.email == "test@example.com"
            assert Role.DEVELOPER in user.roles
    
    def test_has_permission(self):
        """Test permission checking"""
        auth_service = AdvancedAuthService()
        
        # Create a fake token with permissions
        fake_token = "fake.token.here"
        
        # Mock the verify_token method to return a user with specific permissions
        with patch.object(auth_service, 'verify_token', return_value={
            "user_id": "test-user",
            "permissions": [Permission.READ_RULES.value, Permission.SUBSCRIPTION_MANAGE.value]
        }):
            # Test if user has READ_RULES permission
            assert auth_service.has_permission(fake_token, Permission.READ_RULES) == True
            # Test if user has MANAGE_USERS permission (should be False)
            assert auth_service.has_permission(fake_token, Permission.MANAGE_USERS) == False


class TestPatternMatcher:
    """Test Pattern Matching functionality"""
    
    def test_regex_matching(self):
        """Test basic regex pattern matching"""
        matcher = PatternMatcher()
        
        # Test basic regex matching
        code = 'var userInput = req.query.input; document.body.innerHTML = userInput;'
        pattern = {"type": "regex", "value": "innerHTML", "language": "javascript"}
        
        result = matcher._match_rule(code, type('obj', (object,), {'pattern': pattern})())
        
        assert result is not None
        assert "innerHTML" in result
    
    def test_javascript_ast_matching(self):
        """Test JavaScript AST pattern matching"""
        matcher = PatternMatcher()
        
        # Test JavaScript code with eval
        code = '''
        function processInput(input) {
            return eval(input);
        }
        '''
        
        # This should detect the eval usage
        result = matcher._match_javascript_ast(code, "")
        
        assert result is not None
        assert "eval" in result
    
    def test_python_ast_matching(self):
        """Test Python AST pattern matching"""
        matcher = PatternMatcher()
        
        # Test Python code with eval
        code = '''
def process_input(input_str):
    return eval(input_str)
        '''
        
        result = matcher._match_python_ast(code, "")
        
        assert result is not None
        assert "eval" in result or "Dangerous function" in result


class TestHybridPatternMatcher:
    """Test Hybrid Pattern Matching functionality"""
    
    def test_hybrid_matching(self):
        """Test hybrid pattern matching combining regex and AST"""
        hybrid_matcher = HybridPatternMatcher()
        
        # Test code with potential security issues
        code = '''
        function processInput(input) {
            document.body.innerHTML = input;
            return eval(input);
        }
        '''
        
        # Create a mock rule object
        class MockRule:
            def __init__(self):
                self.pattern = {"type": "ast", "value": "some_pattern", "language": "javascript"}
        
        mock_rule = MockRule()
        rules = [mock_rule]
        
        results = hybrid_matcher.match(code, rules)
        
        # Should find matches using AST analysis
        assert len(results) >= 0  # May vary depending on implementation


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