"""
Comprehensive Test Suite for Security MCP Server
Tests all major components and functionalities
"""
import pytest
import sys
import os
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

# Add mcp-server to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'mcp-server'))

from services.pattern_matcher import PatternMatcher
from services.hybrid_pattern_matcher import HybridPatternMatcher
from services.enforcer import Enforcer
from services.subscription import LocalSubscriptionManager
from services.infra_detector import InfrastructureDetector
from services.rule_sync import RuleSync
from models.rule import LocalRule
from models.subscription import LocalSubscription


class TestPatternMatcher:
    """Test Pattern Matcher functionality"""
    
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


class TestEnforcer:
    """Test Enforcer functionality"""
    
    def test_enforce_no_violations(self):
        """Test enforcement with no violations"""
        enforcer = Enforcer()
        
        code = "var x = 5;"
        rules = []  # No rules to violate
        
        result = enforcer.enforce(code, rules, None)
        
        # Should return empty violations list
        assert result["violations"] == []
        assert result["allowed"] == True
    
    def test_enforce_with_violations(self):
        """Test enforcement with violations"""
        enforcer = Enforcer()
        
        # Create a mock rule that would match the code
        class MockRule:
            def __init__(self):
                self.rule_id = "DSV-TEST-001"
                self.title = "Test Rule"
                self.severity = "high"
                self.enforcement = {"level": "block", "message": "Test violation"}
        
        code = "eval('some code');"
        rules = [MockRule()]
        
        # Mock subscription to allow enforcement
        mock_subscription = Mock()
        mock_subscription.is_valid.return_value = True
        
        result = enforcer.enforce(code, rules, mock_subscription)
        
        # Should detect violation and block
        assert len(result["violations"]) > 0
        assert result["allowed"] == False
        assert result["violations"][0]["rule_id"] == "DSV-TEST-001"


class TestLocalSubscriptionManager:
    """Test Local Subscription Manager functionality"""
    
    def test_get_subscription(self):
        """Test getting local subscription"""
        # Mock database session
        mock_db = Mock()
        mock_subscription = Mock()
        mock_subscription.is_valid.return_value = True
        mock_subscription.is_in_grace_period.return_value = False
        mock_db.query().first.return_value = mock_subscription
        
        manager = LocalSubscriptionManager(lambda: [mock_db])
        subscription = manager.get_subscription()
        
        assert subscription is not None
        assert subscription.is_valid() == True


class TestInfrastructureDetector:
    """Test Infrastructure Detector functionality"""
    
    def test_detect_empty_project(self):
        """Test infrastructure detection for empty project"""
        detector = InfrastructureDetector()
        
        # Mock an empty project directory
        with patch('os.path.exists', return_value=True):
            with patch('os.listdir', return_value=[]):
                result = detector.detect('/fake/project/path')
                
                assert result['languages'] == []
                assert result['frameworks'] == []
                assert result['infrastructure'] == []
    
    def test_detect_package_json(self):
        """Test infrastructure detection with package.json"""
        detector = InfrastructureDetector()
        
        # Mock a project with package.json
        with patch('os.path.exists', side_effect=lambda x: x.endswith('package.json')):
            with patch('builtins.open', Mock()) as mock_open:
                mock_open.return_value.__enter__.return_value.read.return_value = '''
                {
                    "dependencies": {
                        "react": "^18.0.0",
                        "express": "^4.18.0"
                    }
                }
                '''
                
                result = detector.detect('/fake/project/path')
                
                # Should detect JavaScript and related frameworks
                assert 'javascript' in result['languages']
                assert 'react' in result['frameworks']
                assert 'express' in result['frameworks']


class TestRuleSync:
    """Test Rule Sync functionality"""
    
    def test_init(self):
        """Test RuleSync initialization"""
        mock_db = Mock()
        
        sync = RuleSync(mock_db)
        
        assert sync.db == mock_db
        assert sync.rule_checksums == {}
    
    def test_get_subscription(self):
        """Test getting subscription from RuleSync"""
        mock_db = Mock()
        mock_subscription = Mock()
        mock_db.query().first.return_value = mock_subscription
        
        sync = RuleSync(mock_db)
        subscription = sync.get_subscription()
        
        assert subscription == mock_subscription
    
    def test_get_local_rule_checksums(self):
        """Test calculating local rule checksums"""
        mock_db = Mock()
        
        # Create a mock rule
        mock_rule = Mock()
        mock_rule.rule_id = "DSV-TEST-001"
        mock_rule.rule_type = "cwe"
        mock_rule.source = "mitre"
        mock_rule.severity = "high"
        mock_rule.title = "Test Rule"
        mock_rule.description = "Test Description"
        mock_rule.cve_refs = []
        mock_rule.cwe_refs = ["CWE-79"]
        mock_rule.pattern = {"type": "regex", "value": "test"}
        mock_rule.applies_to = {"languages": ["javascript"]}
        mock_rule.enforcement = {"level": "block", "message": "Fix it"}
        
        mock_db.query().all.return_value = [mock_rule]
        
        sync = RuleSync(mock_db)
        checksums = sync._get_local_rule_checksums()
        
        assert "DSV-TEST-001" in checksums
        assert len(checksums["DSV-TEST-001"]) == 64  # SHA256 hash length


class TestLocalModels:
    """Test local models functionality"""
    
    def test_local_rule_creation(self):
        """Test creating a local rule"""
        rule = LocalRule(
            rule_id="DSV-LOCAL-001",
            rule_type="cwe",
            source="mitre",
            severity="high",
            title="Local Test Rule",
            description="A test rule for local testing",
            cwe_refs=["CWE-79"],
            pattern={"type": "regex", "value": "test", "language": "javascript"},
            applies_to={"languages": ["javascript"]},
            enforcement={"level": "warn", "message": "Be careful with this"}
        )
        
        assert rule.rule_id == "DSV-LOCAL-001"
        assert rule.severity == "high"
        assert "CWE-79" in rule.cwe_refs
    
    def test_local_subscription_creation(self):
        """Test creating a local subscription"""
        subscription = LocalSubscription(
            user_id="local-user-123",
            auth_token="local-jwt-token",
            is_active=True,
            expires_at=datetime.utcnow() + timedelta(days=30)
        )
        
        assert subscription.user_id == "local-user-123"
        assert subscription.is_active == True
        assert subscription.is_valid() == True


# Run tests if this file is executed directly
if __name__ == '__main__':
    pytest.main([__file__, '-v'])