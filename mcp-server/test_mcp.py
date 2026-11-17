#!/usr/bin/env python3
"""
MCP Server Test Script
Tests MCP server functionality without IDE
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from database import SessionLocal, Base, engine
from models.rule import LocalRule
from services.enforcer import Enforcer
from services.infra_detector import InfrastructureDetector

# Create tables
Base.metadata.create_all(bind=engine)

def test_enforcer():
    """Test code enforcement"""
    print("="*60)
    print("MCP Enforcer Test")
    print("="*60)
    
    db = SessionLocal()
    
    # Add test rule
    test_rule = LocalRule(
        rule_id="DSV-2026-9999",
        rule_type="cwe",
        source="cwe",
        severity="high",
        title="Hardcoded Credentials",
        description="Never hardcode credentials",
        pattern={
            "type": "regex",
            "value": r"API_KEY\s*=\s*['\"][^'\"]+['\"]",
            "language": "python"
        },
        applies_to={
            "languages": ["python"],
            "contexts": ["backend"]
        },
        enforcement={
            "level": "block",
            "message": "Your code has a hardcoded API key. Move it to environment variables.",
            "required_actions": ["Use environment variables", "Use secrets manager"]
        }
    )
    db.add(test_rule)
    db.commit()
    
    # Test code with violation
    bad_code = """
import requests

API_KEY = "sk_live_abc123xyz"
response = requests.get("https://api.example.com", headers={"Authorization": API_KEY})
"""
    
    # Test code without violation
    good_code = """
import requests
import os

API_KEY = os.environ.get("API_KEY")
response = requests.get("https://api.example.com", headers={"Authorization": API_KEY})
"""
    
    # Get rules
    rules = db.query(LocalRule).all()
    
    # Test enforcement
    enforcer = Enforcer()
    
    print("\n[TEST 1] Bad code (should be BLOCKED):")
    print("-" * 60)
    result = enforcer.enforce(bad_code, rules)
    print(f"Blocked: {result.get('blocked')}")
    print(f"Violations: {result.get('violation_count', 0)}")
    if result.get('violations'):
        print(f"Message: {result['violations'][0]['message']}")
    
    print("\n[TEST 2] Good code (should PASS):")
    print("-" * 60)
    result = enforcer.enforce(good_code, rules)
    print(f"Blocked: {result.get('blocked')}")
    print(f"Compliant: {result.get('compliant')}")
    
    print("\n[TEST 3] Infrastructure Detection:")
    print("-" * 60)
    detector = InfrastructureDetector()
    stack = detector.detect(".")
    print(f"Detected: {stack}")
    
    print("\n" + "="*60)
    print("✓ MCP Tests Complete")
    print("="*60)
    
    db.close()

if __name__ == "__main__":
    test_enforcer()
