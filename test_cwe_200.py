#!/usr/bin/env python3
"""
Test CWE-200 Ingestion
CWE-200: Information Exposure
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from database import SessionLocal, Base, engine
from services.cwe_fetcher import CWEFetcher
from services.rule_cache import RuleCache

# Create tables
Base.metadata.create_all(bind=engine)

def test_cwe_200():
    """Test ingestion of CWE-200: Information Exposure"""
    
    # Sample CWE-200 data
    test_cwe = {
        "id": "200",
        "name": "Information Exposure",
        "status": "Final",
        "description": """An information exposure is the intentional or unintentional 
        disclosure of information to an actor that is not explicitly authorized to have 
        access to that information. This can include sensitive data like API responses, 
        error messages, stack traces, or internal system details.""",
        "example_code": """// Vulnerable: Exposing stack trace to user
try {
    processUserInput(input);
} catch (Exception e) {
    response.send(e.getStackTrace());  // BAD!
}""",
        "remediation": """Log detailed errors server-side only. 
        Return generic error messages to users. Never expose stack traces 
        or internal details in production."""
    }
    
    print("=" * 60)
    print("Testing CWE-200: Information Exposure")
    print("=" * 60)
    print(f"\nCWE-{test_cwe['id']}: {test_cwe['name']}")
    print(f"\nDescription: {test_cwe['description'][:120]}...")
    
    db = SessionLocal()
    
    try:
        fetcher = CWEFetcher()
        
        print("\n[1/3] Converting CWE-200 to rule patterns (using Qwen)...")
        rule = fetcher.convert_cwe_to_rule(test_cwe)
        
        if not rule:
            print("✗ Failed to convert CWE-200 to rule")
            return False
        
        print(f"✓ Rule created: {rule.rule_id}")
        print(f"  - Severity: {rule.severity}")
        print(f"  - CWE Refs: {rule.cwe_refs}")
        print(f"  - Pattern Type: {rule.pattern.get('type') if rule.pattern else 'None'}")
        if rule.pattern:
            print(f"  - Pattern Value: {rule.pattern.get('value', 'N/A')[:80]}...")
        print(f"  - Applies to: {rule.applies_to}")
        print(f"\n  - Message: {rule.enforcement.get('message', 'N/A')[:120]}...")
        print(f"\n  - Required Actions:")
        for action in rule.enforcement.get('required_actions', []):
            print(f"      • {action}")
        
        print("\n[2/3] Saving to database...")
        db.add(rule)
        db.commit()
        print("✓ Saved to database")
        
        print("\n[3/3] Verifying...")
        cache = RuleCache(db)
        saved_rule = cache.get_rule_by_id(rule.rule_id)
        
        if saved_rule:
            print(f"✓ Verified: Rule exists in database")
        else:
            print("✗ Verification failed: Rule not found")
            return False
        
        print("\n" + "=" * 60)
        print("✓ CWE-200 Test PASSED!")
        print("=" * 60)
        
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        db.rollback()
        return False
    finally:
        db.close()

if __name__ == "__main__":
    success = test_cwe_200()
    sys.exit(0 if success else 1)
