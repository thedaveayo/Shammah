#!/usr/bin/env python3
"""
Test Single CWE Ingestion
Tests CWE → DSV rule conversion with one example
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from database import SessionLocal, Base, engine
from services.cwe_fetcher import CWEFetcher
from services.rule_cache import RuleCache

# Create tables
Base.metadata.create_all(bind=engine)

def test_single_cwe():
    """Test ingestion of a single CWE entry"""
    
    # Sample CWE-798 data (Hardcoded Credentials)
    test_cwe = {
        "id": "798",
        "name": "Use of Hard-coded Credentials",
        "status": "Final",
        "description": """The software contains hard-coded credentials, 
        such as a password or cryptographic key, and uses it for its own 
        inbound authentication, outbound communication to external components, 
        or encryption of internal resources.""",
        "example_code": """// Vulnerable code
String password = "admin123";
Connection conn = DriverManager.getConnection(url, "admin", password);""",
        "remediation": """Use environment variables or a secure vault 
        to store credentials. Never hardcode them in source code."""
    }
    
    print("=" * 60)
    print("Testing Single CWE Ingestion")
    print("=" * 60)
    print(f"\nCWE-{test_cwe['id']}: {test_cwe['name']}")
    print(f"\nDescription: {test_cwe['description'][:100]}...")
    
    db = SessionLocal()
    
    try:
        # Test CWE fetcher
        fetcher = CWEFetcher()
        
        print("\n[1/3] Converting CWE to rule patterns (using Qwen)...")
        rule = fetcher.convert_cwe_to_rule(test_cwe)
        
        if not rule:
            print("✗ Failed to convert CWE to rule")
            return False
        
        print(f"✓ Rule created: {rule.rule_id}")
        print(f"  - Severity: {rule.severity}")
        print(f"  - CWE Refs: {rule.cwe_refs}")
        print(f"  - Pattern Type: {rule.pattern.get('type') if rule.pattern else 'None'}")
        print(f"  - Applies to: {rule.applies_to}")
        print(f"\n  - Message: {rule.enforcement.get('message', 'N/A')[:100]}...")
        
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
        print("✓ Single CWE Test PASSED!")
        print("=" * 60)
        print(f"\nNext: Run full CWE ingestion with:")
        print(f"  curl -X POST http://localhost:8000/api/fetch/cwe")
        print(f"\nThis will process all ~600 CWEs (takes 30-60 min)")
        
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        db.rollback()
        return False
    finally:
        db.close()

if __name__ == "__main__":
    success = test_single_cwe()
    sys.exit(0 if success else 1)
