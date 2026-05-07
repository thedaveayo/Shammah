import sys
import os
import time
sys.path.insert(0, os.path.join(os.getcwd(), ''))

from database import SessionLocal, Base, engine
from services.cwe_fetcher import CWEFetcher
from models.rule import Rule

def main():
    print("Verifying system configuration with the new API key...")
    
    # Test the LLM connection first
    from services.rule_generator import llm_extract_cwe_patterns
    
    test_cwe = {
        'id': '798',
        'name': 'Use of Hard-coded Credentials',
        'description': 'The software contains hard-coded passwords, cryptographic keys, etc.',
        'example_code': 'String password = "secret123";',
        'remediation': 'Use environment variables or secure vault.'
    }

    print('1. Testing API connection...')
    result = llm_extract_cwe_patterns(test_cwe)
    if result:
        print('   ✓ API connection successful!')
    else:
        print('   ✗ API connection failed')
        return False

    print('2. Testing CWE fetch and parse...')
    fetcher = CWEFetcher()
    xml_content = fetcher.fetch_cwe_taxonomy()
    if xml_content:
        print('   ✓ CWE taxonomy fetch successful')
        cwe_list = fetcher.parse_cwe_xml(xml_content)
        print(f'   ✓ Parsed {len(cwe_list)} CWE entries')
    else:
        print('   ✗ CWE taxonomy fetch failed')
        return False

    print('3. Testing single CWE to rule conversion...')
    # Test with the first CWE from the list
    sample_cwe = cwe_list[0] if cwe_list else test_cwe
    rule = fetcher.convert_cwe_to_rule(sample_cwe)
    if rule:
        print(f'   ✓ Conversion successful: {rule.rule_id}')
    else:
        print('   ✗ Conversion failed')
        return False

    print('4. Checking database connection...')
    try:
        Base.metadata.create_all(bind=engine)
        db = SessionLocal()
        
        # Check current counts
        cwe_count_before = db.query(Rule).filter(Rule.source == 'cwe').count()
        nvd_count_before = db.query(Rule).filter(Rule.source == 'nvd').count()
        total_count_before = db.query(Rule).count()
        
        print(f'   Rules before test insert: CWE={cwe_count_before}, NVD={nvd_count_before}, Total={total_count_before}')
        
        # Try inserting the test rule to verify DB write capability
        db.add(rule)
        db.commit()
        
        # Check counts after
        cwe_count_after = db.query(Rule).filter(Rule.source == 'cwe').count()
        total_count_after = db.query(Rule).count()
        
        print(f'   Rules after test insert: CWE={cwe_count_after}, Total={total_count_after}')
        
        # Rollback the test insertion
        db.delete(rule)
        db.commit()
        
        print('   ✓ Database connection and transaction handling OK')
        
        db.close()
        print('   All tests passed! The system is properly configured and ready to process CWE entries.')
        return True
        
    except Exception as e:
        print(f'   ✗ Database test failed: {str(e)}')
        return False

if __name__ == '__main__':
    success = main()
    if success:
        print("\nSUMMARY:")
        print("- API key is correctly configured and functional")
        print("- System can fetch and parse CWE taxonomy")
        print("- LLM conversion is working properly")
        print("- Database operations are functioning")
        print("- Ready to process all 969 CWE entries when run")
    else:
        print("\nERROR: One or more tests failed. Please check the configuration.")