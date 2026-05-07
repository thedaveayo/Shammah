import sys
import os
sys.path.insert(0, os.path.join(os.getcwd(), ''))

from database import SessionLocal, Base, engine
from services.cwe_fetcher import CWEFetcher
from models.rule import Rule

# Create tables
Base.metadata.create_all(bind=engine)

db = SessionLocal()
fetcher = CWEFetcher()

print('Testing CWE fetch and parse...')

# Fetch and parse the CWE taxonomy
xml_content = fetcher.fetch_cwe_taxonomy()
if xml_content:
    print('Successfully fetched CWE taxonomy')
    cwe_list = fetcher.parse_cwe_xml(xml_content)
    print(f'Parsed {len(cwe_list)} CWE entries')
    
    # Only process the first 5 for testing
    print('Processing first 5 CWE entries to test LLM conversion...')
    processed_count = 0
    for i, cwe_data in enumerate(cwe_list[:5]):  # Limit to first 5
        print(f"Processing {i+1}/5: CWE-{cwe_data['id']}")
        
        rule = fetcher.convert_cwe_to_rule(cwe_data)
        if rule:
            # Check if CWE already exists
            existing = db.query(Rule).filter(Rule.cwe_refs.contains([f"CWE-{cwe_data['id']}"])).first()
            if not existing:
                db.add(rule)
                processed_count += 1
                print(f"  ✓ Created rule: {rule.rule_id}")
            else:
                print(f"  - Already exists")
        else:
            print(f"  ✗ Failed to convert to rule")
    
    db.commit()
    print(f'Completed test run. Processed {processed_count} new CWE rules.')
    
    # Check total count now
    cwe_count = db.query(Rule).filter(Rule.source == 'cwe').count()
    print(f'Total CWE-derived rules in database: {cwe_count}')
else:
    print('Failed to fetch CWE taxonomy')

db.close()
print('Test completed.')