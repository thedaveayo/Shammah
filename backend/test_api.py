import sys
import os
sys.path.insert(0, os.path.join(os.getcwd(), '.'))

from services.rule_generator import llm_extract_cwe_patterns

# Test with a simple CWE entry
test_cwe = {
    'id': '798',
    'name': 'Use of Hard-coded Credentials',
    'description': 'The software contains hard-coded passwords, cryptographic keys, etc.',
    'example_code': 'String password = "secret123";',
    'remediation': 'Use environment variables or secure vault.'
}

print('Testing API connection with simple CWE...')
result = llm_extract_cwe_patterns(test_cwe)
if result:
    print('API connection successful!')
    print(f'Result: {result.get("severity", "N/A")} severity pattern')
    print(f'Message: {result.get("message", "N/A")}')
else:
    print('API connection failed - check API key and configuration')