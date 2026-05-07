"""
Rule Generator Service
LLM-powered rule extraction from CWE and Telegram articles
Uses Alibaba Qwen Flash via OpenAI-compatible API
"""
import json
import sys
import os
from typing import Dict, List, Optional

# Add backend to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from openai import OpenAI  # Qwen is OpenAI-compatible
from config import QWEN_API_KEY, QWEN_BASE_URL, LLM_MODEL, LLM_TEMPERATURE
from models.rule import Rule
from services.id_generator import generate_internal_id

# Initialize Qwen client (OpenAI-compatible API, Singapore endpoint)
client = OpenAI(
    api_key=QWEN_API_KEY,
    base_url=QWEN_BASE_URL
) if QWEN_API_KEY and QWEN_BASE_URL else None

def llm_extract_cwe_patterns(cwe_data: Dict) -> Optional[Dict]:
    """
    Use Qwen LLM to convert abstract CWE description to concrete code patterns
    Returns pattern data for Rule creation
    """
    if not client:
        print("Qwen client not initialized. Set QWEN_API_KEY in .env")
        return None
    
    prompt = f"""You are a security expert. Convert CWE weakness descriptions to concrete, enforceable code patterns.

CWE Name: {cwe_data.get('name', 'Unknown')}
CWE ID: {cwe_data.get('id', 'Unknown')}
Description: {cwe_data.get('description', '')}
Example Code: {cwe_data.get('example_code', '')}
Remediation: {cwe_data.get('remediation', '')}

Generate ONLY valid JSON (no markdown, no explanations) with this exact structure:
{{
    "pattern": {{"type": "regex", "value": "...", "language": "javascript"}},
    "applies_to": {{"languages": ["javascript", "python"], "frameworks": ["react"], "contexts": ["frontend", "backend"]}},
    "severity": "high",
    "message": "Plain English explanation for users (lay terms, not technical jargon)",
    "required_actions": ["Action 1", "Action 2"]
}}

Rules:
- pattern.type: "regex" or "ast"
- pattern.value: Actual regex pattern to match vulnerable code
- pattern.language: Target programming language
- severity: critical/high/medium/low based on impact
- message: Simple explanation a non-technical user understands
- required_actions: Concrete steps to fix the issue"""

    try:
        response = client.chat.completions.create(
            model=LLM_MODEL,
            messages=[
                {"role": "system", "content": "You are a security expert. Output ONLY valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=LLM_TEMPERATURE,
            response_format={"type": "json_object"}
        )
        
        result = json.loads(response.choices[0].message.content)
        return result
        
    except Exception as e:
        print(f"Qwen CWE extraction error: {e}")
        return None

def llm_extract_telegram_rule(article_text: str, existing_cwe_rules: List[Rule]) -> Dict:
    """
    Extract security rule from Telegram article using Qwen
    - Checks if article matches existing CWE (exact match only)
    - If exact match: enrich existing CWE
    - If no match or slight deviation: create new DSV rule
    - LLM determines severity (unless specified in article)
    """
    if not client:
        return None
    
    prompt = f"""You are a security analyst. Extract security weakness patterns from articles.

Article:
{article_text}

Severity guidelines:
- CRITICAL: Remote code execution, auth bypass, data exfiltration
- HIGH: Privilege escalation, sensitive data exposure
- MEDIUM: DoS, limited impact bugs, security misconfigurations
- LOW: Information disclosure, minor misconfigurations, best practice violations

If the article explicitly states severity (e.g., "severity: high"), use theirs.
Otherwise, determine based on impact.

Generate ONLY valid JSON (no markdown, no explanations) with this exact structure:
{{
    "cwe_refs": ["CWE-798"],
    "pattern": {{"type": "regex", "value": "...", "language": "javascript"}},
    "applies_to": {{"languages": ["javascript"], "frameworks": ["react"], "contexts": ["frontend"]}},
    "severity": "HIGH",
    "message": "Plain English explanation...",
    "required_actions": ["Action 1", "Action 2"],
    "source_link": "https://...",
    "is_exact_cwe_match": false
}}

Rules:
- cwe_refs: List of related CWE IDs (if any), empty list if none
- pattern: Code pattern to detect this weakness
- applies_to: Where this applies
- severity: CRITICAL/HIGH/MEDIUM/LOW (uppercase)
- message: Simple explanation for users
- required_actions: Concrete fix steps
- source_link: URL from the article (if present)
- is_exact_cwe_match: false (create new DSV unless EXACTLY matches existing CWE)"""

    try:
        response = client.chat.completions.create(
            model=LLM_MODEL,
            messages=[
                {"role": "system", "content": "You are a security analyst. Output ONLY valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=LLM_TEMPERATURE,
            response_format={"type": "json_object"}
        )
        
        result = json.loads(response.choices[0].message.content)
        return result
        
    except Exception as e:
        print(f"Qwen Telegram extraction error: {e}")
        return None
