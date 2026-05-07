"""
Quick-Fix Suggestion Service
Generates specific code fixes for security vulnerabilities
"""
import json
import sys
import os
from typing import Dict, List, Optional

# Add backend to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from openai import OpenAI  # Qwen is OpenAI-compatible
from config import QWEN_API_KEY, QWEN_BASE_URL, LLM_MODEL, LLM_TEMPERATURE

# Initialize Qwen client (OpenAI-compatible API, Singapore endpoint)
client = OpenAI(
    api_key=QWEN_API_KEY,
    base_url=QWEN_BASE_URL
) if QWEN_API_KEY and QWEN_BASE_URL else None

def generate_quick_fix_suggestions(code_snippet: str, rule_description: str, language: str = "javascript") -> Optional[List[Dict]]:
    """
    Generate specific code fixes for a security vulnerability
    Returns list of fix suggestions with before/after examples
    """
    if not client:
        print("Qwen client not initialized. Set QWEN_API_KEY in .env")
        return None

    prompt = f"""You are a senior security engineer. Provide specific code fixes for the security vulnerability in the code snippet.

Language: {language}
Vulnerability: {rule_description}
Code Snippet:
{code_snippet}

Generate ONLY valid JSON (no markdown, no explanations) with this exact structure:
{{
    "fixes": [
        {{
            "title": "Brief title of the fix",
            "description": "Detailed explanation of the fix",
            "before": "Original vulnerable code (copy exactly from snippet)",
            "after": "Fixed code with security measures applied",
            "confidence": "high/medium/low",
            "complexity": "simple/moderate/complex"
        }}
    ]
}}

Rules:
- Each fix should be a practical, implementable solution
- The 'before' should match the exact code from the snippet
- The 'after' should show the corrected code with security measures
- Provide multiple approaches when possible
- Focus on security best practices for the given language/framework"""

    try:
        response = client.chat.completions.create(
            model=LLM_MODEL,
            messages=[
                {"role": "system", "content": "You are a senior security engineer. Output ONLY valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=LLM_TEMPERATURE,
            response_format={"type": "json_object"}
        )

        result = json.loads(response.choices[0].message.content)
        return result.get("fixes", [])

    except Exception as e:
        print(f"Qwen quick-fix generation error: {e}")
        return None

def generate_fix_from_rule_and_code(rule: 'Rule', code: str, language: str = "javascript") -> Optional[List[Dict]]:
    """
    Generate specific fixes based on a rule and code snippet
    """
    rule_info = f"{rule.title}: {rule.description}"
    if rule.enforcement and "message" in rule.enforcement:
        rule_info += f" - {rule.enforcement['message']}"
    
    return generate_quick_fix_suggestions(code, rule_info, language)