"""
Security Scanner Service
Handles scanning code for security vulnerabilities
"""
import re
import ast
from typing import Dict, List, Any
from datetime import datetime
import json

class SecurityScanner:
    """Scans code for security vulnerabilities"""
    
    def __init__(self):
        # Load security rules from database or configuration
        self.rules = self._load_security_rules()
    
    def _load_security_rules(self) -> List[Dict]:
        """
        Load security rules from the database
        In a real implementation, this would connect to the database
        """
        # This is a placeholder - in the real system, this would fetch from the DB
        return [
            {
                "id": "CWE-79",
                "title": "Cross-site Scripting (XSS)",
                "severity": "high",
                "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page.",
                "patterns": [
                    {"type": "regex", "value": r"innerHTML\s*=", "language": "javascript"},
                    {"type": "regex", "value": r"document\.write\s*\(.*\)", "language": "javascript"}
                ],
                "recommendation": "Use frameworks that automatically escape content or manually escape HTML entities."
            },
            {
                "id": "CWE-89",
                "title": "SQL Injection",
                "severity": "critical",
                "description": "The software constructs all or part of an SQL command using externally-influenced input from an upstream component.",
                "patterns": [
                    {"type": "regex", "value": r"SELECT.*\$.*\$", "language": "sql"},
                    {"type": "regex", "value": r"INSERT.*\$.*\$", "language": "sql"}
                ],
                "recommendation": "Use parameterized queries or prepared statements."
            },
            {
                "id": "CWE-73",
                "title": "External Control of File Name or Path",
                "severity": "high",
                "description": "The software allows user input to control paths or filenames that are used in filesystem operations.",
                "patterns": [
                    {"type": "regex", "value": r"open\s*\(\s*[+]", "language": "python"},
                    {"type": "regex", "value": r"fopen\s*\(\s*\$", "language": "php"}
                ],
                "recommendation": "Validate and sanitize all file paths before using them in filesystem operations."
            }
        ]
    
    def scan_code_block(self, code_block: str, language: str = "unknown", context: str = "unknown") -> Dict:
        """
        Scan a code block for security vulnerabilities
        """
        issues = []
        lines = code_block.split('\n')
        
        # Check each rule against the code
        for rule in self.rules:
            if language.lower() in rule.get("patterns", [{}])[0].get("language", "").lower() or \
               rule.get("patterns", [{}])[0].get("language", "").lower() == "all":
                
                for pattern in rule.get("patterns", []):
                    if pattern.get("language").lower() == language.lower() or pattern.get("language").lower() == "all":
                        if pattern["type"] == "regex":
                            matches = re.findall(pattern["value"], code_block, re.IGNORECASE)
                            if matches:
                                issues.append({
                                    "id": rule["id"],
                                    "title": rule["title"],
                                    "severity": rule["severity"],
                                    "description": rule["description"],
                                    "recommendation": rule["recommendation"],
                                    "matched_patterns": matches[:5],  # Limit to first 5 matches
                                    "context": context
                                })
        
        return {
            "issues": issues,
            "lines": lines,
            "language": language,
            "scan_time": datetime.utcnow().isoformat()
        }
    
    def generate_project_report(self, project_path: str, report_type: str = "summary") -> str:
        """
        Generate a security report for the entire project
        """
        # This would normally scan the entire project
        # For now, we'll return a placeholder report
        if report_type == "summary":
            return f"""
Security Report for Project: {project_path}

Summary:
- Total files scanned: 0 (placeholder)
- Critical vulnerabilities: 0
- High vulnerabilities: 0
- Medium vulnerabilities: 0
- Low vulnerabilities: 0

Recommendation: Run full project scan for complete analysis.
            """.strip()
        elif report_type == "detailed":
            return f"""
Detailed Security Report for Project: {project_path}

No detailed scan performed in this demo.

To perform a detailed scan:
1. Analyze all source files in the project
2. Check for dependencies with known vulnerabilities
3. Verify proper configuration of security settings
4. Identify hardcoded credentials
5. Check for proper input validation
            """.strip()
        elif report_type == "fixes":
            return f"""
Fix Suggestions Report for Project: {project_path}

No fixes identified in this demo.

Common fixes include:
- Use parameterized queries to prevent SQL injection
- Escape output to prevent XSS
- Validate and sanitize all inputs
- Use secure configuration management
- Apply principle of least privilege
            """.strip()
        else:
            return f"Unknown report type: {report_type}"
    
    def get_fix_suggestions(self, code_block: str, vulnerability_types: List[str] = None) -> List[Dict]:
        """
        Get specific fix suggestions for security issues in code
        """
        suggestions = []
        
        # Basic fix suggestions based on common patterns
        if "eval(" in code_block or "eval (" in code_block:
            suggestions.append({
                "title": "Avoid using eval()",
                "issue": "Using eval() can execute arbitrary code and poses a security risk",
                "fix": "Replace eval() with safer alternatives like JSON.parse() for data parsing, or use a whitelist of allowed operations."
            })
        
        if "innerHTML" in code_block:
            suggestions.append({
                "title": "Avoid using innerHTML",
                "issue": "Using innerHTML can lead to cross-site scripting (XSS) vulnerabilities",
                "fix": "Use textContent for plain text, or use a sanitization library when inserting HTML."
            })
        
        if re.search(r"SELECT.*\$.*\$", code_block, re.IGNORECASE):
            suggestions.append({
                "title": "Use parameterized queries",
                "issue": "String concatenation in SQL queries can lead to SQL injection",
                "fix": "Use parameterized queries or prepared statements instead of string concatenation."
            })
        
        if "password" in code_block.lower() and ("=" in code_block) and ("\"" in code_block or "'" in code_block):
            # Check if it's a hardcoded password assignment
            lines = code_block.split('\n')
            for line in lines:
                if "password" in line.lower() and ("=" in line) and ("\"" in line or "'" in line):
                    # This is a simplified check - in reality, you'd want more sophisticated analysis
                    suggestions.append({
                        "title": "Avoid hardcoded credentials",
                        "issue": "Credentials should not be hardcoded in source code",
                        "fix": "Move credentials to environment variables or a secure configuration management system."
                    })
                    break
        
        # Filter by requested vulnerability types if specified
        if vulnerability_types:
            suggestions = [s for s in suggestions if any(vtype.lower() in s["title"].lower() for vtype in vulnerability_types)]
        
        return suggestions