"""
Pattern Matcher Service
Matches code against rule patterns (regex/AST)
"""
import re
import ast
from typing import List, Dict, Optional, Tuple

class PatternMatcher:
    """Matches code against security rule patterns"""

    def match(self, code: str, rules: List) -> List[Tuple]:
        """
        Match code against all rules
        Returns list of (rule, matched_text) tuples for violations
        """
        violations = []

        for rule in rules:
            match_result = self._match_rule(code, rule)
            if match_result:
                violations.append((rule, match_result))

        return violations

    def _match_rule(self, code: str, rule) -> Optional[str]:
        """Match code against a single rule"""
        pattern = rule.pattern if hasattr(rule, 'pattern') else None

        if not pattern:
            return None

        pattern_type = pattern.get("type", "regex") if isinstance(pattern, dict) else "regex"
        pattern_value = pattern.get("value", "") if isinstance(pattern, dict) else str(pattern)
        language = pattern.get("language", "javascript") if isinstance(pattern, dict) else "javascript"

        if pattern_type == "regex":
            return self._match_regex(code, pattern_value)
        elif pattern_type == "ast":
            if language.lower() == "javascript":
                return self._match_javascript_ast(code, pattern_value)
            elif language.lower() == "python":
                return self._match_python_ast(code, pattern_value)
            else:
                # For unsupported languages, fall back to regex
                return self._match_regex(code, pattern_value)
        elif pattern_type == "file_exists":
            return self._match_file_exists(code, pattern_value)

        return None

    def _match_regex(self, code: str, pattern: str) -> Optional[str]:
        """Match code against regex pattern"""
        try:
            match = re.search(pattern, code, re.MULTILINE | re.IGNORECASE)
            if match:
                return match.group(0)
        except re.error:
            print(f"Invalid regex pattern: {pattern}")
        return None

    def _match_javascript_ast(self, code: str, pattern: str) -> Optional[str]:
        """Match JavaScript code against AST pattern - enhanced version"""
        # This is a more sophisticated simulation of JavaScript AST matching
        # In a real implementation, we would use a JavaScript parsing library
        
        # Check for dangerous JavaScript patterns that indicate security issues
        issues_found = []
        
        # Look for eval usage
        if re.search(r'\beval\s*\(', code):
            issues_found.append("eval() usage detected")
        
        # Look for Function constructor usage
        if re.search(r'(new\s+Function|Function\s*\(\s*["\'])', code):
            issues_found.append("Function constructor usage detected")
        
        # Look for setTimeout/setInterval with string arguments (potential code injection)
        if re.search(r'(setTimeout|setInterval)\s*\(\s*["\']', code):
            issues_found.append("setTimeout/setInterval with string argument detected")
        
        # Look for DOM XSS patterns
        dom_xss_patterns = [
            r'\.innerHTML\s*=',
            r'\.outerHTML\s*=',
            r'\.insertAdjacentHTML\s*\(',
            r'document\.write\s*\('
        ]
        
        for pattern in dom_xss_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                issues_found.append(f"Potential DOM XSS via {pattern.split('(')[0].strip()} detected")
        
        # Look for direct cookie manipulation
        if re.search(r'document\.cookie', code, re.IGNORECASE):
            issues_found.append("Direct cookie manipulation detected")
        
        # Look for storage access
        if re.search(r'(localStorage|sessionStorage)\.', code, re.IGNORECASE):
            issues_found.append("Web storage access detected")
        
        # Look for dynamic script injection
        if re.search(r'document\.createElement\s*\(\s*["\']script["\']', code, re.IGNORECASE):
            issues_found.append("Dynamic script element creation detected")
        
        # Look for URL manipulation that might lead to open redirects
        if re.search(r'(location\s*\.=|window\.location\s*\.=|document\.location\s*\.=)', code, re.IGNORECASE):
            issues_found.append("URL redirection detected")
        
        # Look for potential command injection patterns
        if re.search(r'(exec|spawn|fork)\s*\(', code):
            issues_found.append("Potential command execution detected")
        
        if issues_found:
            return "; ".join(issues_found)
        
        return None

    def _match_python_ast(self, code: str, pattern: str) -> Optional[str]:
        """Match Python code against AST pattern"""
        try:
            # Parse the Python code into an AST
            tree = ast.parse(code)
            
            # Walk the AST to find patterns
            for node in ast.walk(tree):
                # Check for dangerous function calls
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                        if func_name in ['eval', 'exec', 'compile']:
                            return f"Dangerous function '{func_name}' detected"
                        elif func_name == 'input':
                            return "Unvalidated user input detected"
                        elif func_name == 'open':
                            # Check if it's a potentially unsafe file operation
                            args = node.args
                            if args and isinstance(args[0], ast.Constant) and '..' in str(args[0].value):
                                return "Potential path traversal detected"
                        elif func_name in ['os.system', 'subprocess.call', 'subprocess.run']:
                            # Check if command is constructed from user input
                            return "Potential command injection detected"
                    
                    # Check for attribute access like eval
                    elif isinstance(node.func, ast.Attribute):
                        attr_name = node.func.attr
                        if attr_name in ['eval', 'exec']:
                            return f"Dangerous method '{attr_name}' detected"
                            
                # Check for hardcoded credentials
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            if 'password' in target.id.lower() or 'key' in target.id.lower() or 'secret' in target.id.lower():
                                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                    return f"Hardcoded credential in variable '{target.id}' detected"
        
            return None
        except SyntaxError:
            # If we can't parse the Python code, fall back to regex
            return self._match_regex(code, pattern)
        except Exception as e:
            print(f"Error in Python AST matching: {e}")
            # Fall back to regex if AST parsing fails
            return self._match_regex(code, pattern)

    def _match_file_exists(self, code: str, pattern: str) -> Optional[str]:
        """Check if file pattern exists"""
        if pattern in code:
            return pattern
        return None
