"""
Hybrid Pattern Matcher Service
Combines regex and AST-based pattern matching for enhanced accuracy
"""
import re
import ast
from typing import List, Dict, Optional, Tuple
from services.pattern_matcher import PatternMatcher

class HybridPatternMatcher:
    """Matches code against security rule patterns using both regex and AST approaches"""

    def __init__(self):
        self.regex_matcher = PatternMatcher()

    def match(self, code: str, rules: List) -> List[Tuple]:
        """
        Match code against all rules using both regex and AST approaches
        Returns list of (rule, matched_text, match_type) tuples for violations
        """
        violations = []

        for rule in rules:
            # Try both regex and AST matching
            regex_result = self._match_rule_regex(code, rule)
            ast_result = self._match_rule_ast(code, rule)
            
            # Combine results
            if regex_result and ast_result:
                # Both detected the issue
                violations.append((rule, f"{regex_result}; {ast_result}", "both"))
            elif regex_result:
                # Only regex detected the issue
                violations.append((rule, regex_result, "regex"))
            elif ast_result:
                # Only AST detected the issue
                violations.append((rule, ast_result, "ast"))

        return violations

    def _match_rule_regex(self, code: str, rule) -> Optional[str]:
        """Match code against a single rule using regex approach"""
        return self.regex_matcher._match_rule(code, rule)

    def _match_rule_ast(self, code: str, rule) -> Optional[str]:
        """Match code against a single rule using AST approach"""
        pattern = rule.pattern if hasattr(rule, 'pattern') else None

        if not pattern:
            return None

        pattern_type = pattern.get("type", "regex") if isinstance(pattern, dict) else "regex"
        pattern_value = pattern.get("value", "") if isinstance(pattern, dict) else str(pattern)
        language = pattern.get("language", "javascript") if isinstance(pattern, dict) else "javascript"

        if pattern_type == "ast":
            if language.lower() == "javascript":
                return self._match_javascript_ast(code, pattern_value)
            elif language.lower() == "python":
                return self._match_python_ast(code, pattern_value)
            else:
                # For unsupported languages, fall back to regex
                return self.regex_matcher._match_regex(code, pattern_value)
        else:
            # For non-AST patterns, return None so we don't duplicate matches
            return None

    def _match_javascript_ast(self, code: str, pattern: str) -> Optional[str]:
        """Match JavaScript code against AST pattern - enhanced version"""
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
            issues_found = []
            
            for node in ast.walk(tree):
                # Check for dangerous function calls
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                        if func_name in ['eval', 'exec', 'compile']:
                            issues_found.append(f"Dangerous function '{func_name}' detected")
                        elif func_name == 'input':
                            issues_found.append("Unvalidated user input detected")
                        elif func_name == 'open':
                            # Check if it's a potentially unsafe file operation
                            args = node.args
                            if args and isinstance(args[0], ast.Constant) and '..' in str(args[0].value):
                                issues_found.append("Potential path traversal detected")
                        elif func_name in ['os.system', 'subprocess.call', 'subprocess.run']:
                            # Check if command is constructed from user input
                            issues_found.append("Potential command injection detected")
                    
                    # Check for attribute access like eval
                    elif isinstance(node.func, ast.Attribute):
                        attr_name = node.func.attr
                        if attr_name in ['eval', 'exec']:
                            issues_found.append(f"Dangerous method '{attr_name}' detected")
                            
                # Check for hardcoded credentials
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            if 'password' in target.id.lower() or 'key' in target.id.lower() or 'secret' in target.id.lower():
                                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                    issues_found.append(f"Hardcoded credential in variable '{target.id}' detected")
        
            if issues_found:
                return "; ".join(issues_found)
            return None
        except SyntaxError:
            # If we can't parse the Python code, return None to let regex handle it
            return None
        except Exception as e:
            print(f"Error in Python AST matching: {e}")
            # Return None to let regex handle it
            return None