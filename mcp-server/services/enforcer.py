"""
Enforcer Service
Applies security rules and determines enforcement action
"""
from typing import List, Dict, Optional
from datetime import datetime
from .pattern_matcher import PatternMatcher

class Enforcer:
    """Enforces security rules on code"""
    
    def __init__(self):
        self.pattern_matcher = PatternMatcher()
    
    def enforce(self, code: str, rules: List, subscription) -> Dict:
        """
        Enforce security rules on code
        Returns enforcement result
        """
        # Check subscription status
        sub_status = self._check_subscription(subscription)
        
        # If expired beyond grace period, return vague warning
        if sub_status.get("status") == "expired":
            return {
                "blocked": False,
                "subscription_status": "expired",
                "message": "⚠️ SECURITY SUBSCRIPTION EXPIRED\n\nYour code may have security issues.\nRenew to view detailed security reports.",
                "renewal_link": "https://security-mcp.com/renew"
            }
        
        # Match code against rules
        violations = self.pattern_matcher.match(code, rules)
        
        if not violations:
            return {
                "blocked": False,
                "subscription_status": sub_status.get("status", "unknown"),
                "compliant": True
            }
        
        # Group violations by severity
        violations_by_severity = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        }
        
        for rule, matched_text in violations:
            severity = getattr(rule, 'severity', 'medium').lower()
            violations_by_severity[severity].append({
                "rule_id": getattr(rule, 'rule_id', 'UNKNOWN'),
                "rule_type": getattr(rule, 'rule_type', 'unknown'),
                "severity": severity,
                "message": self._generate_user_message(rule),
                "required_actions": self._get_required_actions(rule),
                "matched_code": matched_text[:100] if matched_text else ""
            })
        
        # Determine if blocked (active subscription)
        blocked_violations = (
            violations_by_severity["critical"] +
            violations_by_severity["high"] +
            violations_by_severity["medium"]
        )
        
        # Active subscription: block on critical/high/medium
        if sub_status.get("status") in ["active", "grace_period"]:
            if blocked_violations:
                return {
                    "blocked": True,
                    "subscription_status": sub_status.get("status"),
                    "compliant": False,
                    "violations": blocked_violations,
                    "violation_count": len(blocked_violations),
                    "message": self._generate_block_message(blocked_violations)
                }
        
        # Low severity or expired: warn only
        all_violations = violations_by_severity["low"]
        return {
            "blocked": False,
            "subscription_status": sub_status.get("status"),
            "compliant": len(all_violations) == 0,
            "violations": all_violations,
            "violation_count": len(all_violations),
            "message": self._generate_warning_message(all_violations, sub_status.get("status"))
        }
    
    def _check_subscription(self, subscription) -> Dict:
        """Check subscription status"""
        if not subscription:
            return {"status": "no_subscription"}
        
        if hasattr(subscription, 'is_valid') and subscription.is_valid():
            return {"status": "active"}
        
        if hasattr(subscription, 'is_in_grace_period') and subscription.is_in_grace_period():
            return {"status": "grace_period"}
        
        return {"status": "expired"}
    
    def _generate_user_message(self, rule) -> str:
        """Generate lay terms message for user"""
        if hasattr(rule, 'enforcement') and rule.enforcement:
            if isinstance(rule.enforcement, dict):
                return rule.enforcement.get("message", f"Security issue: {getattr(rule, 'title', 'Unknown')}")
        return f"Security issue: {getattr(rule, 'title', 'Unknown')}"
    
    def _get_required_actions(self, rule) -> List[str]:
        """Get required actions to fix"""
        if hasattr(rule, 'enforcement') and rule.enforcement:
            if isinstance(rule.enforcement, dict):
                return rule.enforcement.get("required_actions", ["Fix the security issue"])
        return ["Fix the security issue"]
    
    def _generate_block_message(self, violations: List[Dict]) -> str:
        """Generate message for blocked code"""
        severity = violations[0].get("severity", "HIGH").upper()
        return f"❌ SECURITY ISSUE FOUND ({severity})\n\n{violations[0]['message']}\n\nRequired: {'; '.join(violations[0]['required_actions'])}"
    
    def _generate_warning_message(self, violations: List[Dict], sub_status: str) -> str:
        """Generate warning message"""
        if sub_status == "expired":
            return f"⚠️ SECURITY SUBSCRIPTION EXPIRED\n\nYour code has {len(violations)} security issues.\nRenew to view details."
        return f"⚠️ LOW SEVERITY WARNING\n\n{violations[0]['message'] if violations else ''}\n\nConsider fixing when possible."
