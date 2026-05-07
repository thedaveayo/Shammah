"""
Rule Cache Service
CRUD operations for rules in the database
"""
from typing import List, Optional, Dict
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from models.rule import Rule
from models.subscription import Subscription

class RuleCache:
    """Database operations for rules"""
    
    def __init__(self, db: Session):
        self.db = db
    
    def get_all_rules(self, limit: int = 1000) -> List[Rule]:
        """Get all rules (for admin/export)"""
        return self.db.query(Rule).limit(limit).all()
    
    def get_rules_by_type(self, rule_type: str) -> List[Rule]:
        """Get rules by type (cve, cwe, dsv)"""
        return self.db.query(Rule).filter(Rule.rule_type == rule_type).all()
    
    def get_rule_by_id(self, rule_id: str) -> Optional[Rule]:
        """Get specific rule by DSV ID"""
        return self.db.query(Rule).filter(Rule.rule_id == rule_id).first()
    
    def get_rules_for_stack(self, stack: Dict, last_sync: datetime = None) -> List[Rule]:
        """
        Get rules filtered by infrastructure stack
        Used by MCP sync endpoint
        """
        query = self.db.query(Rule)
        
        # Filter by last sync (delta sync)
        if last_sync:
            query = query.filter(Rule.created_at > last_sync)
            query = query.filter(Rule.updated_at > last_sync)
        
        all_rules = query.all()
        
        # Filter by stack (languages, frameworks)
        filtered_rules = []
        for rule in all_rules:
            if self._rule_applies_to_stack(rule, stack):
                filtered_rules.append(rule)
        
        return filtered_rules
    
    def _rule_applies_to_stack(self, rule: Rule, stack: Dict) -> bool:
        """Check if a rule applies to the given infrastructure stack"""
        applies_to = rule.applies_to or {}
        
        # If no applies_to specified, rule applies to all
        if not applies_to:
            return True
        
        # Check languages
        rule_languages = applies_to.get("languages", [])
        if rule_languages:
            stack_languages = stack.get("languages", [])
            if not any(lang in stack_languages for lang in rule_languages):
                return False
        
        # Check frameworks
        rule_frameworks = applies_to.get("frameworks", [])
        if rule_frameworks:
            stack_frameworks = stack.get("frameworks", [])
            if not any(fw in stack_frameworks for fw in rule_frameworks):
                return False
        
        return True
    
    def get_updated_since(self, timestamp: datetime) -> List[Rule]:
        """Get rules updated since timestamp (for delta sync)"""
        return self.db.query(Rule).filter(
            (Rule.created_at > timestamp) | (Rule.updated_at > timestamp)
        ).all()
    
    def delete_rule(self, rule_id: str) -> bool:
        """Delete a rule by ID"""
        rule = self.get_rule_by_id(rule_id)
        if rule:
            self.db.delete(rule)
            self.db.commit()
            return True
        return False
    
    def get_rule_count(self) -> Dict[str, int]:
        """Get count of rules by type"""
        total = self.db.query(Rule).count()
        cve_count = self.db.query(Rule).filter(Rule.rule_type == "cve").count()
        cwe_count = self.db.query(Rule).filter(Rule.rule_type == "cwe").count()
        dsv_count = self.db.query(Rule).filter(Rule.rule_type == "dsv").count()
        
        return {
            "total": total,
            "cve": cve_count,
            "cwe": cwe_count,
            "dsv": dsv_count
        }
