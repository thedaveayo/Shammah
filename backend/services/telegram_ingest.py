"""
Telegram Ingest Service
Processes Telegram messages and converts to DSV rules
"""
from typing import Dict, Optional, List
from models.rule import Rule
from database import SessionLocal
from .rule_generator import llm_extract_telegram_rule, generate_internal_id

class TelegramIngest:
    """Ingests Telegram messages and converts to security rules"""
    
    def process_message(self, message_text: str, message_date: str) -> Optional[Rule]:
        """
        Process a Telegram message and extract security rule
        Returns Rule object or None if extraction fails
        """
        # Get existing CWE rules for matching
        db = SessionLocal()
        existing_cwe_rules = db.query(Rule).filter(Rule.rule_type == "cwe").all()
        db.close()
        
        # Extract rule using LLM
        extracted = llm_extract_telegram_rule(message_text, existing_cwe_rules)
        
        if not extracted:
            return None
        
        # Check if exact CWE match
        if extracted.get("is_exact_cwe_match", False) and extracted.get("cwe_refs"):
            # Link to existing CWE, don't create new DSV
            # (In production, would enrich the existing CWE rule)
            return None
        
        # Create new DSV rule
        rule_id = generate_internal_id("dsv")
        
        # Parse severity (LLM returns uppercase, we need lowercase)
        severity = extracted.get("severity", "HIGH").lower()
        
        # Generate enforcement
        enforcement = {
            "level": "block" if severity in ["critical", "high", "medium"] else "warn",
            "message": extracted.get("message", "Security issue detected"),
            "required_actions": extracted.get("required_actions", ["Fix the security issue"])
        }
        
        rule = Rule(
            rule_id=rule_id,
            rule_type="dsv",
            source="telegram",
            severity=severity,
            title=extracted.get("message", "Security Rule")[:100],
            description=message_text[:2000],  # Truncate if too long
            cwe_refs=extracted.get("cwe_refs", []),
            pattern=extracted.get("pattern"),
            applies_to=extracted.get("applies_to", {}),
            source_link=extracted.get("source_link"),
            enforcement=enforcement
        )
        
        return rule
    
    def save_rule(self, rule: Rule, db: SessionLocal) -> bool:
        """Save rule to database"""
        try:
            db.add(rule)
            db.commit()
            return True
        except Exception as e:
            print(f"Error saving Telegram rule: {e}")
            db.rollback()
            return False
