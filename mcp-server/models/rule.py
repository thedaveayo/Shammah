"""
Local Rule Model (mirrors backend)
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON
from datetime import datetime
from database import Base

class LocalRule(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String, unique=True, index=True, nullable=False)
    rule_type = Column(String, nullable=False)
    source = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    
    # CVE/CWE references
    cve_refs = Column(JSON, default=list)
    cwe_refs = Column(JSON, default=list)
    
    # CVE-specific
    affected_package = Column(String, nullable=True)
    affected_versions = Column(String, nullable=True)
    
    # Pattern matching
    pattern = Column(JSON, nullable=True)
    applies_to = Column(JSON, default=dict)
    
    # Enforcement
    enforcement = Column(JSON, nullable=False)
    
    # Sync metadata
    synced_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    
    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "rule_type": self.rule_type,
            "severity": self.severity,
            "title": self.title,
            "enforcement": self.enforcement,
            "pattern": self.pattern,
            "applies_to": self.applies_to
        }
