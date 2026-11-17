"""
SQLAlchemy Rule Model
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base

class Rule(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String, unique=True, index=True, nullable=False)  # DSV-YYYY-NNNN
    rule_type = Column(String, nullable=False)  # cve, cwe, dsv
    source = Column(String, nullable=False)  # nvd, mitre, misp, cwe, telegram
    
    # Severity
    severity = Column(String, nullable=False)  # critical, high, medium, low
    
    # Title and description (lay terms)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    
    # CVE-specific fields
    cve_refs = Column(JSON, default=list)  # ["CVE-2024-3094"]
    affected_package = Column(String, nullable=True)
    affected_versions = Column(String, nullable=True)
    
    # CWE-specific fields
    cwe_refs = Column(JSON, default=list)  # ["CWE-798"]
    pattern = Column(JSON, nullable=True)  # {"type": "regex", "value": "...", "language": "javascript"}
    applies_to = Column(JSON, default=dict)  # {"languages": [...], "frameworks": [...], "contexts": [...]}
    
    # DSV-specific
    source_link = Column(String, nullable=True)  # Telegram link or source URL
    
    # Enforcement
    enforcement = Column(JSON, nullable=False)  # {"level": "block", "message": "...", "required_actions": [...]}
    
    # Optional expiry
    expires_at = Column(DateTime, nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    external_refs = Column(JSON, default=list)
    
    def to_dict(self):
        """Convert rule to dictionary for JSON serialization"""
        return {
            "rule_id": self.rule_id,
            "rule_type": self.rule_type,
            "source": self.source,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "cve_refs": self.cve_refs,
            "cwe_refs": self.cwe_refs,
            "affected_package": self.affected_package,
            "affected_versions": self.affected_versions,
            "pattern": self.pattern,
            "applies_to": self.applies_to,
            "source_link": self.source_link,
            "enforcement": self.enforcement,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "metadata": {
                "created_at": self.created_at.isoformat(),
                "updated_at": self.updated_at.isoformat(),
                "external_refs": self.external_refs
            }
        }
