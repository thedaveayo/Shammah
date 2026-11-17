"""
Pydantic schemas for API request/response validation
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict
from datetime import datetime

class RuleCreate(BaseModel):
    """Schema for creating a rule (admin use)"""
    rule_type: str = Field(..., pattern="^(cve|cwe|dsv)$")
    source: str
    severity: str = Field(..., pattern="^(critical|high|medium|low)$")
    title: str
    description: str
    cve_refs: Optional[List[str]] = []
    cwe_refs: Optional[List[str]] = []
    pattern: Optional[Dict] = None
    applies_to: Optional[Dict] = {}
    source_link: Optional[str] = None
    enforcement: Dict

class RuleResponse(BaseModel):
    """Schema for rule response"""
    rule_id: str
    rule_type: str
    source: str
    severity: str
    title: str
    description: str
    cve_refs: List[str]
    cwe_refs: List[str]
    pattern: Optional[Dict]
    applies_to: Dict
    source_link: Optional[str]
    enforcement: Dict
    metadata: Dict

class SyncRequest(BaseModel):
    """Schema for MCP sync request"""
    stack: Optional[Dict] = {}
    last_sync: Optional[str] = None

class SyncResponse(BaseModel):
    """Schema for MCP sync response"""
    new_rules: Optional[List[Dict]] = []
    updated_rules: Optional[List[Dict]] = []
    deleted_rule_ids: Optional[List[str]] = []
    synced_at: str

class TelegramIngestRequest(BaseModel):
    """Schema for Telegram message ingestion"""
    message_text: str
    message_date: Optional[str] = None

class ComplianceStatus(BaseModel):
    """Schema for compliance status response"""
    compliant: bool
    total_violations: int
    violations_by_severity: Dict[str, int]
