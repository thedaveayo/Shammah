"""
Export Generator Service
Generates human-readable rules.json for open-source archive
"""
import json
import os
from datetime import datetime
from typing import List
from models.rule import Rule

class ExportGenerator:
    """Generates export JSON for open-source release"""
    
    def __init__(self, export_path: str = "exports/rules.json"):
        self.export_path = export_path
        # Ensure exports directory exists
        os.makedirs(os.path.dirname(export_path), exist_ok=True)
    
    def generate_export(self, rules: List[Rule]) -> Dict:
        """
        Generate flat JSON structure for export
        All rules use DSV IDs as keys (even CVE/CWE derived rules)
        
        Format:
        {
            "DSV-2024-0001": {
                "agent_rule": "...",
                "relevant_infra": "...",
                "source_link": "...",
                "external_refs": ["CVE-2024-3094"]
            },
            "DSV-2024-0002": {
                "agent_rule": "...",
                "relevant_infra": "...",
                "source_link": "...",
                "external_refs": ["CWE-798"]
            }
        }
        """
        export_data = {}
        
        for rule in rules:
            # Always use DSV ID as key
            key = rule.rule_id  # DSV-YYYY-NNNN
            
            # Build export entry with external references
            export_entry = {
                "agent_rule": self._get_agent_rule_summary(rule),
                "relevant_infra": self._extract_relevant_infra(rule),
                "source_link": self._get_source_link(rule),
                "external_refs": self._get_external_refs(rule)
            }
            
            export_data[key] = export_entry
        
        return export_data
    
    def _get_agent_rule_summary(self, rule: Rule) -> str:
        """Get the agent rule summary"""
        return rule.enforcement.get("message", rule.title)
    
    def _get_external_refs(self, rule: Rule) -> List[str]:
        """Get external references (CVE IDs, CWE IDs)"""
        refs = []
        
        # Add CVE references
        if rule.cve_refs:
            refs.extend(rule.cve_refs)
        
        # Add CWE references
        if rule.cwe_refs:
            refs.extend(rule.cwe_refs)
        
        # Add external refs from metadata
        if rule.external_refs:
            refs.extend(rule.external_refs)
        
        return refs
    
    def _extract_relevant_infra(self, rule: Rule) -> str:
        """Extract relevant infrastructure from rule"""
        # For CVE rules - affected package
        if rule.rule_type == "cve" and rule.affected_package:
            return rule.affected_package
        
        # For CWE/DSV rules - languages/frameworks
        applies_to = rule.applies_to or {}
        languages = applies_to.get("languages", [])
        frameworks = applies_to.get("frameworks", [])
        
        if frameworks:
            return ", ".join(frameworks)
        elif languages:
            return ", ".join(languages)
        else:
            return "General"
    
    def _get_source_link(self, rule: Rule) -> str:
        """Get source link for rule"""
        # DSV rules have explicit source_link
        if rule.source_link:
            return rule.source_link
        
        # CVE rules - NVD link
        if rule.cve_refs and len(rule.cve_refs) > 0:
            cve_id = rule.cve_refs[0]
            return f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        
        # CWE rules - MITRE link
        if rule.cwe_refs and len(rule.cwe_refs) > 0:
            cwe_id = rule.cwe_refs[0].replace("CWE-", "")
            return f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
        
        return ""
    
    def save_export(self, export_data: Dict) -> str:
        """Save export data to file"""
        # Add metadata
        full_export = {
            "_metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "total_rules": len(export_data),
                "version": "1.0.0"
            },
            **export_data
        }
        
        with open(self.export_path, 'w', encoding='utf-8') as f:
            json.dump(full_export, f, indent=2, ensure_ascii=False)
        
        return self.export_path
    
    def generate_and_save(self, rules: List[Rule]) -> str:
        """Generate export and save to file"""
        export_data = self.generate_export(rules)
        return self.save_export(export_data)
