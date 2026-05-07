"""
CVE Fetcher Service
Fetches CVE data from NVD/MITRE/MISP APIs (deterministic parsing)
"""
import requests
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from config import NVD_API_KEY
from models.rule import Rule
from database import SessionLocal

class CVEFetcher:
    """Fetches and parses CVE data from NVD API"""
    
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self):
        self.headers = {
            "apiKey": NVD_API_KEY
        } if NVD_API_KEY else {}
    
    def fetch_recent_cves(self, days_back: int = 7) -> List[Dict]:
        """Fetch CVEs from the last N days"""
        last_modified_start = (datetime.utcnow() - timedelta(days=days_back)).isoformat()
        
        params = {
            "lastModStartDate": last_modified_start,
            "lastModEndDate": datetime.utcnow().isoformat(),
            "resultsPerPage": 2000
        }
        
        try:
            response = requests.get(self.NVD_API_URL, headers=self.headers, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            return data.get("vulnerabilities", [])
        except requests.RequestException as e:
            print(f"Error fetching CVEs: {e}")
            return []
    
    def parse_cve(self, cve_item: Dict) -> Optional[Rule]:
        """
        Parse CVE data deterministically (no LLM needed - data is already structured)
        Returns a Rule object or None if parsing fails
        """
        try:
            cve = cve_item.get("cve", {})
            cve_id = cve.get("id", "")
            
            # Extract severity from CVSS metrics
            severity = self._extract_severity(cve)
            
            # Extract affected package and version range
            affected_package, affected_versions = self._extract_affected(cve)
            
            # Extract CWE reference if available
            cwe_refs = self._extract_cwe_refs(cve)
            
            # Extract description
            descriptions = cve.get("descriptions", [])
            description = descriptions[0].get("value", "") if descriptions else ""
            
            # Generate internal DSV ID
            from .rule_generator import generate_internal_id
            rule_id = generate_internal_id("cve")
            
            # Create enforcement message in lay terms
            enforcement = {
                "level": "block" if severity in ["critical", "high", "medium"] else "warn",
                "message": f"This code uses {affected_package} version {affected_versions}, which has a known security vulnerability ({cve_id}). Upgrade to a patched version.",
                "required_actions": [f"Upgrade {affected_package} to latest version"]
            }
            
            rule = Rule(
                rule_id=rule_id,
                rule_type="cve",
                source="nvd",
                severity=severity,
                title=f"Vulnerability in {affected_package or 'dependency'} ({cve_id})",
                description=description,
                cve_refs=[cve_id],
                cwe_refs=cwe_refs,
                affected_package=affected_package,
                affected_versions=affected_versions,
                enforcement=enforcement,
                external_refs=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"]
            )
            
            return rule
            
        except Exception as e:
            print(f"Error parsing CVE: {e}")
            return None
    
    def _extract_severity(self, cve: Dict) -> str:
        """Extract severity from CVSS metrics"""
        metrics = cve.get("metrics", {})
        
        # Try CVSS v3.1 first
        cvss_v31 = metrics.get("cvssMetricV31", [])
        if cvss_v31:
            base_score = cvss_v31[0].get("cvssData", {}).get("baseScore", 0)
            return self._score_to_severity(base_score)
        
        # Try CVSS v3.0
        cvss_v3 = metrics.get("cvssMetricV3", [])
        if cvss_v3:
            base_score = cvss_v3[0].get("cvssData", {}).get("baseScore", 0)
            return self._score_to_severity(base_score)
        
        # Try CVSS v2
        cvss_v2 = metrics.get("cvssMetricV2", [])
        if cvss_v2:
            base_score = cvss_v2[0].get("cvssData", {}).get("baseScore", 0)
            return self._score_to_severity(base_score, version="v2")
        
        return "medium"  # Default if no metrics
    
    def _score_to_severity(self, score: float, version: str = "v3") -> str:
        """Convert CVSS score to severity string"""
        if version == "v2":
            if score >= 7.0:
                return "high"
            elif score >= 4.0:
                return "medium"
            elif score > 0.0:
                return "low"
        else:  # v3
            if score >= 9.0:
                return "critical"
            elif score >= 7.0:
                return "high"
            elif score >= 4.0:
                return "medium"
            elif score > 0.0:
                return "low"
        return "medium"
    
    def _extract_affected(self, cve: Dict) -> tuple:
        """Extract affected package and version range from CVE"""
        configurations = cve.get("configurations", [])
        
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "")
                    # Parse CPE string: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        package = parts[4]  # Product name
                        version_start = cpe_match.get("versionStartIncluding", "")
                        version_end = cpe_match.get("versionEndExcluding", "")
                        
                        version_range = ""
                        if version_start:
                            version_range = f">={version_start}"
                        if version_end:
                            if version_range:
                                version_range += f",<{version_end}"
                            else:
                                version_range = f"<{version_end}"
                        
                        return package, version_range
        
        return None, None
    
    def _extract_cwe_refs(self, cve: Dict) -> List[str]:
        """Extract CWE references from CVE"""
        weaknesses = cve.get("weaknesses", [])
        cwe_refs = []
        
        for weakness in weaknesses:
            for description in weakness.get("description", []):
                if description.get("value", "").startswith("CWE-"):
                    cwe_id = description.get("value", "").split()[0]
                    if cwe_id.startswith("CWE-"):
                        cwe_refs.append(cwe_id)
        
        return cwe_refs
    
    def sync_cves(self, db: SessionLocal, days_back: int = 90, include_hall_of_fame: bool = True) -> int:
        """
        Fetch recent CVEs and save to database
        days_back: Days to fetch (default: 90)
        include_hall_of_fame: Also fetch critical CVEs for popular frameworks from last year
        """
        saved_count = 0
        
        # Fetch recent CVEs (last N days)
        print(f"CVE Sync: Fetching CVEs from last {days_back} days...")
        cve_items = self.fetch_recent_cves(days_back=days_back)
        
        errors_count = 0
        duplicate_count = 0
        
        for i, cve_item in enumerate(cve_items):
            try:
                rule = self.parse_cve(cve_item)
                if rule and rule.cve_refs and len(rule.cve_refs) > 0:
                    existing = db.query(Rule).filter(
                        Rule.cve_refs.contains([rule.cve_refs[0]])
                    ).first()
                    if not existing:
                        db.add(rule)
                        saved_count += 1
                        if saved_count % 50 == 0:
                            try:
                                db.commit()
                                print(f"CVE Sync: Saved {saved_count} so far...")
                            except Exception as commit_error:
                                db.rollback()
                                duplicate_count += 1
                                print(f"CVE Sync: Commit error: {commit_error}")
            except Exception as e:
                errors_count += 1
                continue
        
        # Fetch Hall of Fame CVEs (critical CVEs for popular packages from last year)
        if include_hall_of_fame:
            print("\nCVE Sync: Fetching Hall of Fame CVEs (critical CVEs for popular frameworks from last year)...")
            from .hall_of_fame_fetcher import HallOfFameFetcher
            hof_fetcher = HallOfFameFetcher()
            hof_cves = hof_fetcher.fetch_critical_cves_for_packages()
            
            hof_saved = 0
            for cve_item in hof_cves:
                try:
                    rule = self.parse_cve(cve_item)
                    if rule and rule.cve_refs and len(rule.cve_refs) > 0:
                        existing = db.query(Rule).filter(
                            Rule.cve_refs.contains([rule.cve_refs[0]])
                        ).first()
                        if not existing:
                            db.add(rule)
                            hof_saved += 1
                except Exception as e:
                    continue
            
            print(f"CVE Sync: Hall of Fame: {hof_saved} new CVEs")
            saved_count += hof_saved
        
        # Final commit
        try:
            db.commit()
            print(f"CVE Sync: Saved {saved_count} new CVE rules total ({errors_count} errors, {duplicate_count} duplicates)")
        except Exception as e:
            db.rollback()
            print(f"CVE Sync: Final commit error: {e}")
        
        return saved_count
