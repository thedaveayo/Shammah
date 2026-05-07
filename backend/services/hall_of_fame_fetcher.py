"""
Hall of Fame CVE Fetcher
Fetches critical CVEs from last 365 days for popular frameworks
"""
import requests
from datetime import datetime, timedelta
from typing import List, Dict
from config import NVD_API_KEY

class HallOfFameFetcher:
    """Fetches critical CVEs for popular frameworks from last year"""
    
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Popular frameworks/packages to prioritize
    POPULAR_PACKAGES = [
        # Python
        "django", "flask", "fastapi", "requests", "numpy", "pandas",
        # JavaScript/Node
        "express", "react", "vue", "angular", "next", "lodash", "axios",
        # Java
        "spring", "hibernate", "log4j", "tomcat", "jetty",
        # PHP
        "laravel", "symfony", "wordpress",
        # Ruby
        "rails", "sinatra",
        # Go
        "gin", "echo",
        # Rust
        "actix", "rocket",
        # Infrastructure
        "docker", "kubernetes", "nginx", "apache",
        # Databases
        "postgresql", "mysql", "mongodb", "redis",
        # Cloud
        "boto3", "aws", "azure", "google-cloud"
    ]
    
    def __init__(self):
        self.headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    
    def fetch_critical_cves_for_packages(self) -> List[Dict]:
        """
        Fetch CVEs from last 365 days that:
        1. Are CRITICAL or HIGH severity
        2. Affect popular packages
        """
        all_cves = []
        
        # Fetch from last 365 days
        last_year = (datetime.utcnow() - timedelta(days=365)).isoformat()
        
        # Fetch in batches by date range (NVD limits to 120 days per request)
        date_ranges = [
            (last_year, (datetime.utcnow() - timedelta(days=245)).isoformat()),
            ((datetime.utcnow() - timedelta(days=245)).isoformat(), (datetime.utcnow() - timedelta(days=120)).isoformat()),
            ((datetime.utcnow() - timedelta(days=120)).isoformat(), datetime.utcnow().isoformat()),
        ]
        
        for start_date, end_date in date_ranges:
            print(f"Fetching CVEs from {start_date[:10]} to {end_date[:10]}...")
            
            params = {
                "lastModStartDate": start_date,
                "lastModEndDate": end_date,
                "resultsPerPage": 2000,
                "cvssV3Severity": "CRITICAL,HIGH"  # Only critical/high severity
            }
            
            try:
                response = requests.get(self.NVD_API_URL, headers=self.headers, params=params, timeout=120)
                response.raise_for_status()
                data = response.json()
                
                cves = data.get("vulnerabilities", [])
                print(f"  Found {len(cves)} CRITICAL/HIGH CVEs in this period")
                
                # Filter for popular packages
                filtered = self._filter_for_popular_packages(cves)
                print(f"  Filtered to {len(filtered)} for popular packages")
                
                all_cves.extend(filtered)
                
            except requests.RequestException as e:
                print(f"Error fetching CVEs: {e}")
                continue
        
        print(f"\nTotal Hall of Fame CVEs: {len(all_cves)}")
        return all_cves
    
    def _filter_for_popular_packages(self, cves: List[Dict]) -> List[Dict]:
        """Filter CVEs that affect popular packages"""
        filtered = []
        
        for cve_item in cves:
            cve = cve_item.get("cve", {})
            
            # Check if CVE affects any popular package
            if self._affects_popular_package(cve):
                filtered.append(cve_item)
        
        return filtered
    
    def _affects_popular_package(self, cve: Dict) -> bool:
        """Check if CVE affects any popular package"""
        configurations = cve.get("configurations", [])
        
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "").lower()
                    
                    # Check if any popular package is in the CPE string
                    for package in self.POPULAR_PACKAGES:
                        if package.lower() in criteria:
                            return True
        
        return False
    
    def parse_cve(self, cve_item: Dict) -> Dict:
        """Parse CVE data for rule creation"""
        cve = cve_item.get("cve", {})
        cve_id = cve.get("id", "")
        
        # Extract severity
        severity = self._extract_severity(cve)
        
        # Extract package and version
        package, version_range = self._extract_affected(cve)
        
        # Extract description
        descriptions = cve.get("descriptions", [])
        description = descriptions[0].get("value", "") if descriptions else ""
        
        return {
            "cve_id": cve_id,
            "severity": severity,
            "package": package,
            "version_range": version_range,
            "description": description
        }
    
    def _extract_severity(self, cve: Dict) -> str:
        """Extract severity from CVSS metrics"""
        metrics = cve.get("metrics", {})
        
        # Try CVSS v3.1
        cvss_v31 = metrics.get("cvssMetricV31", [])
        if cvss_v31:
            base_score = cvss_v31[0].get("cvssData", {}).get("baseScore", 0)
            if base_score >= 9.0:
                return "critical"
            elif base_score >= 7.0:
                return "high"
        
        return "high"  # Default since we filtered for HIGH/CRITICAL
    
    def _extract_affected(self, cve: Dict) -> tuple:
        """Extract affected package and version range"""
        configurations = cve.get("configurations", [])
        
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "")
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
