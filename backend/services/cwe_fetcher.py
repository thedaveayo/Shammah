"""
CWE Fetcher Service
Fetches CWE taxonomy from MITRE and converts to enforcement rules via LLM
"""
import requests
from datetime import datetime
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional
from models.rule import Rule
from database import SessionLocal
from .rule_generator import generate_internal_id, llm_extract_cwe_patterns

class CWEFetcher:
    """Fetches CWE data from MITRE and converts to rules"""
    
    # Updated CWE XML URL (MITRE uses versioned files now)
    CWE_XML_URL = "https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip"
    
    # Alternative fallback URLs
    FALLBACK_URLS = [
        "https://cwe.mitre.org/data/xml/cwec_v4.13.xml.zip",
        "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
    ]
    
    def fetch_cwe_taxonomy(self) -> Optional[bytes]:
        """Download full CWE taxonomy XML from MITRE (handles ZIP files)"""
        import zipfile
        from io import BytesIO
        
        # Try primary URL and fallbacks
        urls_to_try = [self.CWE_XML_URL] + self.FALLBACK_URLS
        
        for url in urls_to_try:
            try:
                print(f"Trying CWE URL: {url}")
                response = requests.get(url, timeout=120)
                response.raise_for_status()
                
                # Handle ZIP files
                if url.endswith('.zip'):
                    print(f"Extracting ZIP from: {url}")
                    with zipfile.ZipFile(BytesIO(response.content)) as zip_file:
                        # Find XML file in ZIP
                        xml_files = [f for f in zip_file.namelist() if f.endswith('.xml')]
                        if xml_files:
                            xml_content = zip_file.read(xml_files[0])
                            print(f"CWE fetch successful from: {url} (extracted {xml_files[0]})")
                            return xml_content
                
                # Plain XML
                print(f"CWE fetch successful from: {url}")
                return response.content
                
            except requests.RequestException as e:
                print(f"CWE fetch failed from {url}: {e}")
                continue
        
        print("All CWE URLs failed")
        return None
    
    def parse_cwe_xml(self, xml_content: bytes) -> List[Dict]:
        """Parse CWE XML and extract weakness entries (handles XML namespaces)"""
        cwe_list = []
        
        try:
            root = ET.fromstring(xml_content)
            
            # CWE XML uses namespace: xmlns="http://cwe.mitre.org/cwe-7"
            # Need to use namespace-aware XPath
            namespace = {'cwe': 'http://cwe.mitre.org/cwe-7'}
            
            # Try with namespace first
            weaknesses = root.findall('.//cwe:Weakness', namespace)
            
            # Fallback to no namespace if needed
            if not weaknesses:
                weaknesses = root.findall('.//Weakness')
            
            for weakness in weaknesses:
                cwe_data = {
                    "id": weakness.get("ID", ""),
                    "name": weakness.get("Name", ""),
                    "status": weakness.get("Status", ""),
                    "description": "",
                    "example_code": "",
                    "remediation": ""
                }
                
                # Extract description with namespace
                desc_elem = weakness.find('cwe:Description', namespace)
                if desc_elem is None:
                    desc_elem = weakness.find('Description')
                if desc_elem is not None and desc_elem.text:
                    cwe_data["description"] = desc_elem.text.strip()
                
                # Extract example code with namespace
                example_elem = weakness.find('cwe:Example_Code', namespace)
                if example_elem is None:
                    example_elem = weakness.find('Example_Code')
                if example_elem is not None and example_elem.text:
                    cwe_data["example_code"] = example_elem.text.strip()
                
                # Extract remediation with namespace
                mitigation_elem = weakness.find('cwe:Mitigation_Factor', namespace)
                if mitigation_elem is None:
                    mitigation_elem = weakness.find('Mitigation_Factor')
                if mitigation_elem is not None and mitigation_elem.text:
                    cwe_data["remediation"] = mitigation_elem.text.strip()
                
                # Only include complete entries
                if cwe_data["id"] and cwe_data["name"] and cwe_data["description"]:
                    cwe_list.append(cwe_data)
        
        except ET.ParseError as e:
            print(f"Error parsing CWE XML: {e}")
            return []
        
        return cwe_list
    
    def convert_cwe_to_rule(self, cwe_data: Dict) -> Optional[Rule]:
        """Convert CWE data to Rule using LLM for pattern extraction"""
        try:
            # Use LLM to extract concrete patterns from abstract CWE description
            pattern_data = llm_extract_cwe_patterns(cwe_data)
            
            if not pattern_data:
                return None
            
            rule_id = generate_internal_id("cwe")
            
            # Generate enforcement message in lay terms
            enforcement = {
                "level": "block",  # CWE patterns are usually important
                "message": pattern_data.get("message", f"Code contains security weakness: {cwe_data['name']}"),
                "required_actions": pattern_data.get("required_actions", ["Fix the security issue"])
            }
            
            rule = Rule(
                rule_id=rule_id,
                rule_type="cwe",
                source="cwe",
                severity=pattern_data.get("severity", "high"),
                title=cwe_data["name"],
                description=cwe_data["description"],
                cwe_refs=[f"CWE-{cwe_data['id']}"],
                pattern=pattern_data.get("pattern"),
                applies_to=pattern_data.get("applies_to", {}),
                enforcement=enforcement,
                external_refs=[f"https://cwe.mitre.org/data/definitions/{cwe_data['id']}.html"]
            )
            
            return rule
            
        except Exception as e:
            print(f"Error converting CWE to rule: {e}")
            return None
    
    def sync_cwe_taxonomy(self, db: SessionLocal, force: bool = False):
        """
        Fetch full CWE taxonomy and convert to rules
        This is a one-time operation (CWE taxonomy rarely changes)
        """
        # Check if we already have CWE rules
        if not force:
            existing_cwe_count = db.query(Rule).filter(Rule.rule_type == "cwe").count()
            if existing_cwe_count > 0:
                print(f"CWE Sync: Already have {existing_cwe_count} CWE rules, skipping")
                return 0
        
        print("CWE Sync: Fetching full CWE taxonomy from MITRE...")
        xml_content = self.fetch_cwe_taxonomy()
        
        if not xml_content:
            print("CWE Sync: Failed to fetch CWE taxonomy")
            return 0
        
        print("CWE Sync: Parsing XML...")
        cwe_list = self.parse_cwe_xml(xml_content)
        print(f"CWE Sync: Found {len(cwe_list)} CWE entries")
        
        # Convert to rules (this may take a while due to LLM calls)
        saved_count = 0
        for i, cwe_data in enumerate(cwe_list):
            print(f"CWE Sync: Processing {i+1}/{len(cwe_list)}: CWE-{cwe_data['id']}")

            rule = self.convert_cwe_to_rule(cwe_data)
            if rule:
                # Check if rule with this CWE ID already exists
                existing = db.query(Rule).filter(Rule.cwe_refs.contains([f"CWE-{cwe_data['id']}"])).first()
                
                if existing:
                    if force:
                        # If forcing, update the existing rule
                        print(f"  Updating existing rule for CWE-{cwe_data['id']}: {existing.rule_id}")
                        # Update the existing rule with new data
                        existing.rule_type = rule.rule_type
                        existing.source = rule.source
                        existing.severity = rule.severity
                        existing.title = rule.title
                        existing.description = rule.description
                        existing.pattern = rule.pattern
                        existing.applies_to = rule.applies_to
                        existing.enforcement = rule.enforcement
                        existing.updated_at = datetime.utcnow()
                    else:
                        # Skip if not forcing
                        continue
                else:
                    # Check if rule_id already exists (to handle ID conflicts)
                    existing_by_id = db.query(Rule).filter(Rule.rule_id == rule.rule_id).first()
                    if existing_by_id:
                        # Generate a new ID if there's a conflict
                        from .id_generator import generate_internal_id
                        rule.rule_id = generate_internal_id("cwe")
                        print(f"  Generated new ID due to conflict: {rule.rule_id}")
                    
                    db.add(rule)
                    saved_count += 1

            # Commit every 10 rules to avoid memory issues
            if (i + 1) % 10 == 0:  # Changed to commit every 10 processed items, not just saved
                try:
                    db.commit()
                    print(f"CWE Sync: Processed {i+1}/{len(cwe_list)} CWEs, {saved_count} rules saved so far...")
                except Exception as e:
                    db.rollback()
                    print(f"  Error committing batch: {e}")
                    # Continue processing despite commit errors

        try:
            db.commit()
            print(f"CWE Sync: Completed. Saved {saved_count} new/update CWE rules")
        except Exception as e:
            db.rollback()
            print(f"CWE Sync: Completed with errors. Saved {saved_count} new/update CWE rules. Last error: {e}")
        
        return saved_count
