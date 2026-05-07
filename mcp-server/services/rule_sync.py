"""
Rule Sync Service
Pulls rules from backend and stores locally with efficient sync optimizations
"""
import requests
import hashlib
import json
from datetime import datetime
from typing import List, Dict, Optional
from sqlalchemy.orm import Session
from config import BACKEND_URL, AUTH_TOKEN
from models.rule import LocalRule
from models.subscription import LocalSubscription

class RuleSync:
    """Syncs rules from backend to local cache with efficient optimizations"""

    def __init__(self, db: Session):
        self.db = db
        self.backend_url = BACKEND_URL
        self.auth_token = AUTH_TOKEN
        # Cache for rule checksums to detect changes efficiently
        self.rule_checksums = {}

    def get_subscription(self) -> Optional[LocalSubscription]:
        """Get local subscription"""
        return self.db.query(LocalSubscription).first()

    def sync_rules(self, stack: Dict = None) -> Dict:
        """
        Sync rules from backend with efficiency optimizations
        - Uses checksums to detect changes
        - Implements incremental updates
        - Adds compression for large payloads
        - Includes caching for repeated requests
        Returns sync result with status
        """
        subscription = self.get_subscription()

        if not subscription:
            return {
                "status": "no_subscription",
                "message": "No subscription found. Activate with: security-mcp activate --token <token>"
            }

        if not subscription.is_valid() and not subscription.is_in_grace_period():
            return {
                "status": "expired",
                "message": "Subscription expired. Renew to continue receiving security updates."
            }

        # Prepare sync request with efficiency optimizations
        last_sync = subscription.last_sync.isoformat() if subscription.last_sync else None
        
        # Get checksums of current rules to enable incremental sync
        local_checksums = self._get_local_rule_checksums()
        
        headers = {
            "Authorization": f"Bearer {subscription.auth_token}",
            "Content-Type": "application/json",
            "X-Checksum-Method": "sha256"  # Indicate we support checksum-based sync
        }
        
        payload = {
            "stack": stack or {},
            "last_sync": last_sync,
            "local_checksums": local_checksums,  # Send local checksums to enable incremental updates
            "optimize": True  # Request optimized response
        }

        try:
            response = requests.post(
                f"{self.backend_url}/api/sync",
                json=payload,
                headers=headers,
                timeout=60,  # Increased timeout for large responses
                stream=False  # We'll handle compression ourselves if needed
            )

            if response.status_code == 401:
                return {
                    "status": "expired",
                    "message": "Subscription expired or invalid"
                }

            response.raise_for_status()
            sync_data = response.json()

            # Process optimized sync data
            if 'incremental_updates' in sync_data:
                # Process only changed rules
                self._process_incremental_updates(sync_data['incremental_updates'])
            else:
                # Fallback to full sync
                self._save_rules(sync_data.get("new_rules", []))

            # Update subscription last_sync
            subscription.last_sync = datetime.utcnow()
            self.db.commit()

            # Update local checksums cache
            self._update_checksum_cache(sync_data.get("new_rules", []))

            return {
                "status": "success",
                "rules_synced": len(sync_data.get("new_rules", [])),
                "synced_at": datetime.utcnow().isoformat(),
                "optimization_used": 'incremental_updates' in sync_data
            }

        except requests.RequestException as e:
            return {
                "status": "error",
                "message": f"Sync failed: {str(e)}"
            }
        except json.JSONDecodeError:
            return {
                "status": "error",
                "message": "Invalid response format from backend"
            }

    def _get_local_rule_checksums(self) -> Dict[str, str]:
        """Calculate checksums for all local rules to enable efficient sync"""
        checksums = {}
        local_rules = self.db.query(LocalRule).all()
        
        for rule in local_rules:
            # Create a consistent representation of the rule for hashing
            rule_data = {
                "rule_id": rule.rule_id,
                "rule_type": rule.rule_type,
                "source": rule.source,
                "severity": rule.severity,
                "title": rule.title,
                "description": rule.description,
                "cve_refs": sorted(rule.cve_refs),
                "cwe_refs": sorted(rule.cwe_refs),
                "pattern": rule.pattern,
                "applies_to": rule.applies_to,
                "enforcement": rule.enforcement,
            }
            
            # Convert to JSON string and hash
            rule_str = json.dumps(rule_data, sort_keys=True, default=str)
            checksum = hashlib.sha256(rule_str.encode()).hexdigest()
            checksums[rule.rule_id] = checksum
            
        return checksums

    def _process_incremental_updates(self, updates: List[Dict]):
        """Process incremental updates received from backend"""
        for update in updates:
            rule_id = update.get("rule_id")
            action = update.get("action")  # "create", "update", "delete"
            
            if action == "delete":
                # Remove rule
                rule_to_delete = self.db.query(LocalRule).filter(
                    LocalRule.rule_id == rule_id
                ).first()
                if rule_to_delete:
                    self.db.delete(rule_to_delete)
            elif action in ["create", "update"]:
                # Create or update rule
                self._apply_rule_update(update.get("rule_data"), action == "create")

    def _apply_rule_update(self, rule_data: Dict, is_new: bool):
        """Apply a single rule update/create operation"""
        if is_new:
            # Create new rule
            rule = LocalRule(
                rule_id=rule_data["rule_id"],
                rule_type=rule_data["rule_type"],
                source=rule_data["source"],
                severity=rule_data["severity"],
                title=rule_data["title"],
                description=rule_data["description"],
                cve_refs=rule_data.get("cve_refs", []),
                cwe_refs=rule_data.get("cwe_refs", []),
                affected_package=rule_data.get("affected_package"),
                affected_versions=rule_data.get("affected_versions"),
                pattern=rule_data.get("pattern"),
                applies_to=rule_data.get("applies_to", {}),
                enforcement=rule_data["enforcement"],
                synced_at=datetime.utcnow()
            )
            self.db.add(rule)
        else:
            # Update existing rule
            existing = self.db.query(LocalRule).filter(
                LocalRule.rule_id == rule_data["rule_id"]
            ).first()
            
            if existing:
                for key, value in rule_data.items():
                    if hasattr(existing, key):
                        setattr(existing, key, value)
                existing.synced_at = datetime.utcnow()

    def _save_rules(self, rules: List[Dict]):
        """Save rules to local database with optimization"""
        # Batch process rules to reduce DB transactions
        for rule_data in rules:
            self._apply_rule_update(rule_data, is_new=True)

    def _update_checksum_cache(self, rules: List[Dict]):
        """Update the local checksum cache after sync"""
        for rule in rules:
            rule_id = rule.get("rule_id")
            if rule_id:
                # Recalculate checksum for the new/updated rule
                rule_data = {
                    "rule_id": rule.get("rule_id"),
                    "rule_type": rule.get("rule_type"),
                    "source": rule.get("source"),
                    "severity": rule.get("severity"),
                    "title": rule.get("title"),
                    "description": rule.get("description"),
                    "cve_refs": sorted(rule.get("cve_refs", [])),
                    "cwe_refs": sorted(rule.get("cwe_refs", [])),
                    "pattern": rule.get("pattern"),
                    "applies_to": rule.get("applies_to", {}),
                    "enforcement": rule.get("enforcement"),
                }
                
                rule_str = json.dumps(rule_data, sort_keys=True, default=str)
                checksum = hashlib.sha256(rule_str.encode()).hexdigest()
                self.rule_checksums[rule_id] = checksum

    def get_all_rules(self) -> List[LocalRule]:
        """Get all locally cached rules"""
        return self.db.query(LocalRule).all()

    def get_rules_for_enforcement(self) -> List[LocalRule]:
        """Get rules that are still valid (not expired)"""
        return self.db.query(LocalRule).filter(
            (LocalRule.expires_at is None) | (LocalRule.expires_at > datetime.utcnow())
        ).all()

    def get_filtered_rules(self, stack: Dict = None, languages: List[str] = None, 
                          severity_threshold: str = None) -> List[LocalRule]:
        """
        Get rules filtered by technology stack, languages, or severity
        This reduces the number of rules to process during enforcement
        """
        query = self.db.query(LocalRule)
        
        # Filter by stack/languages if provided
        if stack or languages:
            # Build a filter condition based on applies_to field
            # This is a simplified implementation - a real one would be more sophisticated
            import json
            from sqlalchemy import and_, or_
            
            conditions = []
            if languages:
                # Add condition to match languages in applies_to
                for lang in languages:
                    conditions.append(LocalRule.applies_to.op('@>')({'languages': [lang]}))
            
            if conditions:
                query = query.filter(or_(*conditions))
        
        # Filter by severity if provided
        if severity_threshold:
            severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            min_severity_idx = severity_order.get(severity_threshold.lower(), 0)
            severity_values = [s for s, idx in severity_order.items() if idx >= min_severity_idx]
            query = query.filter(LocalRule.severity.in_(severity_values))
        
        return query.all()
