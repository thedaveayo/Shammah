"""
Rule Sync Service
Pulls rules from a Shammah backend into the local database.
"""
import logging
from datetime import datetime
from typing import Dict, Optional

import requests
from sqlalchemy import func
from sqlalchemy.orm import Session

from config import BACKEND_URL, SYNC_TIMEOUT_SECONDS
from models.rule import LocalRule
from services.rule_store import upsert_rules

logger = logging.getLogger(__name__)


class RuleSync:
    """Syncs rules from the backend to the local cache"""

    def __init__(self, db: Session, backend_url: Optional[str] = None):
        self.db = db
        self.backend_url = (backend_url or BACKEND_URL).rstrip("/")

    def get_last_sync(self) -> Optional[datetime]:
        """Most recent time a rule from the backend was synced"""
        return (
            self.db.query(func.max(LocalRule.synced_at))
            .filter(LocalRule.source != "shammah-starter")
            .scalar()
        )

    def sync_rules(self, stack: Dict = None, full: bool = False) -> Dict:
        """
        Download new and changed rules from the backend and store them locally.
        Set full=True to download every rule again.
        """
        last = None if full else self.get_last_sync()
        payload = {"stack": stack or {}, "last_sync": last.isoformat() if last else None}

        try:
            response = requests.post(
                f"{self.backend_url}/api/sync",
                json=payload,
                timeout=SYNC_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as e:
            return {"status": "error", "message": f"Sync failed: could not reach {self.backend_url} ({e.__class__.__name__})"}
        except ValueError:
            return {"status": "error", "message": "Sync failed: backend sent an invalid response"}

        rules = data.get("new_rules") or []
        synced_at = datetime.utcnow()
        created, updated = upsert_rules(self.db, rules, synced_at=synced_at)
        return {
            "status": "success",
            "rules_received": len(rules),
            "created": created,
            "updated": updated,
            "total_rules": self.db.query(LocalRule).count(),
            "synced_at": synced_at.isoformat(),
        }
