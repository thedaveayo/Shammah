"""
Client for the hosted Shammah rule feed (Shammah Pro).

Set SHAMMAH_API_KEY and SHAMMAH_FEED_URL to use it. Only rules come down. What
goes up is limited to:
  - scan summaries (counts, rule IDs, repository name, commit), never code, and
    only when the scan is run with --report;
  - false-positive reports (rule ID and the reason you type).
"""
import logging
from datetime import datetime
from typing import Dict, Optional

import requests
from sqlalchemy import func
from sqlalchemy.orm import Session

from config import SHAMMAH_API_KEY, SHAMMAH_FEED_URL, SYNC_TIMEOUT_SECONDS
from models.rule import LocalRule
from services.rule_store import upsert_rules

logger = logging.getLogger(__name__)
FEED_SOURCE_PREFIX = "feed:"


class FeedClient:
    def __init__(self, api_key: Optional[str] = None, url: Optional[str] = None, session=None):
        self.api_key = api_key if api_key is not None else SHAMMAH_API_KEY
        self.url = (url if url is not None else SHAMMAH_FEED_URL).rstrip("/")
        self.http = session or requests

    @property
    def enabled(self) -> bool:
        return bool(self.api_key and self.url)

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}", "User-Agent": "shammah-scanner/0.3"}

    def last_sync(self, db: Session) -> Optional[datetime]:
        return (db.query(func.max(LocalRule.synced_at))
                .filter(LocalRule.source.like(FEED_SOURCE_PREFIX + "%")).scalar())

    def sync(self, db: Session, full: bool = False) -> Dict:
        if not self.enabled:
            return {"status": "disabled", "message": "Shammah Pro feed not configured (set SHAMMAH_API_KEY and SHAMMAH_FEED_URL)."}
        last = None if full else self.last_sync(db)
        params = {"since": last.isoformat()} if last else {}
        try:
            resp = self.http.get(f"{self.url}/v1/rules", params=params, headers=self._headers(),
                                 timeout=SYNC_TIMEOUT_SECONDS)
            if resp.status_code in (401, 403):
                return {"status": "error", "message": f"The Shammah feed refused the API key ({resp.status_code}). "
                                                      "Check SHAMMAH_API_KEY and your plan."}
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            return {"status": "error", "message": f"Could not reach the Shammah feed ({e.__class__.__name__})."}
        except ValueError:
            return {"status": "error", "message": "The Shammah feed sent an invalid response."}

        builtin = {rid for (rid,) in db.query(LocalRule.rule_id).filter(LocalRule.source == "shammah-starter").all()}
        rules = []
        for r in data.get("rules") or []:
            if r.get("rule_id") in builtin:
                continue  # starter rules ship with the scanner; keep the built-in copy
            r = dict(r)
            r["source"] = FEED_SOURCE_PREFIX + (r.get("source") or "shammah")
            rules.append(r)
        created, updated = upsert_rules(db, rules)

        # Drop feed rules the service has retired (incremental sync) or no longer serves (full sync)
        feed_rules = db.query(LocalRule).filter(LocalRule.source.like(FEED_SOURCE_PREFIX + "%"))
        if last:
            retired = set(data.get("retired_rule_ids") or [])
            stale = [r for r in feed_rules.all() if r.rule_id in retired]
        else:
            served = {r.get("rule_id") for r in data.get("rules") or []}
            stale = [r for r in feed_rules.all() if r.rule_id not in served]
        for r in stale:
            db.delete(r)
        db.commit()
        return {"status": "success", "rules_received": len(rules), "created": created, "updated": updated,
                "removed": len(stale), "ruleset_version": data.get("ruleset_version")}

    def report_scan(self, summary: Dict) -> Dict:
        """Send a scan summary (no code) for the dashboard history"""
        if not self.enabled:
            return {"status": "disabled"}
        try:
            resp = self.http.post(f"{self.url}/v1/scans", json=summary, headers=self._headers(),
                                  timeout=SYNC_TIMEOUT_SECONDS)
            resp.raise_for_status()
            return {"status": "success", **(resp.json() if resp.content else {})}
        except (requests.RequestException, ValueError) as e:
            return {"status": "error", "message": f"Could not send the scan summary ({e.__class__.__name__})."}

    def report_false_positive(self, rule_id: str, reason: str) -> Dict:
        if not self.enabled:
            return {"status": "disabled"}
        try:
            resp = self.http.post(f"{self.url}/v1/feedback", headers=self._headers(), timeout=SYNC_TIMEOUT_SECONDS,
                                  json={"rule_id": rule_id, "kind": "false_positive", "reason": reason[:1000]})
            resp.raise_for_status()
            return {"status": "success"}
        except requests.RequestException as e:
            return {"status": "error", "message": f"Could not send the report ({e.__class__.__name__})."}


def scan_summary(result: Dict, repository: str = "", commit: str = "", branch: str = "", trigger: str = "") -> Dict:
    """What the hosted dashboard stores about a scan: counts and rule IDs, never code or file contents"""
    return {
        "repository": repository[:200],
        "commit": commit[:64],
        "branch": branch[:200],
        "trigger": trigger[:50],
        "counts": result["counts"],
        "issues_found": result["issues_found"],
        "files_scanned": result["files_scanned"] + result["files_from_cache"],
        "dependencies_checked": result["dependencies"]["packages"],
        "rule_ids": sorted({f["rule_id"] for f in result["violations"]})[:500],
        "ruleset_version": result.get("ruleset_version"),
        "duration_seconds": result.get("duration_seconds"),
    }
