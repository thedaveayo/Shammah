"""
FastAPI Routes
"""
import secrets
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.orm import Session

from config import ADMIN_API_KEY
from database import get_db
from services.rule_cache import RuleCache
from services.telegram_ingest import TelegramIngest
from services.export_generator import ExportGenerator
from services.cve_fetcher import CVEFetcher
from services.cwe_fetcher import CWEFetcher
from services.quick_fix_service import generate_quick_fix_suggestions
from api.schemas import TelegramIngestRequest

router = APIRouter()


def require_admin(authorization: Optional[str] = Header(None)):
    """
    Protect routes that change data or call paid APIs (NVD, LLM).

    Send the key as `Authorization: Bearer <ADMIN_API_KEY>`.
    If ADMIN_API_KEY is not set, these routes are disabled.
    """
    if not ADMIN_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="Admin routes are disabled. Set ADMIN_API_KEY to enable them.",
        )
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing admin API key")
    supplied = authorization[len("Bearer "):]
    if not secrets.compare_digest(supplied.encode(), ADMIN_API_KEY.encode()):
        raise HTTPException(status_code=403, detail="Invalid admin API key")


@router.post("/rules/telegram", dependencies=[Depends(require_admin)])
def ingest_telegram(request: TelegramIngestRequest, db: Session = Depends(get_db)):
    """Ingest a curated message (e.g. from a Telegram bot) and turn it into a rule"""
    ingest = TelegramIngest()
    rule = ingest.process_message(request.message_text, request.message_date or datetime.utcnow().isoformat())

    if not rule:
        raise HTTPException(status_code=400, detail="Failed to extract rule")

    success = ingest.save_rule(rule, db)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to save")

    # Regenerate export
    rule_cache = RuleCache(db)
    all_rules = rule_cache.get_all_rules()
    export_gen = ExportGenerator()
    export_gen.generate_and_save(all_rules)

    return {"status": "success", "rule_id": rule.rule_id}


@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """Get rule statistics"""
    cache = RuleCache(db)
    return cache.get_rule_count()


@router.get("/public/rules")
def get_public_rules(db: Session = Depends(get_db)):
    """Get public export JSON (no auth required)"""
    cache = RuleCache(db)
    all_rules = cache.get_all_rules()
    export_gen = ExportGenerator()
    return export_gen.generate_export(all_rules)


@router.post("/fetch/cve", dependencies=[Depends(require_admin)])
def trigger_cve_fetch(db: Session = Depends(get_db)):
    """Manually trigger CVE fetch"""
    fetcher = CVEFetcher()
    saved = fetcher.sync_cves(db)
    return {"status": "success", "cves_saved": saved}


@router.post("/fetch/cwe", dependencies=[Depends(require_admin)])
def trigger_cwe_fetch(db: Session = Depends(get_db)):
    """Manually trigger CWE fetch"""
    fetcher = CWEFetcher()
    saved = fetcher.sync_cwe_taxonomy(db, force=False)
    return {"status": "success", "cwe_rules_saved": saved}


@router.post("/quick-fix/suggest", dependencies=[Depends(require_admin)])
def suggest_fixes(code: str, vulnerability_description: str, language: str = "javascript"):
    """Generate specific code fixes for security vulnerabilities (calls the LLM)"""
    fixes = generate_quick_fix_suggestions(code, vulnerability_description, language)

    if fixes is None:
        raise HTTPException(status_code=500, detail="Failed to generate fixes")

    return {
        "status": "success",
        "fixes": fixes
    }
