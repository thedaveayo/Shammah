"""
Startup helpers shared by every mode (MCP server, bridge, CLI, CI).
Kept free of the MCP library so the command-line scanner runs without it.
"""
import logging
import threading

from config import AUTO_SYNC_ON_START
from database import SessionLocal, init_db
from services.rule_store import load_starter_rules

logger = logging.getLogger(__name__)


def prepare_rules(sync: bool = AUTO_SYNC_ON_START, background: bool = True) -> None:
    """Create tables, load starter rules and optionally pull new rules (backend and/or paid feed)"""
    init_db()
    db = SessionLocal()
    try:
        count = load_starter_rules(db)
        logger.info("Loaded %d starter rules", count)
    finally:
        db.close()

    if not sync:
        return

    def _sync():
        from tools import handlers
        db = SessionLocal()
        try:
            text, _ = handlers.sync_rules(db)
            logger.info(text)
        except Exception:  # never let a sync problem stop the server
            logger.exception("Rule sync failed")
        finally:
            db.close()

    if background:
        threading.Thread(target=_sync, name="rule-sync", daemon=True).start()
    else:
        _sync()
