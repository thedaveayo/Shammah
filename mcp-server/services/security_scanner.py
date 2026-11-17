"""
Security Scanner Service
Scans code blocks with the same rules as the MCP server (starter rules plus
any rules synced from the backend). Used by the GitHub repo scanner and the
web interface.
"""
from datetime import datetime
from typing import Dict

from database import SessionLocal, init_db
from services.rule_store import find_issues, load_starter_rules, rules_for_language


class SecurityScanner:
    """Scans code for security vulnerabilities"""

    def __init__(self):
        init_db()
        db = SessionLocal()
        try:
            load_starter_rules(db)
        finally:
            db.close()
        self._rules_by_language: Dict[str, list] = {}

    def _rules(self, language: str):
        if language not in self._rules_by_language:
            db = SessionLocal()
            try:
                rules = rules_for_language(db, None if language in ("", "unknown") else language)
                # Detach plain values so they can be used after the session closes
                db.expunge_all()
            finally:
                db.close()
            self._rules_by_language[language] = rules
        return self._rules_by_language[language]

    def scan_code_block(self, code_block: str, language: str = "unknown", context: str = "unknown") -> Dict:
        """Scan a code block and return the issues found"""
        issues = []
        for f in find_issues(code_block, self._rules(language)):
            issues.append({
                "id": f["rule_id"],
                "title": f["title"],
                "severity": f["severity"],
                "description": f["message"],
                "recommendation": "; ".join(f["required_actions"]),
                "line": f["line"],
                "matched_patterns": [f["matched_code"]],
                "context": context,
            })
        return {
            "issues": issues,
            "lines": code_block.split("\n"),
            "language": language,
            "scan_time": datetime.utcnow().isoformat(),
        }
