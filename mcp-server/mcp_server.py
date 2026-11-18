"""
Shammah MCP Server
Model Context Protocol server that lets coding agents check code against
security rules before they write it.
"""
import logging
import threading
from typing import Optional

from mcp.server.mcpserver import MCPServer

from config import AUTO_SYNC_ON_START
from database import SessionLocal, init_db
from services.rule_store import load_starter_rules
from tools import handlers

logger = logging.getLogger(__name__)

INSTRUCTIONS = """Shammah checks code for security problems using rules built from CVE and CWE data.
Before writing or editing code, call enforce_security with the code and its language.
If the result says BLOCKED, fix every listed issue and check again before using the code.
Use security_scan_file or security_scan_project to review existing code."""


def _run(name: str, **kwargs) -> str:
    db = SessionLocal()
    try:
        text, _ = handlers.HANDLERS[name](db, **kwargs)
        return text
    finally:
        db.close()


def prepare_rules(sync: bool = AUTO_SYNC_ON_START) -> None:
    """Create tables, load starter rules and (optionally) sync from the backend in the background"""
    init_db()
    db = SessionLocal()
    try:
        count = load_starter_rules(db)
        logger.info("Loaded %d starter rules", count)
    finally:
        db.close()

    if sync:
        def _sync():
            db = SessionLocal()
            try:
                text, _ = handlers.sync_rules(db)
                logger.info(text)
            except Exception:  # never let a sync problem stop the server
                logger.exception("Background rule sync failed")
            finally:
                db.close()
        threading.Thread(target=_sync, name="rule-sync", daemon=True).start()


def create_server() -> MCPServer:
    server = MCPServer(name="shammah", title="Shammah", instructions=INSTRUCTIONS, version="0.2.0")

    @server.tool()
    def enforce_security(code: str, language: Optional[str] = None) -> str:
        """Check code for security issues before using it. Returns BLOCKED with the issues to fix
        (critical/high/medium), PASS WITH WARNINGS (low only) or PASS.

        Args:
            code: The code to check.
            language: Language of the code, e.g. python, javascript, typescript, java.
        """
        return _run("enforce_security", code=code, language=language)

    @server.tool()
    def security_scan_file(file_path: str, include_details: bool = True) -> str:
        """Scan a file on disk for security issues.

        Args:
            file_path: Absolute path of the file to scan.
            include_details: Include fix steps and matched code for each issue.
        """
        return _run("security_scan_file", file_path=file_path, include_details=include_details)

    @server.tool()
    def security_scan_project(project_path: str, max_files: int = 2000) -> str:
        """Scan every source and config file in a project folder and summarize the issues.

        Args:
            project_path: Absolute path of the project folder.
            max_files: Stop after this many files.
        """
        return _run("security_scan_project", project_path=project_path, max_files=max_files)

    @server.tool()
    def security_fix_suggestions(code: str, language: Optional[str] = None,
                                 vulnerability_type: Optional[str] = None) -> str:
        """Get step-by-step fixes for the security issues in some code.

        Args:
            code: The code with issues.
            language: Language of the code.
            vulnerability_type: Only show issues matching this text, e.g. "sql" or "CWE-79".
        """
        return _run("security_fix_suggestions", code=code, language=language,
                    vulnerability_type=vulnerability_type)

    @server.tool()
    def security_context_explain(code: str, language: Optional[str] = None,
                                 audience: str = "developer") -> str:
        """Explain the security impact of some code in plain language.

        Args:
            code: The code to explain.
            language: Language of the code.
            audience: developer, manager or security-expert.
        """
        return _run("security_context_explain", code=code, language=language, audience=audience)

    @server.tool()
    def security_rule_details(rule_id: str, include_examples: bool = False) -> str:
        """Show what a rule checks for and how to fix it.

        Args:
            rule_id: Rule ID from a finding, e.g. SHAMMAH-0003 or DSV-2026-0001.
            include_examples: Also show the rule's pattern.
        """
        return _run("security_rule_details", rule_id=rule_id, include_examples=include_examples)

    @server.tool()
    def get_compliance_status(project_path: str = ".") -> str:
        """Show how many rules are loaded, when they were last synced and the project's detected stack.

        Args:
            project_path: Absolute path of the project folder.
        """
        return _run("get_compliance_status", project_path=project_path)

    @server.tool()
    def get_infrastructure_profile(project_path: str = ".") -> str:
        """Detect a project's languages, frameworks and infrastructure.

        Args:
            project_path: Absolute path of the project folder.
        """
        return _run("get_infrastructure_profile", project_path=project_path)

    @server.tool()
    def sync_rules(full: bool = False) -> str:
        """Download new rules from the Shammah backend set in BACKEND_URL.

        Args:
            full: Download every rule again instead of only new ones.
        """
        return _run("sync_rules", full=full)

    return server
