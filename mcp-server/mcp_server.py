"""
Shammah MCP Server
Model Context Protocol server that lets coding agents check code against
security rules before they write it.
"""
import logging
from typing import Optional

from mcp.server.mcpserver import MCPServer

from bootstrap import prepare_rules  # noqa: F401  (re-exported for callers and tests)
from database import SessionLocal
from tools import handlers

logger = logging.getLogger(__name__)

INSTRUCTIONS = """Shammah checks code for security problems using rules built from CVE and CWE data.
Before finishing any task that changed code, call security_scan_file on each changed file
(or enforce_security on new code before using it). If the result says BLOCKED, fix every
listed issue and check again. Use security_scan_project to review a whole project, including
its dependencies."""


def _run(name: str, **kwargs) -> str:
    db = SessionLocal()
    try:
        text, _ = handlers.HANDLERS[name](db, **kwargs)
        return text
    finally:
        db.close()


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
    def security_scan_project(project_path: str, max_files: int = 5000, include_dependencies: bool = True) -> str:
        """Scan every source and config file in a project folder, plus its dependencies, and summarize
        the issues. Unchanged files are served from a cache in .shammah/, so repeat scans are fast.

        Args:
            project_path: Absolute path of the project folder.
            max_files: Stop after this many files.
            include_dependencies: Also check lockfiles for vulnerable packages (needs internet).
        """
        return _run("security_scan_project", project_path=project_path, max_files=max_files,
                    include_dependencies=include_dependencies)

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
    def security_check_dependencies(project_path: str) -> str:
        """Check the project's lockfiles (package-lock.json, yarn.lock, requirements.txt, poetry.lock,
        Pipfile.lock, Cargo.lock, Gemfile.lock, go.mod) for packages with known vulnerabilities, and say
        which version to upgrade to. Only package names and versions are sent to OSV.dev.

        Args:
            project_path: Absolute path of the project folder.
        """
        return _run("security_check_dependencies", project_path=project_path)

    @server.tool()
    def mute_rule(project_path: str, rule_id: str, unmute: bool = False) -> str:
        """Turn a rule off (or back on) for one project. Only do this when the user agrees the finding is wrong.

        Args:
            project_path: Absolute path of the project folder.
            rule_id: The rule to mute, e.g. SHAMMAH-0018.
            unmute: Turn the rule back on instead.
        """
        return _run("mute_rule", project_path=project_path, rule_id=rule_id, unmute=unmute)

    @server.tool()
    def report_false_positive(rule_id: str, reason: str, project_path: Optional[str] = None) -> str:
        """Report a finding that is wrong, so the rule can be improved. Mutes the rule for the project
        when project_path is given. Never include code or secrets in the reason.

        Args:
            rule_id: The rule that fired wrongly.
            reason: One sentence on why the finding is wrong.
            project_path: Absolute path of the project, to mute the rule there.
        """
        return _run("report_false_positive", rule_id=rule_id, reason=reason, project_path=project_path)

    @server.tool()
    def sync_rules(full: bool = False) -> str:
        """Download new rules from the Shammah backend set in BACKEND_URL.

        Args:
            full: Download every rule again instead of only new ones.
        """
        return _run("sync_rules", full=full)

    return server
