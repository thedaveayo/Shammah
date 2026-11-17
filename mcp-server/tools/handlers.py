"""
Tool handlers shared by the MCP server and the local HTTP bridge.

Every handler takes a database session plus keyword arguments and returns
(text, data): `text` is a readable summary for coding agents, `data` is the
same result as structured JSON for IDE extensions.
"""
import os
import re
from collections import Counter
from typing import Dict, List, Optional, Tuple

from sqlalchemy import func
from sqlalchemy.orm import Session

from models.rule import LocalRule
from services.infra_detector import InfrastructureDetector
from services.rule_store import (
    SEVERITY_ORDER, find_issues, language_from_path, normalize_language, rules_for_language,
)
from services.rule_sync import RuleSync

Result = Tuple[str, Dict]

BLOCKING = {"critical", "high", "medium"}
MAX_FILE_BYTES = 2 * 1024 * 1024
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "env", "dist", "build", ".next", "target", "vendor"}
CODE_LANGUAGES = {"javascript", "python", "java", "kotlin", "go", "php", "ruby", "csharp", "rust", "sql"}
SOURCE_EXTENSIONS = {
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".java", ".kt", ".go", ".php", ".rb", ".cs", ".rs", ".sql",
    ".env", ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".properties",
}


def _short(text: str, limit: int = 100) -> str:
    text = (text or "").replace("\n", " ")
    return text if len(text) <= limit else text[:limit] + "..."


def _format_findings(findings: List[Dict], where: str = "") -> str:
    lines = []
    for i, f in enumerate(findings, 1):
        location = f"{where}:{f['line']}" if where else f"line {f['line']}"
        lines.append(f"{i}. [{f['severity'].upper()}] {f['title']} ({f['rule_id']}) at {location}")
        lines.append(f"   Why: {f['message']}")
        lines.append(f"   Fix: {'; '.join(f['required_actions'])}")
        if f["references"]:
            lines.append(f"   Refs: {', '.join(f['references'])}")
        lines.append(f"   Code: {_short(f['matched_code'])}")
    return "\n".join(lines)


def _counts(findings: List[Dict]) -> Dict[str, int]:
    c = Counter(f["severity"] for f in findings)
    return {s: c.get(s, 0) for s in ("critical", "high", "medium", "low")}


# --------------------------------------------------------------------------- code


def enforce_security(db: Session, code: str, language: Optional[str] = None) -> Result:
    """Check code before it is written. Critical/high/medium findings block."""
    if not code:
        return "Error: no code provided.", {"error": "no code provided"}

    findings = find_issues(code, rules_for_language(db, language))
    blocking = [f for f in findings if f["severity"] in BLOCKING]
    data = {
        "blocked": bool(blocking),
        "compliant": not findings,
        "violation_count": len(findings),
        "counts": _counts(findings),
        "violations": findings,
    }

    if not findings:
        text = "PASS: no security issues found by the current rules."
    elif blocking:
        text = (f"BLOCKED: {len(blocking)} issue(s) must be fixed before this code is used.\n\n"
                + _format_findings(findings))
    else:
        text = f"PASS WITH WARNINGS: {len(findings)} low-severity issue(s).\n\n" + _format_findings(findings)
    return text, data


def security_fix_suggestions(db: Session, code: str, language: Optional[str] = None,
                             vulnerability_type: Optional[str] = None) -> Result:
    """Fix steps for each issue found in the code"""
    findings = find_issues(code or "", rules_for_language(db, language))
    if vulnerability_type:
        vt = vulnerability_type.lower()
        findings = [f for f in findings if vt in f["title"].lower() or vt in f["message"].lower()
                    or any(vt in r.lower() for r in f["references"])]

    fixes = [{
        "rule_id": f["rule_id"], "title": f["title"], "severity": f["severity"],
        "line": f["line"], "issue": f["message"], "steps": f["required_actions"],
        "matched_code": f["matched_code"],
    } for f in findings]

    if not fixes:
        return "No issues found, so there is nothing to fix.", {"fixes": []}

    lines = [f"Fix suggestions for {len(fixes)} issue(s):", ""]
    for i, fx in enumerate(fixes, 1):
        lines.append(f"{i}. {fx['title']} ({fx['severity'].upper()}, line {fx['line']})")
        lines.append(f"   Issue: {fx['issue']}")
        for step in fx["steps"]:
            lines.append(f"   - {step}")
    return "\n".join(lines), {"fixes": fixes}


def security_context_explain(db: Session, code: str, language: Optional[str] = None,
                             audience: str = "developer") -> Result:
    """Explain the security impact of code for a developer, manager or security expert"""
    findings = find_issues(code or "", rules_for_language(db, language))
    audience = (audience or "developer").lower()
    counts = _counts(findings)

    if audience == "manager":
        if findings:
            text = (f"This code has {len(findings)} security issue(s) "
                    f"({counts['critical']} critical, {counts['high']} high). They could expose customer data "
                    "or let attackers misuse the system. Fix them before release.")
        else:
            text = "No known security issues were found in this code by the current rules."
    else:
        if findings:
            text = f"{len(findings)} security issue(s) found:\n\n" + _format_findings(findings)
        else:
            text = "No known security issues were found by the current rules."
        if audience == "security-expert":
            signals = {
                "authentication/authorization": ["auth", "login", "permission", "role", "acl", "rbac"],
                "sensitive data": ["encrypt", "decrypt", "hash", "password", "credential", "token"],
                "network": ["socket", "request", "http", "fetch", "axios", "urllib"],
            }
            seen = []
            for area, words in signals.items():
                found = [w for w in words if re.search(r"\b" + re.escape(w), code or "", re.I)]
                if found:
                    seen.append(f"- {area}: {', '.join(found)}")
            if seen:
                text += "\n\nSecurity-relevant areas in this code:\n" + "\n".join(seen)
    return text, {"audience": audience, "counts": counts, "violations": findings}


# --------------------------------------------------------------------------- files


def _read_source(path: str) -> Tuple[Optional[str], Optional[str]]:
    if not os.path.isfile(path):
        return None, f"File does not exist: {path}"
    if os.path.getsize(path) > MAX_FILE_BYTES:
        return None, f"File is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB: {path}"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(), None
    except OSError as e:
        return None, f"Could not read {path}: {e}"


def security_scan_file(db: Session, file_path: str, include_details: bool = True,
                       language: Optional[str] = None) -> Result:
    """Scan one file on disk"""
    code, error = _read_source(file_path)
    if error:
        return f"Error: {error}", {"error": error}
    lang = normalize_language(language) or language_from_path(file_path)
    findings = find_issues(code, rules_for_language(db, lang))
    data = {"file_path": file_path, "language": lang, "counts": _counts(findings), "violations": findings}
    if not findings:
        return f"No security issues found in {file_path}.", data
    if include_details:
        return f"{len(findings)} issue(s) in {file_path}:\n\n" + _format_findings(findings, file_path), data
    summary = "\n".join(f"- [{f['severity'].upper()}] {f['title']} at line {f['line']}" for f in findings)
    return f"{len(findings)} issue(s) in {file_path}:\n{summary}", data


def security_scan_project(db: Session, project_path: str = ".", max_files: int = 2000) -> Result:
    """Scan every source file under a folder"""
    if not os.path.isdir(project_path):
        return f"Error: folder does not exist: {project_path}", {"error": "folder does not exist"}

    rules_cache: Dict[str, List] = {}
    findings: List[Dict] = []
    files_scanned = 0
    truncated = False

    for root, dirs, files in os.walk(project_path):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith(".") or d == ".github")
        for name in sorted(files):
            ext = os.path.splitext(name)[1].lower()
            if ext not in SOURCE_EXTENSIONS and name != ".env":
                continue
            if files_scanned >= max_files:
                truncated = True
                break
            path = os.path.join(root, name)
            code, error = _read_source(path)
            if error:
                continue
            files_scanned += 1
            lang = language_from_path(name)
            if lang not in CODE_LANGUAGES:
                lang = "config"  # config files only get language-independent rules (e.g. secrets)
            if lang not in rules_cache:
                rules_cache[lang] = rules_for_language(db, lang)
            for f in find_issues(code, rules_cache[lang]):
                f["file_path"] = os.path.relpath(path, project_path)
                findings.append(f)
        if truncated:
            break

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["file_path"], f["line"]))
    counts = _counts(findings)
    data = {"project_path": project_path, "files_scanned": files_scanned, "truncated": truncated,
            "issues_found": len(findings), "counts": counts, "violations": findings}

    head = (f"Scanned {files_scanned} file(s) in {project_path}{' (stopped at the file limit)' if truncated else ''}. "
            f"Found {len(findings)} issue(s): {counts['critical']} critical, {counts['high']} high, "
            f"{counts['medium']} medium, {counts['low']} low.")
    if not findings:
        return head, data
    top = findings[:25]
    lines = [head, "", "Most severe issues:"]
    for f in top:
        lines.append(f"- [{f['severity'].upper()}] {f['title']} ({f['rule_id']}) at {f['file_path']}:{f['line']}")
    if len(findings) > len(top):
        lines.append(f"...and {len(findings) - len(top)} more.")
    return "\n".join(lines), data


# --------------------------------------------------------------------------- rules and project


def security_rule_details(db: Session, rule_id: str, include_examples: bool = False) -> Result:
    """Details of one rule"""
    rule = db.query(LocalRule).filter(LocalRule.rule_id == rule_id).first()
    if not rule:
        return f"Rule '{rule_id}' was not found.", {"error": "not found"}

    enforcement = rule.enforcement if isinstance(rule.enforcement, dict) else {}
    data = {
        "rule_id": rule.rule_id, "title": rule.title, "severity": rule.severity, "type": rule.rule_type,
        "source": rule.source, "description": rule.description, "cve_refs": rule.cve_refs or [],
        "cwe_refs": rule.cwe_refs or [], "enforcement": enforcement,
    }
    lines = [
        f"{rule.rule_id}: {rule.title}",
        f"Severity: {rule.severity.upper()}   Type: {rule.rule_type}   Source: {rule.source}",
        "",
        rule.description,
    ]
    refs = (rule.cwe_refs or []) + (rule.cve_refs or [])
    if refs:
        lines.append(f"\nReferences: {', '.join(refs)}")
    if enforcement.get("required_actions"):
        lines.append("\nHow to fix:")
        lines += [f"- {a}" for a in enforcement["required_actions"]]
    if include_examples:
        data["pattern"] = rule.pattern
        data["applies_to"] = rule.applies_to
        if isinstance(rule.pattern, dict):
            lines.append(f"\nPattern ({rule.pattern.get('type', 'regex')}, {rule.pattern.get('language', 'any')}): "
                         f"{rule.pattern.get('value', '')}")
    return "\n".join(lines), data


def get_infrastructure_profile(db: Session, project_path: str = ".") -> Result:
    """Languages, frameworks and infrastructure detected in a project"""
    stack = InfrastructureDetector().detect(project_path)
    langs = ", ".join(stack.get("languages", [])) or "none detected"
    fws = ", ".join(stack.get("frameworks", [])) or "none detected"
    infra = ", ".join(stack.get("infrastructure", [])) or "none detected"
    return f"Languages: {langs}\nFrameworks: {fws}\nInfrastructure: {infra}", stack


def get_compliance_status(db: Session, project_path: str = ".") -> Result:
    """Rules loaded and project stack"""
    total = db.query(LocalRule).count()
    by_source = dict(db.query(LocalRule.source, func.count(LocalRule.id)).group_by(LocalRule.source).all())
    last_sync = RuleSync(db).get_last_sync()
    _, stack = get_infrastructure_profile(db, project_path)
    data = {"rules_loaded": total, "rules_by_source": by_source,
            "last_backend_sync": last_sync.isoformat() if last_sync else None, "stack": stack}
    sources = ", ".join(f"{k}: {v}" for k, v in sorted(by_source.items())) or "none"
    text = (f"Rules loaded: {total} ({sources})\n"
            f"Last backend sync: {data['last_backend_sync'] or 'never'}\n"
            f"Languages: {', '.join(stack.get('languages', [])) or 'none detected'}\n"
            f"Frameworks: {', '.join(stack.get('frameworks', [])) or 'none detected'}")
    return text, data


def sync_rules(db: Session, full: bool = False) -> Result:
    """Pull new rules from the backend"""
    result = RuleSync(db).sync_rules(full=full)
    if result["status"] != "success":
        return result["message"].rstrip(".") + ". The server keeps working with the rules it already has.", result
    return (f"Synced {result['rules_received']} rule(s) from the backend "
            f"({result['created']} new, {result['updated']} updated). "
            f"{result['total_rules']} rules loaded."), result


HANDLERS = {
    "enforce_security": enforce_security,
    "security_scan_file": security_scan_file,
    "security_scan_project": security_scan_project,
    "security_fix_suggestions": security_fix_suggestions,
    "security_context_explain": security_context_explain,
    "security_rule_details": security_rule_details,
    "get_compliance_status": get_compliance_status,
    "get_infrastructure_profile": get_infrastructure_profile,
    "sync_rules": sync_rules,
}
