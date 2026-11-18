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
    find_issues, language_from_path, normalize_language, rules_for_language,
)
from services.feed_client import FeedClient
from services.project_config import load_config, mute_rule as _mute_rule
from services.project_scan import format_text, scan_project
from services.rule_sync import RuleSync

Result = Tuple[str, Dict]

BLOCKING = {"critical", "high", "medium"}
MAX_FILE_BYTES = 2 * 1024 * 1024


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


def _project_root(path: str) -> Optional[str]:
    """Nearest folder above a file that has a .shammah or .git folder"""
    current = os.path.dirname(os.path.abspath(path))
    while True:
        if os.path.isdir(os.path.join(current, ".shammah")) or os.path.isdir(os.path.join(current, ".git")):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent


def security_scan_file(db: Session, file_path: str, include_details: bool = True,
                       language: Optional[str] = None) -> Result:
    """Scan one file on disk"""
    code, error = _read_source(file_path)
    if error:
        return f"Error: {error}", {"error": error}
    lang = normalize_language(language) or language_from_path(file_path)
    root = _project_root(file_path)
    muted = set(load_config(root)["muted_rules"]) if root else set()
    findings = find_issues(code, [r for r in rules_for_language(db, lang) if r.rule_id not in muted])
    data = {"file_path": file_path, "language": lang, "counts": _counts(findings), "violations": findings}
    if not findings:
        return f"No security issues found in {file_path}.", data
    if include_details:
        return f"{len(findings)} issue(s) in {file_path}:\n\n" + _format_findings(findings, file_path), data
    summary = "\n".join(f"- [{f['severity'].upper()}] {f['title']} at line {f['line']}" for f in findings)
    return f"{len(findings)} issue(s) in {file_path}:\n{summary}", data


def security_scan_project(db: Session, project_path: str = ".", max_files: int = 5000,
                          include_dependencies: bool = True) -> Result:
    """Scan every source/config file and every lockfile under a folder (results are cached per file)"""
    if not os.path.isdir(project_path):
        return f"Error: folder does not exist: {project_path}", {"error": "folder does not exist"}
    result = scan_project(db, project_path, max_files=max_files, include_dependencies=include_dependencies)
    return format_text(result), result


def security_check_dependencies(db: Session, project_path: str = ".") -> Result:
    """Check the project's lockfiles for packages with known vulnerabilities (OSV.dev)"""
    from services.dependency_check import check_dependencies
    if not os.path.isdir(project_path):
        return f"Error: folder does not exist: {project_path}", {"error": "folder does not exist"}
    muted = load_config(project_path)["muted_rules"]
    data = check_dependencies(project_path, muted=muted)
    if data["error"]:
        return data["error"], data
    if not data["lockfiles"]:
        return "No lockfiles found (package-lock.json, yarn.lock, requirements.txt, poetry.lock, Pipfile.lock, Cargo.lock, Gemfile.lock, go.mod).", data
    if not data["violations"]:
        return f"Checked {data['packages']} dependencies in {', '.join(data['lockfiles'])}: no known vulnerabilities.", data
    return (f"{len(data['violations'])} known vulnerabilit{'y' if len(data['violations']) == 1 else 'ies'} "
            f"in {data['packages']} dependencies:\n\n" + _format_findings(data["violations"])), data


def mute_rule(db: Session, project_path: str, rule_id: str, unmute: bool = False) -> Result:
    """Turn a rule off (or back on) for one project, saved in .shammah/config.json"""
    if not os.path.isdir(project_path):
        return f"Error: folder does not exist: {project_path}", {"error": "folder does not exist"}
    muted = _mute_rule(project_path, rule_id, unmute=unmute)
    verb = "Unmuted" if unmute else "Muted"
    return f"{verb} {rule_id} for {project_path}. Muted rules: {', '.join(muted) or 'none'}.", {"muted_rules": muted}


def report_false_positive(db: Session, rule_id: str, reason: str, project_path: Optional[str] = None) -> Result:
    """Report a wrong finding. Mutes the rule for the project if a path is given; tells Shammah Pro if configured."""
    parts, data = [], {"rule_id": rule_id}
    if project_path and os.path.isdir(project_path):
        data["muted_rules"] = _mute_rule(project_path, rule_id)
        parts.append(f"Muted {rule_id} for this project.")
    sent = FeedClient().report_false_positive(rule_id, reason or "")
    data["reported"] = sent["status"] == "success"
    if sent["status"] == "success":
        parts.append("Reported to Shammah so the rule can be fixed.")
    elif sent["status"] == "disabled":
        parts.append("To help fix the rule, open an issue: https://github.com/thedaveayo/Shammah/issues/new?template=rule_request.md")
    else:
        parts.append(sent.get("message", "Could not send the report."))
    return " ".join(parts), data


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
    """Pull new rules from the backend in BACKEND_URL and, if configured, the Shammah Pro feed"""
    lines, data = [], {}
    feed = FeedClient()
    if feed.enabled:
        res = feed.sync(db, full=full)
        data["feed"] = res
        lines.append(res["message"] if res["status"] != "success" else
                     f"Shammah Pro feed: {res['rules_received']} rule(s) ({res['created']} new, {res['updated']} updated).")
    sync = RuleSync(db)
    if not sync.backend_url:
        result = {"status": "skipped", "message": "no BACKEND_URL set"}
        if not feed.enabled:
            return "Nothing to sync from: set BACKEND_URL or SHAMMAH_API_KEY and SHAMMAH_FEED_URL.", result
    else:
        result = sync.sync_rules(full=full)
    data.update(result)
    if result["status"] == "skipped":
        pass
    elif result["status"] != "success":
        if not feed.enabled:
            return result["message"].rstrip(".") + ". The server keeps working with the rules it already has.", data
        lines.append("Backend: " + result["message"])
    else:
        lines.append(f"Backend: {result['rules_received']} rule(s) ({result['created']} new, {result['updated']} updated).")
    total = db.query(LocalRule).count()
    data["total_rules"] = total
    ok = result["status"] == "success" or (feed.enabled and data["feed"]["status"] == "success")
    data["status"] = "success" if ok else "error"
    lines.append(f"{total} rules loaded.")
    return " ".join(lines), data


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
    "security_check_dependencies": security_check_dependencies,
    "mute_rule": mute_rule,
    "report_false_positive": report_false_positive,
}
