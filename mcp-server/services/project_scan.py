"""
Whole-project scan with caching.

Each file's result is cached under its content hash and the fingerprint of every
rule it was checked against:
  - a changed file is checked against all rules;
  - an unchanged file is skipped, except for rules that are new or changed since
    the last scan, which are run on it alone;
  - findings from rules that were removed or changed are dropped.
"""
import hashlib
import json
import os
import time
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from services.dependency_check import OSVClient, check_dependencies
from services.project_config import is_excluded, load_cache, load_config, save_cache
from services.rule_store import SEVERITY_ORDER, find_issues, language_from_path, rules_for_language

MAX_FILE_BYTES = 2 * 1024 * 1024
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "env", "dist", "build", ".next", "target",
             "vendor", ".shammah"}
CODE_LANGUAGES = {"javascript", "python", "java", "kotlin", "go", "php", "ruby", "csharp", "rust", "sql"}
SOURCE_EXTENSIONS = {
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".java", ".kt", ".go", ".php", ".rb", ".cs", ".rs", ".sql",
    ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".properties",
}
LOCKFILE_NAMES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "Pipfile.lock", "poetry.lock", "Cargo.lock"}


def rule_fingerprint(rule) -> str:
    payload = json.dumps({"p": rule.pattern, "s": rule.severity, "t": rule.title, "e": rule.enforcement},
                         sort_keys=True, default=str)
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]


def ruleset_version(rules) -> str:
    joined = "|".join(sorted(f"{r.rule_id}:{rule_fingerprint(r)}" for r in rules))
    return hashlib.sha1(joined.encode("utf-8")).hexdigest()[:16]


def iter_source_files(project_path: str, exclude: List[str]):
    for root, dirs, files in os.walk(project_path):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and (not d.startswith(".") or d == ".github"))
        for name in sorted(files):
            ext = os.path.splitext(name)[1].lower()
            if name in LOCKFILE_NAMES or (ext not in SOURCE_EXTENSIONS and name != ".env"):
                continue
            path = os.path.join(root, name)
            rel = os.path.relpath(path, project_path).replace("\\", "/")
            if is_excluded(rel, exclude):
                continue
            yield path, rel


def _counts(findings: List[Dict]) -> Dict[str, int]:
    counts = {s: 0 for s in ("critical", "high", "medium", "low")}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


def scan_project(db: Session, project_path: str, max_files: int = 5000, use_cache: bool = True,
                 include_dependencies: bool = True, osv_client: Optional[OSVClient] = None) -> Dict:
    started = time.time()
    project_path = os.path.abspath(project_path)
    config = load_config(project_path)
    muted = set(config["muted_rules"])
    cache = load_cache(project_path) if use_cache else {"files": {}, "osv": {}}
    old_files = cache.get("files", {})
    new_files: Dict[str, Dict] = {}

    rules_by_lang: Dict[str, Dict[str, object]] = {}
    findings: List[Dict] = []
    files_scanned = files_from_cache = 0
    truncated = False

    for path, rel in iter_source_files(project_path, config["exclude"]):
        if files_scanned + files_from_cache >= max_files:
            truncated = True
            break
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                continue
            with open(path, "rb") as fh:
                raw = fh.read()
        except OSError:
            continue
        content_hash = hashlib.sha1(raw).hexdigest()
        lang = language_from_path(rel)
        if lang not in CODE_LANGUAGES:
            lang = "config"  # only language-independent rules (e.g. secrets)
        if lang not in rules_by_lang:
            rules_by_lang[lang] = {r.rule_id: r for r in rules_for_language(db, lang) if r.rule_id not in muted}
        rules = rules_by_lang[lang]
        fingerprints = {rid: rule_fingerprint(r) for rid, r in rules.items()}

        entry = old_files.get(rel)
        if entry and entry.get("hash") == content_hash:
            checked = entry.get("rules", {})
            kept = [f for f in entry.get("findings", []) if checked.get(f["rule_id"]) == fingerprints.get(f["rule_id"])]
            to_run = [r for rid, r in rules.items() if checked.get(rid) != fingerprints[rid]]
            if to_run:
                kept += find_issues(raw.decode("utf-8", errors="replace"), to_run)
                files_scanned += 1
            else:
                files_from_cache += 1
            file_findings = kept
        else:
            file_findings = find_issues(raw.decode("utf-8", errors="replace"), list(rules.values()))
            files_scanned += 1

        new_files[rel] = {"hash": content_hash, "rules": fingerprints,
                          "findings": [{k: v for k, v in f.items() if k != "file_path"} for f in file_findings]}
        for f in file_findings:
            findings.append({**f, "file_path": rel, "kind": "code"})

    deps = {"lockfiles": [], "packages": 0, "violations": [], "error": None}
    if include_dependencies:
        client = osv_client or OSVClient(cache=cache.setdefault("osv", {}))
        deps = check_dependencies(project_path, client=client, muted=muted)
        findings += deps["violations"]

    if use_cache:
        cache["files"] = new_files
        save_cache(project_path, cache)

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["file_path"], f["line"]))
    all_rules = {rid: r for rules in rules_by_lang.values() for rid, r in rules.items()}
    return {
        "project_path": project_path,
        "files_scanned": files_scanned,
        "files_from_cache": files_from_cache,
        "truncated": truncated,
        "issues_found": len(findings),
        "counts": _counts(findings),
        "violations": findings,
        "dependencies": {k: deps[k] for k in ("lockfiles", "packages", "error")},
        "muted_rules": sorted(muted),
        "ruleset_version": ruleset_version(all_rules.values()) if all_rules else None,
        "duration_seconds": round(time.time() - started, 2),
    }


def blocking_count(result: Dict, fail_on: str = "high") -> int:
    limit = SEVERITY_ORDER.get(fail_on, 1)
    return sum(1 for f in result["violations"] if SEVERITY_ORDER.get(f["severity"], 9) <= limit)


def format_text(result: Dict, limit: int = 25) -> str:
    c = result["counts"]
    deps = result["dependencies"]
    head = (f"Scanned {result['files_scanned']} file(s) ({result['files_from_cache']} unchanged, from cache) "
            f"and {deps['packages']} dependencies in {result['project_path']}"
            f"{' (stopped at the file limit)' if result['truncated'] else ''}. "
            f"Found {result['issues_found']} issue(s): {c['critical']} critical, {c['high']} high, "
            f"{c['medium']} medium, {c['low']} low.")
    lines = [head]
    if deps.get("error"):
        lines.append(deps["error"])
    if result["violations"]:
        lines += ["", "Most severe issues:"]
        for f in result["violations"][:limit]:
            lines.append(f"- [{f['severity'].upper()}] {f['title']} ({f['rule_id']}) at {f['file_path']}:{f['line']}")
            lines.append(f"  Fix: {'; '.join(f['required_actions'])}")
        if len(result["violations"]) > limit:
            lines.append(f"...and {len(result['violations']) - limit} more.")
    return "\n".join(lines)
