"""
Rule Store
Loads rules into the local database, picks the rules that apply to a language,
and turns pattern matches into findings with line and column numbers.
"""
import json
import logging
import os
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple

from sqlalchemy.orm import Session

from config import STARTER_RULES_PATH
from models.rule import LocalRule
from services.pattern_matcher import PatternMatcher

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Map editor language IDs, aliases and file extensions to rule languages.
_LANGUAGE_ALIASES = {
    "javascript": "javascript", "js": "javascript", "jsx": "javascript", "mjs": "javascript", "cjs": "javascript",
    "javascriptreact": "javascript", "node": "javascript", "nodejs": "javascript",
    # JavaScript rules also apply to TypeScript
    "typescript": "javascript", "ts": "javascript", "tsx": "javascript", "typescriptreact": "javascript",
    "python": "python", "py": "python", "python3": "python",
    "java": "java", "kotlin": "kotlin", "kt": "kotlin",
    "go": "go", "golang": "go",
    "php": "php", "ruby": "ruby", "rb": "ruby",
    "csharp": "csharp", "c#": "csharp", "cs": "csharp",
    "rust": "rust", "rs": "rust",
    "sql": "sql",
}

_ANY = {"", "any", "all", "*"}

_RULE_FIELDS = (
    "rule_type", "source", "severity", "title", "description", "cve_refs", "cwe_refs",
    "affected_package", "affected_versions", "pattern", "applies_to", "enforcement",
)


def normalize_language(language: Optional[str]) -> str:
    """Return a rule language for an editor language ID or alias ('' if unknown)"""
    if not language:
        return ""
    key = language.strip().lower().lstrip(".")
    return _LANGUAGE_ALIASES.get(key, key)


def language_from_path(path: str) -> str:
    """Guess the rule language from a file name"""
    _, ext = os.path.splitext(path)
    return normalize_language(ext)


def upsert_rules(db: Session, rules: Iterable[Dict], synced_at: Optional[datetime] = None) -> Tuple[int, int]:
    """Insert or update rules by rule_id. Returns (created, updated)."""
    synced_at = synced_at or datetime.utcnow()
    created = updated = 0
    existing = {r.rule_id: r for r in db.query(LocalRule).all()}

    for data in rules:
        rule_id = data.get("rule_id")
        if not rule_id or not data.get("pattern"):
            continue
        values = {f: data.get(f) for f in _RULE_FIELDS}
        values["cve_refs"] = values["cve_refs"] or []
        values["cwe_refs"] = values["cwe_refs"] or []
        values["applies_to"] = values["applies_to"] or {}
        values["enforcement"] = values["enforcement"] or {}
        values["description"] = values["description"] or values["title"] or ""
        values["rule_type"] = values["rule_type"] or "dsv"
        values["source"] = values["source"] or "backend"
        values["severity"] = (values["severity"] or "medium").lower()
        if not values["title"]:
            continue

        rule = existing.get(rule_id)
        if rule is None:
            rule = LocalRule(rule_id=rule_id, synced_at=synced_at, **values)
            db.add(rule)
            existing[rule_id] = rule
            created += 1
        else:
            for field, value in values.items():
                setattr(rule, field, value)
            rule.synced_at = synced_at
            updated += 1

    db.commit()
    return created, updated


def load_starter_rules(db: Session) -> int:
    """Load (or refresh) the starter rules shipped with the server"""
    try:
        data = json.loads(STARTER_RULES_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        logger.error("Could not read starter rules from %s: %s", STARTER_RULES_PATH, e)
        return 0
    rules = data.get("rules", [])
    upsert_rules(db, rules)
    return len(rules)


def rule_languages(rule) -> List[str]:
    """Languages a rule applies to ([] means every language)"""
    langs = set()
    pattern = rule.pattern if isinstance(rule.pattern, dict) else {}
    pattern_lang = normalize_language(pattern.get("language"))
    if pattern_lang not in _ANY:
        langs.add(pattern_lang)
    applies = rule.applies_to if isinstance(rule.applies_to, dict) else {}
    for lang in applies.get("languages") or []:
        lang = normalize_language(lang)
        if lang not in _ANY:
            langs.add(lang)
    return sorted(langs)


def rules_for_language(db: Session, language: Optional[str] = None) -> List[LocalRule]:
    """Rules with a pattern that apply to the language (all rules if language is unknown)"""
    lang = normalize_language(language)
    rules = [r for r in db.query(LocalRule).all() if r.pattern]
    if not lang:
        return rules
    return [r for r in rules if not rule_languages(r) or lang in rule_languages(r)]


def _position(code: str, matched: str) -> Tuple[int, int, int, int]:
    """1-based (line, column, end_line, end_column) of the first occurrence of matched"""
    index = code.find(matched) if matched else -1
    if index < 0:
        return 1, 1, 1, 1
    line = code.count("\n", 0, index) + 1
    line_start = code.rfind("\n", 0, index) + 1
    column = index - line_start + 1
    end_index = index + len(matched)
    end_line = code.count("\n", 0, end_index) + 1
    end_line_start = code.rfind("\n", 0, end_index) + 1
    end_column = end_index - end_line_start + 1
    return line, column, end_line, end_column


def find_issues(code: str, rules: List) -> List[Dict]:
    """Match code against rules and return findings, most severe first"""
    findings = []
    for rule, matched in PatternMatcher().match(code, rules):
        enforcement = rule.enforcement if isinstance(rule.enforcement, dict) else {}
        line, column, end_line, end_column = _position(code, matched or "")
        findings.append({
            "rule_id": rule.rule_id,
            "title": rule.title,
            "severity": (rule.severity or "medium").lower(),
            "message": enforcement.get("message") or rule.description,
            "description": rule.description,
            "required_actions": enforcement.get("required_actions") or ["Fix the security issue"],
            "references": list(rule.cwe_refs or []) + list(rule.cve_refs or []),
            "matched_code": (matched or "")[:200],
            "line": line,
            "column": column,
            "end_line": end_line,
            "end_column": end_column,
        })
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["line"], f["column"]))
    return findings
