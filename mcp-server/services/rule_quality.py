"""
Rule quality checks.

A rule is only trusted when:
  - its required fields are present and its severity is valid,
  - its pattern compiles and doesn't look prone to catastrophic backtracking,
  - it flags every "bad" example and none of its "good" examples.

Used by `python main.py test-rules`, the test suite, and the hosted rule feed
before it publishes a rule.
"""
import re
from types import SimpleNamespace
from typing import Dict, Iterable, List

from services.pattern_matcher import PatternMatcher

REQUIRED_FIELDS = ("rule_id", "title", "severity", "pattern", "enforcement")
SEVERITIES = {"critical", "high", "medium", "low"}
# A group with a quantifier inside, repeated by another quantifier: (a+)+, (\w*)*, (x+|y)+
_NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]")


def check_rule(rule: Dict, require_examples: bool = True) -> List[str]:
    """Return a list of problems with a rule (empty list = the rule passes)"""
    problems = []
    rid = rule.get("rule_id", "<no id>")

    for field in REQUIRED_FIELDS:
        if not rule.get(field):
            problems.append(f"{rid}: missing {field}")
    if rule.get("severity") and rule["severity"].lower() not in SEVERITIES:
        problems.append(f"{rid}: severity must be one of {', '.join(sorted(SEVERITIES))}")

    enforcement = rule.get("enforcement") or {}
    if isinstance(enforcement, dict):
        if not enforcement.get("message"):
            problems.append(f"{rid}: enforcement.message (plain-language explanation) is missing")
        if not enforcement.get("required_actions"):
            problems.append(f"{rid}: enforcement.required_actions (fix steps) is missing")

    pattern = rule.get("pattern") or {}
    value = pattern.get("value") if isinstance(pattern, dict) else None
    if not value:
        problems.append(f"{rid}: pattern.value is empty")
        return problems
    try:
        re.compile(value)
    except re.error as e:
        problems.append(f"{rid}: pattern does not compile ({e})")
        return problems
    if _NESTED_QUANTIFIER.search(value):
        problems.append(f"{rid}: pattern has a nested quantifier and may hang on long input")

    examples = rule.get("examples") or {}
    bad, good = examples.get("bad") or [], examples.get("good") or []
    if require_examples and (not bad or not good):
        problems.append(f"{rid}: needs at least one bad and one good example")

    probe = SimpleNamespace(pattern=pattern)
    matcher = PatternMatcher()
    for code in bad:
        if not matcher._match_rule(code, probe):
            problems.append(f"{rid}: misses its bad example: {code!r}")
    for code in good:
        if matcher._match_rule(code, probe):
            problems.append(f"{rid}: flags its good example (false positive): {code!r}")
    return problems


def check_rules(rules: Iterable[Dict], require_examples: bool = True) -> Dict:
    """Check many rules. Returns {"passed": [...ids], "failed": {id: [problems]}}"""
    passed, failed, seen = [], {}, set()
    for rule in rules:
        rid = rule.get("rule_id", "<no id>")
        problems = check_rule(rule, require_examples=require_examples)
        if rid in seen:
            problems.append(f"{rid}: duplicate rule_id")
        seen.add(rid)
        if problems:
            failed[rid] = problems
        else:
            passed.append(rid)
    return {"passed": passed, "failed": failed}
