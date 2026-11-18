"""
SARIF 2.1.0 output, so GitHub shows findings in the Security tab and on pull requests.
"""
from typing import Dict, List

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}


def to_sarif(findings: List[Dict], version: str = "0.3.0") -> Dict:
    rules: Dict[str, Dict] = {}
    results = []
    for f in findings:
        rid = f["rule_id"]
        if rid not in rules:
            help_text = f["message"] + "\n\nHow to fix:\n" + "\n".join(f"- {a}" for a in f["required_actions"])
            rules[rid] = {
                "id": rid,
                "name": rid.replace("-", ""),
                "shortDescription": {"text": f["title"]},
                "fullDescription": {"text": f.get("description") or f["message"]},
                "help": {"text": help_text, "markdown": help_text},
                "properties": {"tags": ["security"] + list(f.get("references", [])),
                               "security-severity": SECURITY_SEVERITY.get(f["severity"], "5.5")},
            }
        results.append({
            "ruleId": rid,
            "level": LEVEL.get(f["severity"], "warning"),
            "message": {"text": f"{f['title']}: {f['message']} Fix: {'; '.join(f['required_actions'])}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f["file_path"].replace("\\", "/")},
                "region": {"startLine": max(int(f.get("line") or 1), 1),
                           "startColumn": max(int(f.get("column") or 1), 1)},
            }}],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Shammah", "version": version,
                                "informationUri": "https://github.com/thedaveayo/Shammah",
                                "rules": list(rules.values())}},
            "results": results,
        }],
    }
