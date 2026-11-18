"""
Tests for dependency checks, the cached project scan, SARIF, rule quality checks,
`init`, the agent hook and the Shammah Pro feed client. No network: OSV.dev and
the feed are faked.
"""
import json
import os
import subprocess
import sys
from unittest.mock import Mock

import pytest

from database import SessionLocal, init_db
from models.rule import LocalRule
from services import dependency_check as dc
from services.feed_client import FeedClient, scan_summary
from services.project_config import load_config, mute_rule
from services.project_scan import blocking_count, scan_project
from services.rule_quality import check_rule, check_rules
from services.rule_store import load_starter_rules, upsert_rules
from services.sarif import to_sarif
from tools import handlers

MCP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture()
def db():
    init_db()
    session = SessionLocal()
    session.query(LocalRule).delete()
    session.commit()
    load_starter_rules(session)
    try:
        yield session
    finally:
        session.close()


# ---------------------------------------------------------------- fake OSV.dev

VULNS = {
    "GHSA-aaaa": {"id": "GHSA-aaaa", "summary": "Header leak", "aliases": ["CVE-2018-1", "PYSEC-1"],
                  "database_specific": {"severity": "MODERATE"},
                  "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"},
                                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}]},
    "PYSEC-1": {"id": "PYSEC-1", "summary": "Header leak (dup)", "aliases": ["GHSA-aaaa", "CVE-2018-1"],
                "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"},
                              "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}]},
    "GHSA-bbbb": {"id": "GHSA-bbbb", "summary": "Proxy auth leak", "aliases": ["CVE-2023-2"],
                  "database_specific": {"severity": "HIGH"},
                  "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"},
                                "ranges": [{"events": [{"introduced": "2.3.0"}, {"fixed": "2.31.0"}]}]}]},
}


class FakeHTTP:
    def __init__(self):
        self.batch_calls = 0

    def post(self, url, json=None, timeout=None):
        self.batch_calls += 1
        results = []
        for q in json["queries"]:
            hit = q["package"]["name"] == "requests" and q["version"] == "2.19.0"
            results.append({"vulns": [{"id": "GHSA-aaaa"}, {"id": "PYSEC-1"}, {"id": "GHSA-bbbb"}]} if hit else {})
        resp = Mock()
        resp.raise_for_status.return_value = None
        resp.json.return_value = {"results": results}
        return resp

    def get(self, url, timeout=None):
        resp = Mock()
        resp.raise_for_status.return_value = None
        resp.json.return_value = VULNS[url.rsplit("/", 1)[1]]
        return resp


# ---------------------------------------------------------------- lockfile parsers

def test_parsers(tmp_path):
    files = {
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "app"}, "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/a/node_modules/@scope/b": {"version": "1.0.0"}}}),
        "yarn.lock": '"left-pad@^1.0.0", left-pad@~1.3.0:\n  version "1.3.0"\n\n"@babel/core@^7.0.0":\n  version "7.1.0"\n',
        "requirements.txt": "requests==2.19.0\nflask>=2  # not pinned\nuvicorn[standard]==0.30.0 ; python_version>'3'\n",
        "Pipfile.lock": json.dumps({"default": {"django": {"version": "==3.0.0"}}, "develop": {}}),
        "poetry.lock": '[[package]]\nname = "jinja2"\nversion = "2.10"\n',
        "Cargo.lock": '[[package]]\nname = "time"\nversion = "0.1.0"\n',
        "Gemfile.lock": "GEM\n  specs:\n    rails (5.0.0)\n      actionpack (= 5.0.0)\n",
        "go.mod": "module x\n\nrequire (\n\tgolang.org/x/net v0.1.0 // indirect\n)\nrequire github.com/a/b v1.2.3\n",
    }
    got = set()
    for name, text in files.items():
        got |= {(e, n, v) for e, n, v, _, _ in dc.parse_lockfile(str(tmp_path / name), text)}
    expected = {
        ("npm", "lodash", "4.17.20"), ("npm", "@scope/b", "1.0.0"), ("npm", "left-pad", "1.3.0"),
        ("npm", "@babel/core", "7.1.0"), ("PyPI", "requests", "2.19.0"), ("PyPI", "uvicorn", "0.30.0"),
        ("PyPI", "django", "3.0.0"), ("RubyGems", "rails", "5.0.0"), ("Go", "golang.org/x/net", "v0.1.0"),
        ("Go", "github.com/a/b", "v1.2.3"),
    }
    if sys.version_info >= (3, 11):
        expected |= {("PyPI", "jinja2", "2.10"), ("crates.io", "time", "0.1.0")}
    assert expected <= got
    assert ("PyPI", "flask", "2") not in got


def test_dependency_findings_are_grouped_and_deduplicated(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\nflask==3.1.3\n", encoding="utf-8")
    http = FakeHTTP()
    data = dc.check_dependencies(str(tmp_path), client=dc.OSVClient(cache={}, session=http))
    assert data["packages"] == 2 and data["error"] is None
    (finding,) = data["violations"]
    assert finding["title"] == "Vulnerable dependency: requests 2.19.0"
    assert finding["advisories"] == ["GHSA-aaaa", "GHSA-bbbb"]  # PYSEC-1 is an alias of GHSA-aaaa
    assert finding["severity"] == "high"
    assert finding["required_actions"][0] == "Upgrade requests to 2.31.0 or later (from 2.19.0)"
    assert "CVE-2018-1" in finding["references"] and finding["line"] == 1


def test_dependency_mute_by_cve(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
    data = dc.check_dependencies(str(tmp_path), client=dc.OSVClient(cache={}, session=FakeHTTP()),
                                 muted=["CVE-2023-2"])
    assert data["violations"][0]["advisories"] == ["GHSA-aaaa"]


def test_osv_results_are_cached():
    http, cache = FakeHTTP(), {}
    client = dc.OSVClient(cache=cache, session=http)
    client.vulnerable([("PyPI", "requests", "2.19.0")])
    client.vulnerable([("PyPI", "requests", "2.19.0")])
    assert http.batch_calls == 1


def test_osv_unreachable_is_reported_not_raised(tmp_path):
    import requests
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
    http = Mock()
    http.post.side_effect = requests.ConnectionError("down")
    data = dc.check_dependencies(str(tmp_path), client=dc.OSVClient(cache={}, session=http))
    assert data["violations"] == [] and "OSV.dev" in data["error"]


# ---------------------------------------------------------------- cached project scan

def test_project_scan_uses_cache_and_reruns_only_new_rules(db, tmp_path):
    (tmp_path / "a.py").write_text("data = pickle.loads(b)\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("print('ok')\n", encoding="utf-8")

    first = scan_project(db, str(tmp_path), include_dependencies=False)
    assert (first["files_scanned"], first["files_from_cache"]) == (2, 0)
    assert {f["rule_id"] for f in first["violations"]} == {"SHAMMAH-0015"}

    second = scan_project(db, str(tmp_path), include_dependencies=False)
    assert (second["files_scanned"], second["files_from_cache"]) == (0, 2)
    assert second["violations"] == first["violations"]

    # a new rule arrives: unchanged files are checked against it only
    upsert_rules(db, [{"rule_id": "DSV-TEST-PRINT", "rule_type": "dsv", "source": "test", "severity": "low",
                       "title": "print call", "description": "d",
                       "pattern": {"type": "regex", "value": r"\bprint\(", "language": "python"},
                       "enforcement": {"message": "m", "required_actions": ["a"]}}])
    third = scan_project(db, str(tmp_path), include_dependencies=False)
    assert third["files_scanned"] == 2 and third["files_from_cache"] == 0
    assert {f["rule_id"] for f in third["violations"]} == {"SHAMMAH-0015", "DSV-TEST-PRINT"}

    # a changed file is rescanned with every rule
    (tmp_path / "a.py").write_text("data = json.loads(b)\n", encoding="utf-8")
    fourth = scan_project(db, str(tmp_path), include_dependencies=False)
    assert {f["rule_id"] for f in fourth["violations"]} == {"DSV-TEST-PRINT"}
    assert fourth["files_from_cache"] == 1


def test_project_scan_respects_mutes_and_excludes(db, tmp_path):
    (tmp_path / "a.py").write_text("hashlib.md5(x)\npickle.loads(b)\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "t.py").write_text("eval(x)\n", encoding="utf-8")
    mute_rule(str(tmp_path), "SHAMMAH-0018")
    cfg_path = tmp_path / ".shammah" / "config.json"
    cfg = json.loads(cfg_path.read_text())
    cfg["exclude"] = ["tests/**"]
    cfg_path.write_text(json.dumps(cfg))

    result = scan_project(db, str(tmp_path), include_dependencies=False)
    assert {f["rule_id"] for f in result["violations"]} == {"SHAMMAH-0015"}
    assert load_config(str(tmp_path))["muted_rules"] == ["SHAMMAH-0018"]
    assert blocking_count(result, "high") == 1 and blocking_count(result, "critical") == 0


def test_report_false_positive_mutes_rule(db, tmp_path):
    text, data = handlers.report_false_positive(db, rule_id="SHAMMAH-0018", reason="used for cache keys",
                                                project_path=str(tmp_path))
    assert data["muted_rules"] == ["SHAMMAH-0018"]
    assert "issues/new" in text  # no Pro feed configured: points to the issue template


# ---------------------------------------------------------------- SARIF

def test_sarif_shape(db, tmp_path):
    (tmp_path / "a.py").write_text("x = 1\ndata = pickle.loads(b)\n", encoding="utf-8")
    result = scan_project(db, str(tmp_path), include_dependencies=False)
    sarif = to_sarif(result["violations"])
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert run["tool"]["driver"]["rules"][0]["id"] == "SHAMMAH-0015"
    loc = run["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "a.py" and loc["region"]["startLine"] == 2
    assert run["results"][0]["level"] == "error"


# ---------------------------------------------------------------- rule quality

def _rule(**over):
    base = {"rule_id": "T-1", "title": "t", "severity": "high",
            "pattern": {"type": "regex", "value": r"danger\(", "language": "any"},
            "enforcement": {"message": "m", "required_actions": ["a"]},
            "examples": {"bad": ["danger(x)"], "good": ["safe(x)"]}}
    base.update(over)
    return base


def test_rule_quality_checks():
    assert check_rule(_rule()) == []
    assert any("misses its bad example" in p for p in check_rule(_rule(examples={"bad": ["nope"], "good": ["safe"]})))
    assert any("false positive" in p for p in check_rule(_rule(examples={"bad": ["danger("], "good": ["danger(1)"]})))
    assert any("nested quantifier" in p for p in check_rule(_rule(pattern={"type": "regex", "value": r"(a+)+b"})))
    assert any("does not compile" in p for p in check_rule(_rule(pattern={"type": "regex", "value": "("})))
    assert any("needs at least one" in p for p in check_rule(_rule(examples={})))
    report = check_rules([_rule(), _rule()])
    assert "T-1" in report["failed"]  # duplicate id


def test_all_starter_rules_pass_their_examples():
    from config import STARTER_RULES_PATH
    rules = json.loads(STARTER_RULES_PATH.read_text(encoding="utf-8"))["rules"]
    report = check_rules(rules)
    assert report["failed"] == {}
    assert len(report["passed"]) == len(rules)


# ---------------------------------------------------------------- init and hook

def test_init_merges_and_is_idempotent(tmp_path, capsys):
    from shammah_init import MAIN_PY, run_init
    (tmp_path / "CLAUDE.md").write_text("# My project\n\nKeep this.\n", encoding="utf-8")
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"other": {"command": "x"}}}), encoding="utf-8")
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "mcp.json").write_text("{not json", encoding="utf-8")

    code = run_init(str(tmp_path))
    assert code == 1  # the broken .vscode/mcp.json is reported, not overwritten
    assert (tmp_path / ".vscode" / "mcp.json").read_text(encoding="utf-8") == "{not json"

    mcp = json.loads((tmp_path / ".mcp.json").read_text())
    assert set(mcp["mcpServers"]) == {"other", "shammah"}
    assert mcp["mcpServers"]["shammah"]["args"] == [MAIN_PY]
    claude_md = (tmp_path / "CLAUDE.md").read_text(encoding="utf-8")
    assert "Keep this." in claude_md and claude_md.count("shammah:start") == 1
    hooks = json.loads((tmp_path / ".claude" / "settings.json").read_text())["hooks"]["PostToolUse"]
    assert len(hooks) == 1 and hooks[0]["hooks"][0]["command"].endswith(" hook")
    assert "alwaysApply: true" in (tmp_path / ".cursor" / "rules" / "shammah.mdc").read_text(encoding="utf-8")
    assert "shammah:start" in (tmp_path / "AGENTS.md").read_text(encoding="utf-8")

    (tmp_path / ".vscode" / "mcp.json").write_text("{}", encoding="utf-8")
    assert run_init(str(tmp_path)) == 0
    assert (tmp_path / "CLAUDE.md").read_text(encoding="utf-8") == claude_md
    hooks = json.loads((tmp_path / ".claude" / "settings.json").read_text())["hooks"]["PostToolUse"]
    assert len(hooks) == 1  # no duplicate hook


def test_hook_returns_2_with_findings_for_the_agent(tmp_path):
    bad = tmp_path / "bad.py"
    bad.write_text("data = pickle.loads(b)\n", encoding="utf-8")
    good = tmp_path / "good.py"
    good.write_text("print('hi')\n", encoding="utf-8")
    env = {**os.environ, "DATABASE_URL": "sqlite:///" + str(tmp_path / "hook.db").replace("\\", "/"),
           "AUTO_SYNC_ON_START": "false"}

    def run(path):
        payload = json.dumps({"tool_name": "Write", "tool_input": {"file_path": str(path)}})
        return subprocess.run([sys.executable, os.path.join(MCP_DIR, "main.py"), "hook"], input=payload,
                              capture_output=True, text=True, env=env, timeout=120)

    blocked = run(bad)
    assert blocked.returncode == 2
    assert blocked.stderr.startswith("Shammah found security issues") and "SHAMMAH-0015" in blocked.stderr
    assert run(good).returncode == 0
    assert run(tmp_path / "missing.py").returncode == 0


# ---------------------------------------------------------------- Shammah Pro feed client

def test_feed_sync_and_reporting(db):
    http = Mock()
    rules_resp = Mock(status_code=200)
    rules_resp.raise_for_status.return_value = None
    rules_resp.json.return_value = {"ruleset_version": "v1", "rules": [{
        "rule_id": "DSV-2026-0200", "rule_type": "cve", "source": "nvd", "severity": "high", "title": "Feed rule",
        "description": "d", "pattern": {"type": "regex", "value": r"feedDanger\(", "language": "any"},
        "enforcement": {"message": "m", "required_actions": ["a"]}}]}
    http.get.return_value = rules_resp
    client = FeedClient(api_key="shm_test", url="https://feed.example", session=http)

    result = client.sync(db)
    assert result["status"] == "success" and result["created"] == 1
    assert db.query(LocalRule).filter_by(rule_id="DSV-2026-0200").one().source == "feed:nvd"
    assert http.get.call_args.kwargs["headers"]["Authorization"] == "Bearer shm_test"
    client.sync(db)
    assert "since" in http.get.call_args.kwargs["params"]

    denied = Mock(status_code=401)
    http.get.return_value = denied
    assert "refused the API key" in client.sync(db)["message"]

    assert FeedClient(api_key="", url="").sync(db)["status"] == "disabled"


def test_scan_summary_contains_no_code(db, tmp_path):
    (tmp_path / "a.py").write_text('API_KEY = "supersecretvalue123"\n', encoding="utf-8")
    result = scan_project(db, str(tmp_path), include_dependencies=False)
    summary = scan_summary(result, repository="me/app", commit="abc", branch="main", trigger="push")
    text = json.dumps(summary)
    assert "supersecretvalue123" not in text and "API_KEY" not in text
    assert summary["rule_ids"] == ["SHAMMAH-0001"] and summary["counts"]["high"] == 1
