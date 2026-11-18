"""
Tests for the rule store, tool handlers, rule sync, HTTP bridge and the MCP
server itself (started over stdio and driven by a real MCP client).
"""
import json
import os
import re
import sys
import threading
import urllib.error
import urllib.request
from unittest.mock import Mock, patch

import pytest

from config import STARTER_RULES_PATH
from database import SessionLocal, init_db
from models.rule import LocalRule
from services.rule_store import find_issues, load_starter_rules, normalize_language, rules_for_language, upsert_rules
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


def _ids(findings):
    return {f["rule_id"] for f in findings}


# ---------------------------------------------------------------- starter rules

def test_starter_rules_file_is_valid():
    data = json.loads(STARTER_RULES_PATH.read_text(encoding="utf-8"))
    ids = [r["rule_id"] for r in data["rules"]]
    assert len(ids) == len(set(ids))
    for r in data["rules"]:
        re.compile(r["pattern"]["value"])
        assert r["severity"] in {"critical", "high", "medium", "low"}
        assert r["enforcement"]["message"] and r["enforcement"]["required_actions"]
        assert r["cwe_refs"]


@pytest.mark.parametrize("language,code,rule_id", [
    ("python", 'password = "hunter2hunter2"', "SHAMMAH-0001"),
    ("javascript", "const k = 'AKIAABCDEFGHIJKLMNOP';", "SHAMMAH-0002"),
    ("javascript", "eval(userInput)", "SHAMMAH-0003"),
    ("typescript", "el.innerHTML = name;", "SHAMMAH-0005"),
    ("javascript", "exec(`ls ${dir}`)", "SHAMMAH-0007"),
    ("javascript", "db.query(`SELECT * FROM t WHERE id = ${id}`)", "SHAMMAH-0008"),
    ("python", "eval(data)", "SHAMMAH-0011"),
    ("python", "subprocess.call(cmd, shell=True)", "SHAMMAH-0012"),
    ("python", 'os.system("rm " + path)', "SHAMMAH-0013"),
    ("python", 'cur.execute(f"SELECT * FROM u WHERE n = {n}")', "SHAMMAH-0014"),
    ("python", "obj = pickle.loads(blob)", "SHAMMAH-0015"),
    ("python", "yaml.load(stream)", "SHAMMAH-0016"),
    ("python", "requests.get(url, verify=False)", "SHAMMAH-0017"),
    ("python", "app.run(debug=True)", "SHAMMAH-0019"),
    ("java", 'stmt.executeQuery("SELECT * FROM u WHERE id = " + id);', "SHAMMAH-0021"),
])
def test_starter_rules_catch_bad_code(db, language, code, rule_id):
    assert rule_id in _ids(find_issues(code, rules_for_language(db, language)))


@pytest.mark.parametrize("language,code", [
    ("python", 'password = os.environ["PASSWORD"]'),
    ("python", 'cur.execute("SELECT * FROM u WHERE n = %s", (n,))'),
    ("python", "subprocess.run(['ls', path])"),
    ("python", "yaml.load(stream, Loader=yaml.SafeLoader)"),
    ("python", "result = ast.literal_eval(text)"),
    ("javascript", "el.textContent = name;"),
    ("javascript", "if (a.innerHTML == b) {}"),
    ("javascript", "db.query('SELECT * FROM t WHERE id = $1', [id])"),
])
def test_starter_rules_allow_safe_code(db, language, code):
    assert find_issues(code, rules_for_language(db, language)) == []


# ---------------------------------------------------------------- languages and positions

def test_language_aliases():
    assert normalize_language("typescriptreact") == "javascript"
    assert normalize_language(".py") == "python"
    assert normalize_language(None) == ""


def test_rules_are_filtered_by_language(db):
    js = _ids(find_issues("eval(x)", rules_for_language(db, "javascript")))
    py = _ids(find_issues("eval(x)", rules_for_language(db, "python")))
    assert js == {"SHAMMAH-0003"}
    assert py == {"SHAMMAH-0011"}


def test_findings_have_line_and_column(db):
    code = "import pickle\n\nx = 1\ndata = pickle.loads(b)\n"
    finding = next(f for f in find_issues(code, rules_for_language(db, "python")) if f["rule_id"] == "SHAMMAH-0015")
    assert (finding["line"], finding["column"]) == (4, 8)


# ---------------------------------------------------------------- handlers

def test_enforce_security_blocks_and_passes(db):
    text, data = handlers.enforce_security(db, code='cur.execute(f"SELECT {x}")', language="python")
    assert text.startswith("BLOCKED")
    assert data["blocked"] is True and data["counts"]["critical"] == 1

    text, data = handlers.enforce_security(db, code="x = hashlib.md5(b).hexdigest()", language="python")
    assert text.startswith("PASS WITH WARNINGS")
    assert data["blocked"] is False and data["violation_count"] == 1

    text, data = handlers.enforce_security(db, code="print('hello')", language="python")
    assert text.startswith("PASS:")
    assert data["compliant"] is True


def test_scan_project_and_file(db, tmp_path):
    (tmp_path / "app.py").write_text("pickle.loads(x)\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "lib.js").write_text("eval(x)\n", encoding="utf-8")
    (tmp_path / "settings.json").write_text('{"api_key": "abcdefghijklmnop"}', encoding="utf-8")

    _, data = handlers.security_scan_project(db, project_path=str(tmp_path))
    files = {v["file_path"] for v in data["violations"]}
    assert files == {"app.py", "settings.json"}  # node_modules skipped
    assert data["files_scanned"] == 2

    _, data = handlers.security_scan_file(db, file_path=str(tmp_path / "app.py"))
    assert _ids(data["violations"]) == {"SHAMMAH-0015"}

    text, data = handlers.security_scan_file(db, file_path=str(tmp_path / "missing.py"))
    assert "error" in data


def test_rule_details_and_fixes(db):
    text, data = handlers.security_rule_details(db, rule_id="SHAMMAH-0014", include_examples=True)
    assert "CWE-89" in text and data["pattern"]["type"] == "regex"
    _, data = handlers.security_fix_suggestions(db, code="eval(x)", language="python")
    assert data["fixes"][0]["steps"]


# ---------------------------------------------------------------- rule sync

def test_upsert_is_idempotent(db):
    rule = {"rule_id": "DSV-TEST-0001", "rule_type": "dsv", "source": "telegram", "severity": "high",
            "title": "Test", "description": "d", "pattern": {"type": "regex", "value": "danger\\(", "language": "any"},
            "enforcement": {"message": "m", "required_actions": ["a"]}}
    assert upsert_rules(db, [rule]) == (1, 0)
    rule["severity"] = "critical"
    assert upsert_rules(db, [rule]) == (0, 1)
    assert db.query(LocalRule).filter_by(rule_id="DSV-TEST-0001").one().severity == "critical"


def test_sync_stores_backend_rules(db):
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {"new_rules": [{
        "rule_id": "DSV-2026-0042", "rule_type": "dsv", "source": "telegram", "severity": "high",
        "title": "Token in localStorage", "description": "d",
        "pattern": {"type": "regex", "value": r"localStorage\.setItem\(\s*['\"]token", "language": "javascript"},
        "applies_to": {"languages": ["javascript"]},
        "enforcement": {"message": "Tokens in localStorage can be stolen by XSS", "required_actions": ["Use httpOnly cookies"]},
    }]}
    with patch("services.rule_sync.requests.post", return_value=response) as post:
        text, result = handlers.sync_rules(db)
    assert result["status"] == "success" and result["created"] == 1
    assert post.call_args.kwargs["json"]["last_sync"] is None
    _, data = handlers.enforce_security(db, code="localStorage.setItem('token', t)", language="javascript")
    assert "DSV-2026-0042" in _ids(data["violations"])

    with patch("services.rule_sync.requests.post", return_value=response) as post:
        handlers.sync_rules(db)
    assert post.call_args.kwargs["json"]["last_sync"] is not None  # second sync only asks for changes


def test_sync_failure_keeps_rules(db):
    text, result = handlers.sync_rules(db)  # BACKEND_URL points at a closed port
    assert result["status"] == "error"
    assert "keeps working" in text
    assert db.query(LocalRule).count() > 0


# ---------------------------------------------------------------- HTTP bridge

@pytest.fixture()
def bridge(db):
    from http_bridge import make_server
    httpd = make_server("127.0.0.1", 0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def _post(url, body, headers=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_bridge_runs_tools(bridge):
    status, body = _post(bridge + "/api/tools/call",
                         {"name": "enforce_security", "arguments": {"code": "eval(x)", "language": "javascript"}})
    assert status == 200
    assert body["blocked"] is True and body["result"].startswith("BLOCKED")
    assert body["violations"][0]["line"] == 1

    with urllib.request.urlopen(bridge + "/health", timeout=10) as r:
        assert json.loads(r.read())["status"] == "ok"


def test_bridge_rejects_bad_requests(bridge):
    url = bridge + "/api/tools/call"
    assert _post(url, {"name": "nope"})[0] == 404
    assert _post(url, {"name": "enforce_security", "arguments": {}})[0] == 400
    assert _post(url, {"name": "enforce_security", "arguments": {"code": "x"}},
                 headers={"Origin": "https://evil.example"})[0] == 403
    assert _post(url, {"name": "enforce_security", "arguments": {"code": "x"}},
                 headers={"Host": "evil.example"})[0] == 403


# ---------------------------------------------------------------- MCP over stdio

def test_mcp_server_end_to_end_over_stdio(tmp_path):
    """Start main.py as a coding agent would and call tools through a real MCP client"""
    import anyio
    from mcp.client import Client
    from mcp.client.stdio import StdioServerParameters

    env = {**os.environ, "DATABASE_URL": "sqlite:///" + str(tmp_path / "e2e.db").replace("\\", "/"),
           "AUTO_SYNC_ON_START": "false", "PYTHONIOENCODING": "utf-8"}
    params = StdioServerParameters(command=sys.executable, args=[os.path.join(MCP_DIR, "main.py")],
                                   env=env, cwd=str(tmp_path))

    async def run():
        async with Client(params, read_timeout_seconds=60) as client:
            tools = {t.name for t in (await client.list_tools()).tools}
            result = await client.call_tool("enforce_security",
                                            {"code": 'cursor.execute(f"SELECT * FROM t WHERE id={i}")',
                                             "language": "python"})
            text = result.content[0].text
            ok = await client.call_tool("enforce_security", {"code": "print('hi')", "language": "python"})
            return tools, text, ok.content[0].text

    tools, blocked_text, ok_text = anyio.run(run)
    assert {"enforce_security", "security_scan_file", "security_scan_project", "sync_rules"} <= tools
    assert blocked_text.startswith("BLOCKED") and "SHAMMAH-0014" in blocked_text
    assert ok_text.startswith("PASS")
