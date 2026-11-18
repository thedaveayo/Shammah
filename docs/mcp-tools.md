# MCP Tools

The Shammah MCP server (`mcp-server/main.py`) gives coding agents these tools. Every tool returns readable text. The local bridge for IDE extensions returns the same text in `result` plus the structured data shown below.

## Connecting an agent

Use the absolute path to `mcp-server/main.py`. The server talks MCP over stdio.

**Claude Code**
```bash
claude mcp add shammah -- python /path/to/Shammah/mcp-server/main.py
```

**Cursor** – `.cursor/mcp.json`
```json
{
  "mcpServers": {
    "shammah": {
      "command": "python",
      "args": ["/path/to/Shammah/mcp-server/main.py"]
    }
  }
}
```

**VS Code** – `.vscode/mcp.json`
```json
{
  "servers": {
    "shammah": {
      "type": "stdio",
      "command": "python",
      "args": ["/path/to/Shammah/mcp-server/main.py"]
    }
  }
}
```

If you use a virtual environment, point `command` at that environment's Python.

To make the agent use Shammah automatically, add to your project instructions:

> Before writing code, call the `enforce_security` tool with the code and its language. If it says BLOCKED, fix the issues and check again.

---

## `enforce_security`

Check code before using it. This is the main tool.

| Argument | Required | Description |
|---|---|---|
| `code` | yes | The code to check |
| `language` | no | e.g. `python`, `javascript`, `typescript`, `java`. Without it, rules for every language are used. |

**Text result**
```
BLOCKED: 1 issue(s) must be fixed before this code is used.

1. [CRITICAL] SQL query built from strings (Python) (SHAMMAH-0014) at line 3
   Why: The database query is built from strings. Attackers can change the query and read or delete your data.
   Fix: Pass values as parameters: cursor.execute(sql, (value,)); Use your ORM's query builder
   Refs: CWE-89
   Code: .execute(f"
```

The first word is always `BLOCKED` (critical, high or medium issues), `PASS WITH WARNINGS` (low only) or `PASS`.

**Structured data (bridge)**
```json
{
  "blocked": true,
  "compliant": false,
  "violation_count": 1,
  "counts": {"critical": 1, "high": 0, "medium": 0, "low": 0},
  "violations": [{
    "rule_id": "SHAMMAH-0014",
    "title": "SQL query built from strings (Python)",
    "severity": "critical",
    "message": "The database query is built from strings...",
    "required_actions": ["Pass values as parameters: cursor.execute(sql, (value,))"],
    "references": ["CWE-89"],
    "matched_code": ".execute(f\"",
    "line": 3, "column": 11, "end_line": 3, "end_column": 22
  }]
}
```

## `security_scan_file`

Scan a file on disk. Arguments: `file_path` (absolute path), `include_details` (default `true`). The language is taken from the file extension.

## `security_scan_project`

Scan every source and config file in a folder (skips `.git`, `node_modules`, virtual environments and build output). Arguments: `project_path`, `max_files` (default 2000). Returns counts by severity and the most severe issues with `file:line`.

## `security_fix_suggestions`

Fix steps for each issue in some code. Arguments: `code`, `language`, `vulnerability_type` (optional filter such as `sql` or `CWE-79`).

## `security_context_explain`

Explain the security impact of code. Arguments: `code`, `language`, `audience` (`developer`, `manager` or `security-expert`).

## `security_rule_details`

What a rule checks and how to fix it. Arguments: `rule_id`, `include_examples` (also show the pattern).

## `get_compliance_status`

Rules loaded (by source), last backend sync and the project's detected stack. Argument: `project_path`.

## `get_infrastructure_profile`

Languages, frameworks and infrastructure detected in a project. Argument: `project_path`.

## `sync_rules`

Download new rules from the backend in `BACKEND_URL`. Argument: `full` (download everything again). If the backend can't be reached, the server keeps the rules it has.

---

## Enforcement levels

| Severity | Result |
|----------|--------|
| **Critical / High / Medium** | `BLOCKED` until fixed |
| **Low** | `PASS WITH WARNINGS` |

## Command line

```bash
python main.py                 # MCP server over stdio (what agents run)
python main.py --check FILE    # scan one file; exit code 1 if anything blocks
python main.py --sync          # sync rules from the backend once
python main.py --bridge        # local HTTP bridge for IDE extensions
```

`--check` makes a simple pre-commit or CI check:

```bash
python /path/to/Shammah/mcp-server/main.py --check src/app.py
```

## Local bridge (for IDE extensions)

`python main.py --bridge` serves the same tools on `http://127.0.0.1:8765`:

```bash
curl -X POST http://127.0.0.1:8765/api/tools/call \
  -H "Content-Type: application/json" \
  -d '{"name": "enforce_security", "arguments": {"code": "eval(x)", "language": "javascript"}}'
```

`GET /health` returns the number of rules loaded. The bridge only accepts requests made to `localhost` and refuses requests from web pages (any request with an `Origin` header).
