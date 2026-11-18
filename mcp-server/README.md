# Shammah MCP Server

Model Context Protocol (MCP) server that lets coding agents check code for security problems before they write it.

## Quick start

```bash
cd mcp-server
pip install -r requirements.txt
python main.py --check path/to/file.py   # try it
```

Register it with your agent using the absolute path to `main.py`, for example in Claude Code:

```bash
claude mcp add shammah -- python /path/to/Shammah/mcp-server/main.py
```

Cursor and VS Code examples are in [../docs/mcp-tools.md](../docs/mcp-tools.md).

## Rules

- **Starter rules** (`rules/starter_rules.json`): 21 hand-checked rules for JavaScript/TypeScript, Python, Java and any language (leaked secrets). Loaded on every start, so the server works offline.
- **Backend rules**: if you run the Shammah backend, the server downloads its rules from `BACKEND_URL` on start (`AUTO_SYNC_ON_START`) or with the `sync_rules` tool.

Rules are stored in `mcp_local.db` next to `main.py`.

## Tools

`enforce_security`, `security_scan_file`, `security_scan_project`, `security_fix_suggestions`, `security_context_explain`, `security_rule_details`, `get_compliance_status`, `get_infrastructure_profile`, `security_check_dependencies`, `mute_rule`, `report_false_positive`, `sync_rules`. See [../docs/mcp-tools.md](../docs/mcp-tools.md).

## Modes

```bash
python main.py                      # MCP over stdio (what agents run)
python main.py init [PROJECT]       # connect your agents: MCP config, instructions, hook
python main.py scan [PROJECT]       # code + dependencies, cached; --format sarif for GitHub
python main.py check FILE           # scan one file; exit code 1 if anything blocks
python main.py hook                 # agent hook (Claude Code PostToolUse)
python main.py bridge               # local HTTP bridge for IDE extensions (127.0.0.1:8765)
python main.py sync                 # pull new rules (backend and/or Shammah Pro feed)
python main.py test-rules           # check every rule against its examples
```

For CI, `requirements-scan.txt` installs just what `scan` and `check` need (no MCP library).

## Configuration

Optional settings in `mcp-server/.env` (see `.env.example`):

```
BACKEND_URL=http://localhost:8000
SYNC_TIMEOUT_SECONDS=10
AUTO_SYNC_ON_START=true
BRIDGE_HOST=127.0.0.1
BRIDGE_PORT=8765
LOG_LEVEL=INFO

# Shammah Pro (optional)
SHAMMAH_API_KEY=
SHAMMAH_FEED_URL=
```

Logs go to stderr, because stdout carries the MCP protocol.

## Tests

```bash
python -m pytest tests
```

`tests/test_server.py` includes an end-to-end test that starts `main.py` and drives it with a real MCP client.

## Privacy

Code is checked locally. The server only contacts the backend in `BACKEND_URL` to download rules; it never sends your code anywhere.

## License

[AGPL-3.0](../LICENSE)
