# Shammah

**A security gate for AI coding agents.** Shammah is an MCP (Model Context Protocol) server that checks the code your coding agent writes against security rules built from public CVE and CWE data, and blocks unsafe code before it lands in your project.

> **Status: early stage.** The core pieces work, but expect rough edges. See [Known issues](#known-issues).

## How it works

```
CVE feed (NVD) ─┐                                   ┌──► coding agent (MCP, stdio)
CWE catalog ────┼─► Backend ──/api/sync──► MCP server
Curated tips ───┘   (optional)             (local)  └──► IDE extensions (local HTTP bridge)
                                              ▲
                                     built-in starter rules
```

- **MCP server** (`mcp-server/`): runs on your machine and gives coding agents tools such as `enforce_security`, `security_scan_file` and `security_scan_project`. It ships with 21 hand-checked starter rules (leaked keys, SQL built from strings, XSS, shell injection, unsafe deserialization, disabled TLS checks and more), so it works without a backend.
- **Backend** (`backend/`, optional): fetches CVE and CWE data, uses an LLM to turn advisories into more rules, and serves them to MCP servers through `/api/sync`. Run your own.
- **IDE extensions** (`vscode-extension/`, `jetbrains-plugin/`): show findings in the editor by calling the MCP server's local bridge.
- **Web interface** (`web-interface/`): a small local page for scanning a public GitHub repository.

Critical, high and medium findings **block**; low findings only **warn**. Starter rules are `SHAMMAH-NNNN`; rules from the backend are `DSV-YYYY-NNNN` (DSV = Dave Sourced Vulnerability). Every rule links to its CWE/CVE source.

## Quick start

Requires Python 3.10+.

### 1. Install the MCP server

```bash
git clone https://github.com/thedaveayo/Shammah.git
cd Shammah/mcp-server
pip install -r requirements.txt
python main.py --check path/to/some_file.py     # try it from the command line
```

### 2. Connect your coding agent

Use the **absolute** path to `mcp-server/main.py`.

**Claude Code**
```bash
claude mcp add shammah -- python /path/to/Shammah/mcp-server/main.py
```

**Cursor** (`.cursor/mcp.json`) or **VS Code** (`.vscode/mcp.json`, using `"servers"` instead of `"mcpServers"`)
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

Then ask your agent to check its code with Shammah, or add a line like this to your project instructions (`CLAUDE.md`, `.cursorrules`, ...):

> Before writing code, call the `enforce_security` tool with the code and its language. If it says BLOCKED, fix the issues and check again.

See [docs/mcp-tools.md](docs/mcp-tools.md) for every tool.

### 3. Optional: IDE extension

```bash
cd mcp-server
python main.py --bridge        # local bridge on http://127.0.0.1:8765
```

Then build and install the [VS Code extension](vscode-extension/README.md). Findings show up in the Problems panel as you type.

### 4. Optional: run your own backend for more rules

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env        # set ADMIN_API_KEY and an LLM key
python main.py              # http://127.0.0.1:8000, API docs at /docs
curl -X POST http://127.0.0.1:8000/api/fetch/cwe -H "Authorization: Bearer $ADMIN_API_KEY"
curl -X POST http://127.0.0.1:8000/api/fetch/cve -H "Authorization: Bearer $ADMIN_API_KEY"
```

The MCP server syncs from `BACKEND_URL` (default `http://localhost:8000`) when it starts, or on demand with the `sync_rules` tool or `python main.py --sync`. If no backend is reachable it keeps using the rules it has.

## Configuration

| Variable | Where | Purpose |
|---|---|---|
| `NVD_API_KEY` | backend | Optional. Higher NVD rate limits. |
| `QWEN_API_KEY`, `QWEN_BASE_URL`, `QWEN_MODEL` | backend | Any OpenAI-compatible LLM, used to generate rules and fixes. |
| `ADMIN_API_KEY` | backend | Protects routes that change data or call paid APIs. Empty = those routes are off. |
| `HOST`, `PORT` | backend | Defaults to `127.0.0.1:8000`. |
| `CORS_ORIGINS` | backend | Comma-separated browser origins allowed to call the API. |
| `BACKEND_URL` | mcp-server | Where to sync extra rules from (optional). |
| `AUTO_SYNC_ON_START` | mcp-server | Sync from the backend when the server starts (default `true`). |
| `BRIDGE_PORT` | mcp-server | Port of the local bridge for IDE extensions (default `8765`). |

Full details: [docs/user-guide-tutorial.md](docs/user-guide-tutorial.md) and [docs/deployment.md](docs/deployment.md).

## Documentation

- [User guide](docs/user-guide-tutorial.md)
- [Backend API](docs/api.md)
- [MCP tools](docs/mcp-tools.md)
- [Severity guide](docs/severity-guide.md)
- [Deployment](docs/deployment.md)

## Known issues

- Matching is pattern-based (regular expressions), so expect some false positives and misses. Please report both with the "Rule request or false positive" issue template.
- The VS Code extension and JetBrains plugin aren't published to their marketplaces yet; build them from source. The JetBrains plugin has no settings page yet (set `SHAMMAH_BRIDGE_URL` to change its address).
- Some older tests in `backend/tests` and `mcp-server/tests` fail because their mocks no longer match the code. CI skips them by name until they're fixed.

Help with any of these is welcome.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and our [Code of Conduct](CODE_OF_CONDUCT.md). To report a security vulnerability, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## License

Shammah is licensed under the [GNU Affero General Public License v3.0](LICENSE). If you run a modified version as a network service, you must offer its source code to the users of that service.

Rule data is derived from MITRE CWE and the NIST National Vulnerability Database. See [NOTICE](NOTICE) for attributions.
