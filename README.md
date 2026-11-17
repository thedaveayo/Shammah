# Shammah

**A security gate for AI coding agents.** Shammah is an MCP (Model Context Protocol) server that checks the code your coding agent writes against security rules built from public CVE and CWE data, and blocks unsafe code before it lands in your project.

> **Status: early stage.** The core pieces work, but expect rough edges. See [Known issues](#known-issues).

## How it works

```
CVE feed (NVD) ─┐
CWE catalog ────┼─► Backend ──► rules ──► MCP server ◄──► your coding agent / IDE
Curated tips ───┘   (FastAPI)              (local)
```

- **Backend** (`backend/`): fetches CVE and CWE data, uses an LLM to turn advisories into rules, and serves them over a small API. Run your own.
- **MCP server** (`mcp-server/`): runs on your machine, keeps a local copy of the rules, and gives coding agents tools such as `enforce_security` and `get_fix_suggestions`.
- **IDE extensions** (`vscode-extension/`, `jetbrains-plugin/`): early prototypes for scanning inside VS Code and JetBrains IDEs.
- **Web interface** (`web-interface/`): a small local page for scanning a public GitHub repository.

Rules are identified as `DSV-YYYY-NNNN` (DSV = Dave Sourced Vulnerability) and keep links to their CVE/CWE sources.

## Quick start

Requires Python 3.10+.

### 1. Run the backend

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env        # then fill in what you need
python main.py              # http://127.0.0.1:8000, API docs at /docs
```

To load rules, set `ADMIN_API_KEY` in `.env`, restart, then:

```bash
curl -X POST http://127.0.0.1:8000/api/fetch/cwe -H "Authorization: Bearer $ADMIN_API_KEY"
curl -X POST http://127.0.0.1:8000/api/fetch/cve -H "Authorization: Bearer $ADMIN_API_KEY"
```

### 2. Run the MCP server

```bash
cd mcp-server
pip install -r requirements.txt
cp .env.example .env        # set BACKEND_URL
python main.py
```

Then register it with your coding agent. See [docs/mcp-tools.md](docs/mcp-tools.md) for Cursor and VS Code examples.

## Configuration

| Variable | Where | Purpose |
|---|---|---|
| `NVD_API_KEY` | backend | Optional. Higher NVD rate limits. |
| `QWEN_API_KEY`, `QWEN_BASE_URL`, `QWEN_MODEL` | backend | Any OpenAI-compatible LLM, used to generate rules and fixes. |
| `ADMIN_API_KEY` | backend | Protects routes that change data or call paid APIs. Empty = those routes are off. |
| `HOST`, `PORT` | backend | Defaults to `127.0.0.1:8000`. |
| `CORS_ORIGINS` | backend | Comma-separated browser origins allowed to call the API. |
| `BACKEND_URL` | mcp-server | Where to sync rules from. |

Full details: [docs/user-guide-tutorial.md](docs/user-guide-tutorial.md) and [docs/deployment.md](docs/deployment.md).

## Documentation

- [User guide](docs/user-guide-tutorial.md)
- [Backend API](docs/api.md)
- [MCP tools](docs/mcp-tools.md)
- [Severity guide](docs/severity-guide.md)
- [Deployment](docs/deployment.md)

## Known issues

- The VS Code extension and JetBrains plugin call `/api/tools/call`, which the backend does not provide yet.
- `mcp-server/main.py` and `mcp-server/tools/enforce_security.py` define two different tool sets; they should be merged.
- Rule sync from the MCP server calls `/api/sync`, which the backend does not provide yet.
- Some tests in `backend/tests` and `mcp-server/tests` fail because their mocks no longer match the code.

Help with any of these is welcome.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and our [Code of Conduct](CODE_OF_CONDUCT.md). To report a security vulnerability, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## License

Shammah is licensed under the [GNU Affero General Public License v3.0](LICENSE). If you run a modified version as a network service, you must offer its source code to the users of that service.

Rule data is derived from MITRE CWE and the NIST National Vulnerability Database. See [NOTICE](NOTICE) for attributions.
