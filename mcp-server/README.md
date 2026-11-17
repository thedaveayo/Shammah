# Shammah MCP Server

Model Context Protocol (MCP) server for coding agents. It checks code as it is written against Shammah's security rules.

## Architecture

- **MCP server** (this folder): runs locally and talks to coding agents over MCP.
- **Backend** (`../backend`): builds the rules from CVE/CWE data. Run your own and point `BACKEND_URL` at it.
- **Coding agent**: any MCP-capable assistant or IDE.

## Quick start

```bash
cd mcp-server
pip install -r requirements.txt
cp .env.example .env    # set BACKEND_URL
python main.py
```

Then register the server with your coding agent. See [../docs/mcp-tools.md](../docs/mcp-tools.md).

## Tools

- `scan_code_block`: scan a code block for vulnerabilities after it is generated
- `get_security_report`: summary, detailed or fixes report for a project
- `get_fix_suggestions`: fix suggestions for identified issues

## How it works

1. The agent writes code.
2. The agent calls a Shammah tool with that code.
3. Shammah matches it against local rules.
4. Issues and suggested fixes go back to the agent.

## Supported languages

JavaScript/TypeScript, Python, Java, Go, PHP, Ruby and C#.

## Configuration

Set in `.env`:

```
BACKEND_URL=http://localhost:8000
DATABASE_URL=sqlite:///./mcp_local.db
SYNC_INTERVAL_HOURS=24
AUTO_SYNC_ON_START=true
```

## Troubleshooting

**Connection refused**
- Make sure the server is running and your agent points at it.

**No security issues detected**
- Check that the backend has rules: `curl http://localhost:8000/api/stats`.
- Check that `BACKEND_URL` is correct.

## Privacy

Code is analyzed locally. The MCP server only contacts the backend to download rules.

## License

[AGPL-3.0](../LICENSE)
