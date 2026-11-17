# Shammah User Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Using Shammah](#using-shammah)
6. [Tutorials](#tutorials)
7. [Troubleshooting](#troubleshooting)
8. [FAQ](#faq)

## Introduction

Shammah is a security gate for AI coding agents. It runs as an MCP (Model Context Protocol) server next to your IDE and checks code against security rules built from public CVE and CWE data, so unsafe code is flagged before it lands in your project.

### Key Features
- Security checks that coding agents call through MCP tools
- IDE extensions for VS Code and JetBrains IDEs (early stage)
- 21 built-in starter rules, so it works with no other setup
- More rules generated from CVE and CWE data by the optional backend, plus your own curated rules
- Rules filtered by your project's technology stack
- Fix suggestions and plain-language explanations
- Free and open source under the AGPL-3.0 license

## Getting Started

### Prerequisites
- Python 3.10 or higher
- Git (for the GitHub repository scanner)
- An internet connection to fetch CVE/CWE data and sync rules
- Optional: an [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) for higher rate limits
- Optional: an OpenAI-compatible LLM API key, used to turn advisories into rules and to suggest fixes

### System Requirements
- Operating System: Windows, macOS, or Linux
- RAM: 4GB minimum
- Disk Space: 500MB available space

## Installation

### MCP Server Installation (start here)
1. Clone the repository and install the MCP server:
   ```bash
   git clone https://github.com/thedaveayo/Shammah.git
   cd Shammah/mcp-server
   pip install -r requirements.txt
   ```

2. Try it from the command line:
   ```bash
   python main.py --check path/to/some_file.py
   ```

3. Register it with your coding agent, using the absolute path to `main.py`. For Claude Code:
   ```bash
   claude mcp add shammah -- python /path/to/Shammah/mcp-server/main.py
   ```
   Cursor and VS Code examples are in [mcp-tools.md](mcp-tools.md).

The server comes with 21 starter rules, so this is all you need to get started.

### Backend Server Installation (optional)
The backend fetches CVE/CWE data and builds a larger rule set that MCP servers download. You can run your own.

1. Clone the repository:
   ```bash
   git clone https://github.com/thedaveayo/Shammah.git
   cd Shammah/backend
   ```

2. Install backend dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your API keys and settings
   ```

4. Start the backend server:
   ```bash
   python main.py
   ```
   The server will be available at `http://127.0.0.1:8000`

5. Point MCP servers at it by setting `BACKEND_URL` in `mcp-server/.env`. They sync on start, or run `python main.py --sync`.

### IDE Extensions
The extensions talk to the MCP server's local bridge. Start it with:

```bash
cd mcp-server
python main.py --bridge        # http://127.0.0.1:8765
```

The VS Code extension and JetBrains plugin are not published to the marketplaces yet. Build them from source:

- **VS Code:** see [`vscode-extension/README.md`](../vscode-extension/README.md)
- **JetBrains IDEs:** see [`jetbrains-plugin/README.md`](../jetbrains-plugin/README.md)

## Configuration

### Backend Configuration
The backend is configured through `backend/.env` (see `backend/.env.example`):

```bash
DATABASE_URL=sqlite:///./security_mcp.db

# Data sources and LLM
NVD_API_KEY=
QWEN_API_KEY=
QWEN_BASE_URL=https://dashscope-intl.aliyuncs.com/compatible-mode/v1
QWEN_MODEL=qwen-flash
TELEGRAM_BOT_TOKEN=

# Protects /api/fetch/*, /api/rules/telegram and /api/quick-fix/suggest.
# Leave empty to disable those routes.
ADMIN_API_KEY=

HOST=127.0.0.1
PORT=8000
SYNC_INTERVAL_HOURS=6
CORS_ORIGINS=http://localhost:3000,http://localhost:8000
```

`QWEN_*` works with any OpenAI-compatible API: point `QWEN_BASE_URL` and `QWEN_MODEL` at the provider you use.

### MCP Server Configuration
The MCP server is configured through `mcp-server/.env`:

```bash
BACKEND_URL=http://localhost:8000   # optional backend for extra rules
AUTO_SYNC_ON_START=true
SYNC_TIMEOUT_SECONDS=10
BRIDGE_PORT=8765                    # local bridge for IDE extensions
```

All settings are optional.

### IDE Extension Configuration
1. Open your IDE settings
2. Search for "Security MCP"
3. Set the bridge URL (default `http://127.0.0.1:8765`) and choose whether to scan as you type

## Using Shammah

### With a coding agent
Register the MCP server with your agent (see [mcp-tools.md](mcp-tools.md) for Claude Code, Cursor and VS Code examples). The agent can then call `enforce_security` on code it writes and get back violations to fix. To make that automatic, add this to your project instructions (`CLAUDE.md`, `.cursorrules`, ...):

> Before writing code, call the `enforce_security` tool with the code and its language. If it says BLOCKED, fix the issues and check again.

### From the command line
```bash
python mcp-server/main.py --check src/app.py   # exit code 1 if anything blocks
```

### Manual Scanning

#### VS Code
- Right-click in the editor and select "Security MCP: Scan Current File"
- Or open the command palette (Ctrl+Shift+P) and run "Security MCP: Scan Current File"

#### JetBrains IDEs
- Right-click in the editor and select "Security MCP" → "Scan Current File"

### Security Dashboard

#### VS Code
- Open the command palette (Ctrl+Shift+P) and run "Security MCP: Show Security Dashboard"

#### JetBrains IDEs
- Open View → Tool Windows → Security Dashboard

## Tutorials

### Tutorial 1: Setting Up Shammah for a New Project

1. **Install the MCP server** and register it with your coding agent (see Installation).
2. **Tell the agent to use it** by adding the instruction above to your project instructions.
3. **Start coding.** The agent checks generated code with `enforce_security` and fixes anything that's blocked.
4. **Optional: more rules.** Run the backend, set `ADMIN_API_KEY`, fetch CWE and CVE data, then sync:
   ```bash
   curl -X POST http://localhost:8000/api/fetch/cwe -H "Authorization: Bearer $ADMIN_API_KEY"
   curl -X POST http://localhost:8000/api/fetch/cve -H "Authorization: Bearer $ADMIN_API_KEY"
   python mcp-server/main.py --sync
   ```

### Tutorial 2: Understanding Security Alerts

When Shammah finds a problem it returns:

1. **The rule** that matched, with its CVE/CWE references
2. **A severity** (critical, high, medium or low)
3. **A plain-language explanation** of the risk
4. **Required actions** to fix it

Example:
```
Title: SQL Injection Vulnerability
Severity: HIGH
Description: Unsanitized input being used in SQL query construction
Suggestion: Use parameterized queries instead of string concatenation
```

### Tutorial 3: Customizing Security Rules

1. **Technology stack detection:** Shammah detects your project's languages and frameworks and applies matching rules.
2. **Curated rules:** post advisories to `/api/rules/telegram` (admin key required) and the backend turns them into rules.
3. **Severity:** critical, high and medium findings block; low findings only warn. See [severity-guide.md](severity-guide.md).

## Troubleshooting

### Common Issues

**Extension not connecting**
- Start the bridge: `python main.py --bridge` in `mcp-server/`
- Check `http://127.0.0.1:8765/health` responds and the extension's server URL matches

**Agent doesn't see the Shammah tools**
- Use the absolute path to `mcp-server/main.py` in the agent's MCP config
- Make sure `command` is a Python that has the requirements installed (e.g. your virtual environment's Python)

**Admin routes return 503**
- Set `ADMIN_API_KEY` in `backend/.env` and restart the backend

**No security alerts appearing**
- Ask the agent to run `get_compliance_status` to see how many rules are loaded
- Pass the right `language`; rules are filtered by language

**False positive alerts**
- Open an issue with a minimal code sample so the rule can be improved

### Debugging Tips

1. **Check backend logs** for errors or warnings.
2. **Verify API connectivity:**
   ```bash
   curl http://localhost:8000/api/stats
   ```
3. **Review the IDE console** for extension errors.

## FAQ

**Q: How is Shammah different from traditional static analysis tools?**
A: It is built for AI coding agents: the agent checks code through MCP while it writes, instead of a scan running after the fact. It can also use an LLM to explain issues and suggest fixes.

**Q: Does Shammah send my code to external servers?**
A: Pattern matching runs locally in the MCP server. Code is only sent to an LLM provider if you call the quick-fix route on a backend that has an LLM key configured.

**Q: Can Shammah be used offline?**
A: Yes. The MCP server works offline with its starter rules and any rules it synced before. It only needs a connection to sync new rules from a backend.

**Q: What does it cost?**
A: Nothing. Shammah is free and open source under the AGPL-3.0 license. You pay only for any third-party APIs you choose to use (for example an LLM provider).

**Q: How do I report a security vulnerability in Shammah itself?**
A: Follow [SECURITY.md](../SECURITY.md). Please don't open a public issue for vulnerabilities.

## Support

- Questions and bugs: [GitHub Issues](https://github.com/thedaveayo/Shammah/issues)
- Contributing: [CONTRIBUTING.md](../CONTRIBUTING.md)
