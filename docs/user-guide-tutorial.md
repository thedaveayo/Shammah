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
- About 1,000 rules generated from CVE and CWE data, plus your own curated rules
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

### Backend Server Installation
The backend fetches CVE/CWE data and builds the rule set. You can run your own.

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

### MCP Server Installation
1. Navigate to the MCP server directory:
   ```bash
   cd ../mcp-server
   ```

2. Install MCP server dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up environment variables:
   ```bash
   cp .env.example .env
   # Set BACKEND_URL to your backend
   ```

4. Start the MCP server:
   ```bash
   python main.py
   ```

### IDE Extensions
The VS Code extension and JetBrains plugin are not published to the marketplaces yet. Build them from source:

- **VS Code:** see [`vscode-extension/README.md`](../vscode-extension/README.md)
- **JetBrains IDEs:** see [`jetbrains-plugin/README.md`](../jetbrains-plugin/README.md)

Then set the backend URL in the extension settings.

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
BACKEND_URL=http://localhost:8000
DATABASE_URL=sqlite:///./mcp_local.db
SYNC_INTERVAL_HOURS=24
AUTO_SYNC_ON_START=true
```

### IDE Extension Configuration
1. Open your IDE settings
2. Search for "Security MCP"
3. Set the backend URL and choose whether to scan as you type

## Using Shammah

### With a coding agent
Register the MCP server with your agent (see [mcp-tools.md](mcp-tools.md) for Cursor and VS Code examples). The agent can then call `enforce_security` on code it writes and get back violations to fix.

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

1. **Run the backend** following the installation steps above.
2. **Load rules:** with `ADMIN_API_KEY` set, fetch CWE and CVE data:
   ```bash
   curl -X POST http://localhost:8000/api/fetch/cwe -H "Authorization: Bearer $ADMIN_API_KEY"
   curl -X POST http://localhost:8000/api/fetch/cve -H "Authorization: Bearer $ADMIN_API_KEY"
   ```
3. **Run the MCP server** and register it with your coding agent.
4. **Start coding.** The agent checks generated code with `enforce_security`.

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

**Extension not connecting to backend**
- Check that the backend is running at the configured URL
- If the backend runs on another machine, set `HOST=0.0.0.0` and add the extension's origin to `CORS_ORIGINS`

**Admin routes return 503**
- Set `ADMIN_API_KEY` in `backend/.env` and restart the backend

**No security alerts appearing**
- Check that rules have been fetched: `curl http://localhost:8000/api/stats`
- Check that your project's technology stack is supported

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
A: The MCP server works offline with cached rules. It needs a connection to sync new rules from the backend.

**Q: What does it cost?**
A: Nothing. Shammah is free and open source under the AGPL-3.0 license. You pay only for any third-party APIs you choose to use (for example an LLM provider).

**Q: How do I report a security vulnerability in Shammah itself?**
A: Follow [SECURITY.md](../SECURITY.md). Please don't open a public issue for vulnerabilities.

## Support

- Questions and bugs: [GitHub Issues](https://github.com/thedaveayo/Shammah/issues)
- Contributing: [CONTRIBUTING.md](../CONTRIBUTING.md)
