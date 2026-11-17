# Security Policy

Shammah is a security tool, so we take vulnerabilities in it seriously.

## Reporting a vulnerability

**Please do not open a public issue.** Instead, report it privately through GitHub:

1. Go to the [Security tab](https://github.com/thedaveayo/Shammah/security) of this repository.
2. Click **Report a vulnerability**.
3. Describe the issue, how to reproduce it, and its impact.

You can expect an acknowledgement within 7 days. We'll keep you updated while we work on a fix and credit you in the release notes unless you'd rather stay anonymous.

## Supported versions

Shammah is in early development. Only the latest code on the `main` branch receives security fixes.

## Scope

In scope:
- the backend API (`backend/`)
- the MCP server (`mcp-server/`)
- the web interface (`web-interface/`)
- the IDE extensions (`vscode-extension/`, `jetbrains-plugin/`)

Out of scope:
- missing or inaccurate security rules (please open a normal issue for those)
- vulnerabilities in third-party dependencies that are already publicly known (a pull request that upgrades them is welcome)

## Running Shammah safely

- Set a long, random `ADMIN_API_KEY` on any backend reachable by others, and keep it secret.
- Keep `HOST=127.0.0.1` unless you need remote access, and put a reverse proxy with TLS in front if you do.
- Limit `CORS_ORIGINS` to the sites that really need browser access.
- Don't expose the web interface to the internet without authentication and rate limiting.
