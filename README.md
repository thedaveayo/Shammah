# Shammah - Dave Sourced Vulnerability System

An MCP server that acts as an authoritarian security gate for IDE coding agents, enforcing security rules derived from CVE feeds, CWE feeds, and other curated sources.

## Quick Start

### Backend (Your Server)
```bash
cd backend
pip install -r requirements.txt
python main.py
```

### MCP Server (User's Machine)
```bash
cd mcp-server
pip install -r requirements.txt
python main.py
```

## Architecture

- **Backend**: Security Agent that processes CVE/CWE/curated sources → generates rules
- **MCP Server**: Local enforcer that blocks unsafe code in IDE
- **Subscription**: Auth token-based ($15/month, 30-day expiry, 7-day grace period)

## Documentation

- [PLAN.md](PLAN.md) - Full implementation plan
- [BUILD_LOG.md](BUILD_LOG.md) - Action log with timestamps
- [docs/api.md](docs/api.md) - Backend API documentation
- [docs/mcp-tools.md](docs/mcp-tools.md) - MCP tool documentation

## License

Proprietary - Dave Sourced Vulnerability System
