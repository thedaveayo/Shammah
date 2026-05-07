# Shammah Server

Model Context Protocol (MCP) server for coding agents. Provides real-time security scanning for code as it's being written.

## Overview

Shammah integrates with coding agents to provide security scanning capabilities. The server connects to the Shammah backend to receive continuously updated security rules.

## Architecture

- **MCP Server**: Runs locally, communicates with coding agents via MCP protocol
- **Backend Service**: Hosted service that manages security rules and subscriptions
- **Coding Agents**: AI coding assistants that utilize security scanning

## Quick Start

### 1. Activate Your Subscription
```bash
cd mcp-server
python activate.py --token YOUR_SUBSCRIPTION_TOKEN
```

### 2. Start the Shammah Server
```bash
python main.py
```

### 3. Connect Your Coding Agent
Configure your MCP-enabled IDE or coding agent to connect to `localhost:8080`

## Features

### Security Scanning
- `scan_code_block`: Scan a code block for security vulnerabilities after generation
- `get_security_report`: Get a detailed security report for the current project
- `get_fix_suggestions`: Get specific fix suggestions for identified security issues

### Subscription Management
- `validate_subscription`: Validate the current subscription status

## How It Works

1. **Code Generation**: Agent writes code
2. **Post-Generation Scan**: Shammah scans code after generation is complete
3. **Issue Detection**: Potential security issues are identified
4. **Reporting**: Results are reported to the agent/developer
5. **Fix Suggestions**: Specific fixes are suggested when possible

## Supported Languages

- JavaScript/TypeScript
- Python
- Java
- Go
- PHP
- Ruby
- C#

## Configuration

The server is configured via environment variables in `.env`:

```
BACKEND_URL=http://localhost:8000
AUTH_TOKEN=your-subscription-token
```

## Troubleshooting

### Common Issues

**Issue: Connection refused**
- Ensure the Shammah server is running on port 8080
- Check firewall settings

**Issue: Invalid subscription**
- Verify your subscription token is valid
- Check that the token hasn't expired

**Issue: No security issues detected**
- Ensure your code contains actual vulnerabilities
- Verify the server is connected to the backend for updated rules

### Debugging

Enable debug logging by setting the environment variable:
```
LOG_LEVEL=DEBUG
```

## Security

- All code analysis happens locally
- Only metadata about detected issues is sent to the backend
- Authentication tokens are stored securely

## License

[License information]