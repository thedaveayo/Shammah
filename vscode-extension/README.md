# Security MCP Extension

The Security MCP extension brings real-time security enforcement to your VS Code editor. It connects to the Security MCP backend to scan your code for vulnerabilities as you type.

## Features

- Real-time scanning of code for security vulnerabilities
- Integration with the Security MCP backend and rule set
- Context-aware security recommendations
- Quick-fix suggestions for common security issues
- Security dashboard to monitor project health

## Requirements

- Security MCP backend server running
- No account or token needed; Shammah is free and open source

## Extension Settings

This extension contributes the following settings:

- `security-mcp.backendUrl`: URL of the Security MCP backend server (default: http://localhost:8000)
- `security-mcp.apiToken`: optional token, only needed if you put your backend behind an authenticating proxy
- `security-mcp.enableRealtimeScanning`: Enable real-time scanning of code as you type (default: true)

## Commands

- `security-mcp.scanCurrentFile`: Scan the current file for security vulnerabilities
- `security-mcp.showSecurityDashboard`: Show the security dashboard
- `security-mcp.applyQuickFix`: Apply quick fixes for detected security issues

## Known Issues

Currently, this is a basic implementation that connects to the Security MCP backend. Position mapping for diagnostics needs to be implemented based on the actual MCP server response format.