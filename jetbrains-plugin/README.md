# Security MCP JetBrains Plugin

The Security MCP JetBrains plugin brings real-time security enforcement to your JetBrains IDE. It connects to the Security MCP backend to scan your code for vulnerabilities as you type.

## Features

- Real-time scanning of code for security vulnerabilities
- Integration with the Security MCP backend and rule set
- Context-aware security recommendations
- Quick-fix suggestions for common security issues
- Security dashboard to monitor project health

## Requirements

- Security MCP backend server running
- Valid API token for authentication

## Installation

1. Build the plugin using Gradle: `./gradlew buildPlugin`
2. Install the plugin in your JetBrains IDE from disk
3. Configure the backend URL and API token in the plugin settings

## Commands

- `Scan Current File`: Scan the current file for security vulnerabilities
- `Apply Security Quick Fix`: Apply quick fixes for detected security issues

## Known Issues

Currently, this is a basic implementation that connects to the Security MCP backend. More advanced features like real-time annotation will be implemented in future versions.