# Security MCP User Guide & Tutorials

## Table of Contents
1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Using Security MCP](#using-security-mcp)
6. [Tutorials](#tutorials)
7. [Troubleshooting](#troubleshooting)
8. [FAQ](#faq)

## Introduction

Security MCP (Model Context Protocol) is a security enforcement system that integrates directly into your IDE to provide real-time security scanning and enforcement as you write code. The system blocks security vulnerabilities before they're written by analyzing code against a comprehensive database of security rules.

### Key Features
- Real-time security scanning as you type
- Integration with popular IDEs (VS Code, JetBrains IDEs)
- Over 2,000 security rules covering CVEs, CWEs, and custom DSV rules
- Context-aware analysis based on your technology stack
- Detailed fix suggestions and security explanations
- Subscription-based access to continuously updated rules

## Getting Started

### Prerequisites
- Python 3.8 or higher
- Node.js (for JavaScript AST analysis)
- An active internet connection to sync security rules
- A Security MCP subscription token (contact us for evaluation access)

### System Requirements
- Operating System: Windows, macOS, or Linux
- RAM: 4GB minimum, 8GB recommended
- Disk Space: 500MB available space

## Installation

### Backend Server Installation
1. Clone the Security MCP repository:
   ```bash
   git clone https://github.com/your-org/security-mcp.git
   cd security-mcp/backend
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
   The server will be available at `http://localhost:8000`

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
   # Edit .env with your backend URL and token
   ```

4. Activate your subscription:
   ```bash
   python activate.py --token YOUR_SUBSCRIPTION_TOKEN --user-id YOUR_USER_ID
   ```

5. Start the MCP server:
   ```bash
   python main.py
   ```

### IDE Extensions
#### VS Code Extension
1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X)
3. Search for "Security MCP"
4. Install the extension
5. Configure the extension with your backend URL and API token

#### JetBrains IDE Plugin
1. Open your JetBrains IDE (IntelliJ IDEA, PyCharm, etc.)
2. Go to Settings (Ctrl+Alt+S)
3. Navigate to Plugins
4. Click "Marketplace" and search for "Security MCP"
5. Install the plugin
6. Restart your IDE
7. Configure the plugin with your backend URL and API token

## Configuration

### Backend Configuration
The backend configuration is managed through the `.env` file:

```bash
# Backend Configuration
DATABASE_URL=sqlite:///./security_mcp.db

# API Keys
NVD_API_KEY=your_nvd_api_key_here
QWEN_API_KEY=your_qwen_api_key_here
QWEN_BASE_URL=https://your-qwen-endpoint.com
TELEGRAM_BOT_TOKEN=your_telegram_bot_token

# Backend Settings
BACKEND_URL=http://localhost:8000
SYNC_INTERVAL_HOURS=6

# JWT Settings (CHANGE IN PRODUCTION!)
JWT_SECRET_KEY=your-secret-key-change-in-production
JWT_ALGORITHM=HS256
TOKEN_EXPIRE_DAYS=30

# LLM Settings (Qwen Flash)
QWEN_MODEL=qwen-flash
LLM_TEMPERATURE=0.1
```

### MCP Server Configuration
The MCP server configuration is managed through its `.env` file:

```bash
# MCP Server Configuration
BACKEND_URL=http://localhost:8000
AUTH_TOKEN=your_auth_token
SYNC_INTERVAL_HOURS=6
```

### IDE Extension Configuration
Extensions can be configured through the IDE settings:

1. Open your IDE settings
2. Search for "Security MCP"
3. Configure the following settings:
   - Backend URL: The URL of your backend server
   - API Token: Your authentication token
   - Enable Real-time Scanning: Whether to scan as you type

## Using Security MCP

### Real-time Scanning
Once installed and configured, Security MCP will automatically scan your code as you type:

1. Open a project in your IDE
2. Begin writing code
3. Security MCP will highlight potential security vulnerabilities
4. Hover over highlighted issues to see details
5. Use quick-fix suggestions to address issues

### Manual Scanning
You can also manually scan files or projects:

#### VS Code
- Right-click in the editor and select "Security MCP: Scan Current File"
- Or use the command palette (Ctrl+Shift+P) and search for "Security MCP: Scan Current File"

#### JetBrains IDEs
- Right-click in the editor and select "Security MCP" → "Scan Current File"
- Or use the corresponding keyboard shortcut

### Security Dashboard
Access the security dashboard to view project-wide security status:

#### VS Code
- Open the Command Palette (Ctrl+Shift+P)
- Search for "Security MCP: Show Security Dashboard"

#### JetBrains IDEs
- Look for the Security Dashboard tool window in your IDE
- If not visible, go to View → Tool Windows → Security Dashboard

### Applying Quick Fixes
When Security MCP detects an issue, it often provides quick-fix suggestions:

1. Click on the lightbulb icon that appears next to the issue
2. Select a suggested fix
3. The fix will be automatically applied to your code

## Tutorials

### Tutorial 1: Setting Up Security MCP for a New Project

1. **Install Backend Server**
   Follow the installation steps in the "Installation" section to set up the backend server.

2. **Activate Your Subscription**
   Contact Security MCP support to obtain a subscription token, then activate it:
   ```bash
   cd mcp-server
   python activate.py --token YOUR_TOKEN --user-id YOUR_USER_ID
   ```

3. **Install IDE Extension**
   Install the Security MCP extension for your preferred IDE.

4. **Configure the Extension**
   - Open IDE settings
   - Navigate to Security MCP settings
   - Enter your backend URL and API token
   - Enable real-time scanning

5. **Start Coding**
   Open a project in your IDE and start writing code. Security MCP will automatically scan for vulnerabilities.

### Tutorial 2: Understanding Security Alerts

When Security MCP identifies a potential security issue, it will:

1. **Highlight the Problem Code** - The problematic code will be underlined in your editor
2. **Show Alert Details** - Hover over the highlighted code to see details about the vulnerability
3. **Provide Fix Suggestions** - Look for quick-fix options in the form of lightbulb icons
4. **Link to Resources** - Security MCP often provides links to documentation about the vulnerability

Example alert:
```
Title: SQL Injection Vulnerability
Severity: HIGH
Description: Unsanitized input being used in SQL query construction
Suggestion: Use parameterized queries instead of string concatenation
```

### Tutorial 3: Customizing Security Rules

Security MCP allows you to customize which rules apply to your project:

1. **Technology Stack Detection**
   Security MCP automatically detects your project's technology stack (languages, frameworks, etc.) to apply relevant rules.

2. **Custom Rule Creation**
   For enterprise customers, custom security rules can be created to address organization-specific security policies.

3. **Rule Filtering**
   You can configure which types of rules to apply (e.g., disable low-severity warnings in development).

### Tutorial 4: Managing Subscriptions

1. **Check Subscription Status**
   - In your IDE, look for the Security MCP status indicator
   - Or visit your dashboard at `[backend-url]/dashboard`

2. **Renewing Subscriptions**
   - Contact Security MCP sales team before expiration
   - Update your token using the activation command

3. **Managing Multiple Projects**
   - Each project can use the same subscription token
   - Enterprise plans support multiple concurrent projects

## Troubleshooting

### Common Issues

**Issue: Extension not connecting to backend**
- Solution: Verify that the backend server is running and accessible at the configured URL
- Check firewall settings if running on different machines

**Issue: No security alerts appearing**
- Solution: Verify that real-time scanning is enabled in extension settings
- Ensure your project's technology stack is supported

**Issue: High CPU usage during scans**
- Solution: Adjust scan frequency in extension settings
- Consider excluding large, non-source files from scans

**Issue: False positive alerts**
- Solution: Report false positives through the Security MCP portal
- Temporary workaround: Add a comment to suppress specific alerts (e.g., `// security-mcp-ignore`)

### Debugging Tips

1. **Check Backend Logs**
   Monitor the backend server logs for any errors or warnings.

2. **Verify API Connectivity**
   Test connectivity between MCP server and backend using:
   ```bash
   curl -X GET http://localhost:8000/api/stats
   ```

3. **Review IDE Console**
   Check your IDE's developer console for extension-related errors.

4. **Update Security Rules**
   Manually trigger a rule sync if you suspect outdated rules:
   ```bash
   curl -X POST http://localhost:8000/api/sync
   ```

## FAQ

**Q: How does Security MCP differ from traditional static analysis tools?**
A: Security MCP operates in real-time as you write code, providing immediate feedback. Traditional tools typically analyze code after it's written. Security MCP also integrates with LLMs to provide context-aware, natural language explanations and fix suggestions.

**Q: Does Security MCP send my code to external servers?**
A: No, Security MCP analyzes code locally in your IDE. Only metadata about detected vulnerabilities may be sent to our servers for statistical purposes, with user consent.

**Q: Can Security MCP be used offline?**
A: The MCP server works offline using cached security rules, but it needs occasional internet access to sync new rules from the backend.

**Q: What programming languages does Security MCP support?**
A: Currently, Security MCP has full support for JavaScript, TypeScript, Python, Java, and Go. Support for additional languages is continuously expanding.

**Q: How often are security rules updated?**
A: Security rules are updated daily with new CVEs and emerging threat patterns. Premium subscribers receive updates as soon as they're available.

**Q: Is there a free tier available?**
A: Security MCP offers a limited free tier for open-source projects and individual developers. Contact our team for more information.

**Q: How do I report a security vulnerability in Security MCP itself?**
A: Please contact our security team directly at security@securitymcp.com. Do not report security vulnerabilities through public channels.

## Support

For additional support:
- Visit our documentation at [documentation URL]
- Join our community forum at [forum URL]
- Contact support at support@securitymcp.com
- For urgent security issues, contact security@securitymcp.com