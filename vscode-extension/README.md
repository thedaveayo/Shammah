# Shammah for VS Code

Shows Shammah's security findings in the editor as you type, using the same rules coding agents get through MCP.

## Requirements

The Shammah bridge running on your machine:

```bash
cd mcp-server
pip install -r requirements.txt
python main.py --bridge        # http://127.0.0.1:8765
```

No account or token is needed.

## Build and install

The extension isn't on the Marketplace yet. Build it from source:

```bash
cd vscode-extension
npm install
npm run compile
npx @vscode/vsce package       # creates security-mcp-0.0.1.vsix
code --install-extension security-mcp-0.0.1.vsix
```

## Features

- Findings in the Problems panel and as squiggles at the exact code: critical/high as errors, medium as warnings, low as info
- Scans when you open, edit (after a 1-second pause) or save a file
- **Security MCP: Scan Current File** – scan on demand
- **Security MCP: Show Fix Suggestions** – fix steps for every issue in the current file
- **Security MCP: Show Security Dashboard** – issue counts and loaded rules

## Settings

- `security-mcp.serverUrl`: URL of the bridge (default `http://127.0.0.1:8765`)
- `security-mcp.enableRealtimeScanning`: scan while you type (default `true`)

## Privacy

Your code is sent only to the bridge on your own machine.
