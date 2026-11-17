# Shammah JetBrains Plugin (prototype)

Scans code in JetBrains IDEs with Shammah, through the local bridge.

## Requirements

The Shammah bridge running on your machine:

```bash
cd mcp-server
pip install -r requirements.txt
python main.py --bridge        # http://127.0.0.1:8765
```

No account or token is needed.

## Installation

1. Build the plugin: `./gradlew buildPlugin`
2. In your IDE, install it from disk (Settings → Plugins → ⚙ → Install Plugin from Disk)

The plugin calls the bridge at `http://127.0.0.1:8765`. To use another address, set the `SHAMMAH_BRIDGE_URL` environment variable before starting the IDE.

## Commands

- `Scan Current File`: scan the current file for security issues
- `Apply Security Quick Fix`: show fix suggestions for the current file

## Known issues

This is an early prototype: there is no settings page yet, and the plugin hasn't been built or tested against the current bridge. Contributions welcome.
