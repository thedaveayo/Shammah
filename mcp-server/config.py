"""
MCP Server Configuration
All settings come from environment variables (or mcp-server/.env).
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Folder this file lives in. Coding agents start the server from any working
# directory, so paths are resolved relative to here, not the current directory.
MCP_DIR = Path(__file__).resolve().parent

load_dotenv(MCP_DIR / ".env")

# Backend Connection (optional: the server works offline with its starter rules)
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000").rstrip("/")
SYNC_TIMEOUT_SECONDS = float(os.getenv("SYNC_TIMEOUT_SECONDS", "10"))

# Shammah Pro: hosted rule feed (both must be set to use it)
SHAMMAH_API_KEY = os.getenv("SHAMMAH_API_KEY", "")
SHAMMAH_FEED_URL = os.getenv("SHAMMAH_FEED_URL", "").rstrip("/")

# Local Database
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{(MCP_DIR / 'mcp_local.db').as_posix()}")

# Starter rules shipped with the server
STARTER_RULES_PATH = MCP_DIR / "rules" / "starter_rules.json"

# Sync Settings
SYNC_INTERVAL_HOURS = int(os.getenv("SYNC_INTERVAL_HOURS", "24"))
AUTO_SYNC_ON_START = os.getenv("AUTO_SYNC_ON_START", "true").lower() == "true"

# Local HTTP bridge for IDE extensions (python main.py --bridge)
BRIDGE_HOST = os.getenv("BRIDGE_HOST", "127.0.0.1")
BRIDGE_PORT = int(os.getenv("BRIDGE_PORT", "8765"))
