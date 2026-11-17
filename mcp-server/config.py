"""
MCP Server Configuration
"""
import os
from dotenv import load_dotenv

load_dotenv()

# Backend Connection
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")

# Local Database
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./mcp_local.db")

# Sync Settings
SYNC_INTERVAL_HOURS = int(os.getenv("SYNC_INTERVAL_HOURS", "24"))
AUTO_SYNC_ON_START = os.getenv("AUTO_SYNC_ON_START", "true").lower() == "true"
