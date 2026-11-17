"""
Shammah Backend Configuration
All settings come from environment variables (or a .env file).
"""
import os
from dotenv import load_dotenv

load_dotenv()

# Database
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./security_mcp.db")

# API Keys
NVD_API_KEY = os.getenv("NVD_API_KEY", "")  # NVD API for CVE feeds (optional, raises rate limits)
QWEN_API_KEY = os.getenv("QWEN_API_KEY", "")  # Any OpenAI-compatible LLM key (default: Alibaba Qwen)
QWEN_BASE_URL = os.getenv("QWEN_BASE_URL", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")  # Telegram bot for submissions (optional)

# Admin key for routes that change data or call paid APIs.
# Leave empty to disable those routes.
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")

# Server
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8000"))
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
SYNC_INTERVAL_HOURS = int(os.getenv("SYNC_INTERVAL_HOURS", "6"))

# Comma-separated list of origins allowed to call the API from a browser.
CORS_ORIGINS = [
    o.strip()
    for o in os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:8000").split(",")
    if o.strip()
]

# LLM Settings
LLM_MODEL = os.getenv("QWEN_MODEL", "qwen-flash")
LLM_TEMPERATURE = 0.1  # Low temperature for consistent extraction
