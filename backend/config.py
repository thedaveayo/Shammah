"""
Security MCP Backend Configuration
"""
import os
from dotenv import load_dotenv

load_dotenv()

# Database
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./security_mcp.db")

# API Keys
NVD_API_KEY = os.getenv("NVD_API_KEY", "")  # NVD API for CVE feeds
QWEN_API_KEY = os.getenv("QWEN_API_KEY", "")  # Alibaba Qwen LLM (Singapore)
QWEN_BASE_URL = os.getenv("QWEN_BASE_URL", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1")  # Singapore endpoint
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")  # Telegram bot for submissions

# Backend Settings
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
SYNC_INTERVAL_HOURS = int(os.getenv("SYNC_INTERVAL_HOURS", "6"))

# JWT Settings (Subscription Tokens)
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRE_DAYS = 30

# LLM Settings (Qwen Flash)
LLM_MODEL = os.getenv("QWEN_MODEL", "qwen-flash")  # Qwen Flash for fast, cheap agentic work
LLM_TEMPERATURE = 0.1  # Low temperature for consistent extraction
