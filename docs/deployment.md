# Deployment Guide

## Prerequisites

- Python 3.11+
- NVD API Key (free from https://nvd.nist.gov/developers/request-an-api-key)
- Anthropic API Key (https://console.anthropic.com/)
- Telegram Bot Token (optional, from @BotFather)

---

## Backend Deployment

### Option 1: Railway (Recommended)

1. **Create Railway Account**
   ```
   https://railway.app/
   ```

2. **Deploy from GitHub**
   ```bash
   # Push code to GitHub
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin <your-repo>
   git push
   ```

3. **Connect Railway to GitHub Repo**
   - Create new project in Railway
   - Select "Deploy from GitHub"
   - Choose your repo

4. **Set Environment Variables**
   ```
   DATABASE_URL=postgresql://...  # Railway auto-provides
   NVD_API_KEY=your_nvd_key
   ANTHROPIC_API_KEY=your_anthropic_key
   TELEGRAM_BOT_TOKEN=your_bot_token
   JWT_SECRET_KEY=<generate-random-string>
   ```

5. **Deploy**
   Railway auto-deploys on push

---

### Option 2: Local Development

1. **Install Dependencies**
   ```bash
   cd backend
   pip install -r requirements.txt
   ```

2. **Configure Environment**
   ```bash
   cp .env.example .env
   # Edit .env with your API keys
   ```

3. **Run Server**
   ```bash
   python main.py
   ```

4. **Access API**
   ```
   http://localhost:8000
   http://localhost:8000/docs  # Swagger UI
   ```

---

### Option 3: VPS (DigitalOcean, Linode, etc.)

1. **Install Python & Dependencies**
   ```bash
   sudo apt update
   sudo apt install python3.11 python3-pip
   pip3 install -r requirements.txt
   ```

2. **Set up PostgreSQL**
   ```bash
   sudo apt install postgresql
   sudo -u postgres psql
   CREATE DATABASE security_mcp;
   ```

3. **Configure Environment**
   ```bash
   cp .env.example .env
   # Edit with your settings
   ```

4. **Run with Gunicorn**
   ```bash
   gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:8000
   ```

5. **Set up systemd Service**
   ```ini
   # /etc/systemd/system/security-mcp.service
   [Unit]
   Description=Security MCP Backend
   After=network.target

   [Service]
   User=www-data
   WorkingDirectory=/path/to/backend
   ExecStart=/usr/local/bin/gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:8000
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```

   ```bash
   sudo systemctl enable security-mcp
   sudo systemctl start security-mcp
   ```

---

## MCP Server Installation (User Side)

### Installation

1. **Clone/Download MCP Server**
   ```bash
   git clone <repo>
   cd security-mcp/mcp-server
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure**
   ```bash
   cp .env.example .env
   # Edit BACKEND_URL to point to your backend
   ```

4. **Activate Subscription**
   ```bash
   # Get auth token from backend after subscribing
   python -c "from services.subscription import LocalSubscriptionManager; from database import SessionLocal; db = SessionLocal(); mgr = LocalSubscriptionManager(db); mgr.activate('your_auth_token', 'user123')"
   ```

5. **Configure IDE**
   
   **Cursor:**
   Add to `.cursor/mcp.json`:
   ```json
   {
     "mcpServers": {
       "security-mcp": {
         "command": "python",
         "args": ["/absolute/path/to/mcp-server/main.py"],
         "cwd": "/absolute/path/to/mcp-server"
       }
     }
   }
   ```

   **VS Code:**
   Install MCP extension, add to settings:
   ```json
   {
     "mcp.servers": {
       "security-mcp": {
         "type": "stdio",
         "command": "python",
         "args": ["/absolute/path/to/mcp-server/main.py"]
       }
     }
   }
   ```

---

## Initial Setup

### 1. Fetch CWE Taxonomy (One-time)
```bash
curl -X POST http://localhost:8000/api/fetch/cwe \
  -H "Authorization: Bearer <admin_token>"
```

This downloads 600+ CWE entries and converts them to rules (~30 minutes).

### 2. Fetch Recent CVEs
```bash
curl -X POST http://localhost:8000/api/fetch/cve \
  -H "Authorization: Bearer <admin_token>"
```

### 3. Test Telegram Ingestion
```bash
curl -X POST http://localhost:8000/api/rules/telegram \
  -H "Content-Type: application/json" \
  -d '{
    "message_text": "New auth bypass in Express.js\nseverity: high\nhttps://example.com/article"
  }'
```

### 4. Generate Export
The export JSON is auto-generated after each rule change:
```bash
curl http://localhost:8000/api/public/rules
```

---

## Monitoring

### Health Check
```bash
curl http://localhost:8000/health
```

### View Logs (Railway)
```bash
railway logs
```

### View Logs (VPS)
```bash
journalctl -u security-mcp -f
```

---

## Backup

### Database Backup
```bash
# SQLite (default)
cp security_mcp.db security_mcp.backup.db

# PostgreSQL
pg_dump security_mcp > backup.sql
```

### Export Backup
```bash
curl http://localhost:8000/api/public/rules > rules-backup.json
```

---

## Troubleshooting

### Backend won't start
- Check environment variables are set
- Verify API keys are valid
- Check database connection

### MCP not connecting to IDE
- Verify absolute paths in MCP config
- Check Python environment has all dependencies
- Restart IDE

### Rules not syncing
- Verify subscription is active
- Check BACKEND_URL in MCP config
- Look for auth errors in logs
