# MCP Tools Documentation

The MCP server exposes these tools to IDE coding agents:

---

## 1. `enforce_security`

Validates code against security rules. Returns violations that must be fixed before proceeding.

**Parameters:**
```json
{
  "code": "const API_KEY = 'sk_live_abc123'",
  "language": "javascript"  // optional
}
```

**Response (Active Subscription - Violation Found):**
```json
{
  "blocked": true,
  "subscription_status": "active",
  "compliant": false,
  "violations": [
    {
      "rule_id": "DSV-2026-0001",
      "rule_type": "dsv",
      "severity": "high",
      "message": "Your code has a password written directly in it. Anyone who sees your code can steal this password.",
      "required_actions": ["Move API key to backend", "Use environment variables"],
      "example_fix": "const API_KEY = process.env.API_KEY",
      "matched_code": "const API_KEY = 'sk_live_abc123'"
    }
  ],
  "violation_count": 1,
  "message": "❌ SECURITY ISSUE FOUND (HIGH)\n\nYour code has a password..."
}
```

**Response (Expired Subscription):**
```json
{
  "blocked": false,
  "subscription_status": "expired",
  "message": "⚠️ SECURITY SUBSCRIPTION EXPIRED\n\nYour code may have security issues.\nRenew to view detailed security reports.",
  "renewal_link": "https://security-mcp.com/renew"
}
```

---

## 2. `get_compliance_status`

Get current security compliance status of the project.

**Parameters:**
```json
{
  "project_path": "/path/to/project"  // optional, defaults to "."
}
```

**Response:**
```
Subscription: user123
Rules loaded: 650
Detected stack: {
  "languages": ["python@3.11", "javascript@18"],
  "frameworks": ["flask@2.3", "react@18.2"],
  "infrastructure": ["docker", "aws:lambda"],
  "confidence": 0.95
}
```

---

## 3. `acknowledge_fix`

Acknowledge that a security violation has been fixed.

**Parameters:**
```json
{
  "violation_id": "DSV-2026-0001",
  "fix_description": "Moved API key to .env file and loaded via process.env"
}
```

**Response:**
```
✓ Fix acknowledged for DSV-2026-0001
Fix: Moved API key to .env file and loaded via process.env
```

---

## 4. `get_infrastructure_profile`

Detect project infrastructure (languages, frameworks, etc.).

**Parameters:**
```json
{
  "project_path": "/path/to/project"
}
```

**Response:**
```json
{
  "languages": ["javascript", "typescript"],
  "frameworks": ["react", "express"],
  "infrastructure": ["docker"],
  "confidence": 0.85
}
```

---

## 5. `sync_rules`

Sync latest security rules from backend (requires active subscription).

**Parameters:** None (auto-detects stack)

**Response:**
```json
{
  "status": "success",
  "rules_synced": 15,
  "synced_at": "2026-04-29T12:00:00Z"
}
```

---

## Usage Examples

### Cursor IDE Integration

Add to `.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "security-mcp": {
      "command": "python",
      "args": ["/path/to/security-mcp/mcp-server/main.py"],
      "cwd": "/path/to/security-mcp/mcp-server"
    }
  }
}
```

### VS Code Integration

Add to `settings.json`:
```json
{
  "mcp.servers": {
    "security-mcp": {
      "type": "stdio",
      "command": "python",
      "args": ["/path/to/mcp-server/main.py"]
    }
  }
}
```

---

## Subscription States

| State | `enforce_security` Behavior |
|-------|----------------------------|
| **Active** | Full enforcement (block on critical/high/medium) |
| **Grace Period (0-7 days expired)** | Full enforcement with warnings |
| **Expired (7+ days)** | Vague warnings only, can proceed |

---

## Error Handling

All tools return errors in this format:
```json
{
  "error": "Error message describing what went wrong"
}
```

Common errors:
- `No subscription found` - User needs to activate MCP
- `Subscription expired` - User needs to renew
- `Sync failed` - Backend unreachable
