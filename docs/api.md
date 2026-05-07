# Security MCP API Documentation

## Base URL
```
http://localhost:8000/api
```

## Authentication

Most endpoints require an auth token in the `Authorization` header:
```
Authorization: Bearer <your_auth_token>
```

---

## Endpoints

### Subscription Management

#### `POST /auth/subscribe`
Create new subscription

**Request:**
```json
{
  "user_id": "user123",
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "user_id": "user123",
  "status": "active",
  "auth_token": "eyJhbGc...",
  "expires_at": "2026-05-29T00:00:00Z",
  "days_until_expiry": 30
}
```

---

#### `GET /auth/status`
Check subscription status

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "status": "active",
  "days_until_expiry": 25,
  "expires_at": "2026-05-29T00:00:00Z"
}
```

---

#### `POST /auth/renew`
Renew subscription

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "status": "active",
  "auth_token": "new_eyJhbGc...",
  "expires_at": "2026-06-29T00:00:00Z",
  "days_until_expiry": 60
}
```

---

### Rule Management

#### `GET /rules`
List all rules (requires subscription)

**Query Parameters:**
- `rule_type` (optional): Filter by type (cve, cwe, dsv)
- `limit` (optional): Max results (default: 1000)

**Response:**
```json
[
  {
    "rule_id": "DSV-2026-0001",
    "rule_type": "dsv",
    "source": "telegram",
    "severity": "high",
    "title": "Firebase security rules must validate user UID",
    "description": "...",
    "cwe_refs": ["CWE-798"],
    "pattern": {...},
    "applies_to": {...},
    "source_link": "https://t.me/...",
    "enforcement": {
      "level": "block",
      "message": "...",
      "required_actions": ["..."]
    },
    "metadata": {...}
  }
]
```

---

#### `GET /rules/{rule_id}`
Get specific rule by ID

**Response:** Single rule object

---

#### `POST /sync`
Sync rules for MCP (delta sync)

**Request:**
```json
{
  "stack": {
    "languages": ["python", "javascript"],
    "frameworks": ["flask", "react"]
  },
  "last_sync": "2026-04-29T00:00:00Z"
}
```

**Response:**
```json
{
  "subscription_status": "active",
  "new_rules": [...],
  "updated_rules": [...],
  "synced_at": "2026-04-29T12:00:00Z"
}
```

---

#### `POST /rules/telegram`
Ingest Telegram message (no auth required - trusted source)

**Request:**
```json
{
  "message_text": "New Firebase auth bypass found...\nseverity: critical\nhttps://twitter.com/...",
  "message_date": "2026-04-29T00:00:00Z"
}
```

**Response:**
```json
{
  "status": "success",
  "rule_id": "DSV-2026-0002"
}
```

---

### Public Endpoints (No Auth)

#### `GET /public/rules`
Get public export JSON (open-source archive)

**Response:**
```json
{
  "_metadata": {...},
  "CVE-2024-3094": {
    "agent_rule": "...",
    "relevant_infra": "linux",
    "source_link": "https://nvd.nist.gov/..."
  },
  "DSV-2026-0001": {
    "agent_rule": "...",
    "relevant_infra": "firebase, javascript",
    "source_link": "https://t.me/..."
  }
}
```

---

#### `GET /stats`
Get rule statistics

**Response:**
```json
{
  "total": 650,
  "cve": 50,
  "cwe": 600,
  "dsv": 0
}
```

---

### Admin Endpoints

#### `POST /fetch/cve`
Manually trigger CVE fetch

**Response:**
```json
{
  "status": "success",
  "cves_saved": 25
}
```

---

#### `POST /fetch/cwe`
Manually trigger CWE taxonomy fetch (one-time operation)

**Response:**
```json
{
  "status": "success",
  "cwe_rules_saved": 600
}
```
