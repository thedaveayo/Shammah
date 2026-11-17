# Backend API

Base URL: `http://127.0.0.1:8000` (set with `HOST` and `PORT`). Interactive docs are served at `/docs`.

## Authentication

Read-only routes are public. Routes that change data or call paid APIs (NVD, LLM) need the admin key:

```
Authorization: Bearer <ADMIN_API_KEY>
```

If `ADMIN_API_KEY` is not set on the server, those routes return `503`. A missing key returns `401`, a wrong key returns `403`.

## Public routes

### `GET /health`
```json
{ "status": "healthy" }
```

### `GET /api/stats`
Rule counts by type.
```json
{ "total": 1000, "cve": 120, "cwe": 860, "dsv": 20 }
```

### `GET /api/public/rules`
All rules as a flat JSON object keyed by rule ID.
```json
{
  "_metadata": { "generated_at": "2026-05-02T02:57:07", "total_rules": 1000, "version": "1.0.0" },
  "DSV-2026-0001": {
    "agent_rule": "This code stores a password or secret directly in the app...",
    "relevant_infra": "react",
    "source_link": "https://cwe.mitre.org/data/definitions/798.html",
    "external_refs": ["CWE-798", "https://cwe.mitre.org/data/definitions/798.html"]
  }
}
```

## Admin routes

### `POST /api/fetch/cwe`
Download the CWE catalog and turn it into rules. Takes a while on first run.
```json
{ "status": "success", "cwe_rules_saved": 640 }
```

### `POST /api/fetch/cve`
Fetch recent CVEs from NVD and turn them into rules.
```json
{ "status": "success", "cves_saved": 42 }
```

### `POST /api/rules/telegram`
Turn a curated advisory message into a rule (uses the LLM).

Request:
```json
{
  "message_text": "New auth bypass in Express.js\nseverity: high\nhttps://example.com/article",
  "message_date": "2026-04-29T20:00:00Z"
}
```
Response:
```json
{ "status": "success", "rule_id": "DSV-2026-0042" }
```

### `POST /api/quick-fix/suggest`
Ask the LLM for code fixes. Parameters are sent as query parameters: `code`, `vulnerability_description`, `language` (default `javascript`).
```json
{ "status": "success", "fixes": [ { "title": "Use parameterized queries", "description": "..." } ] }
```

## Errors

Errors use FastAPI's default shape:
```json
{ "detail": "Invalid admin API key" }
```
