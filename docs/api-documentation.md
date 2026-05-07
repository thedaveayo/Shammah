# Security MCP API Documentation

## Overview

Security MCP (Model Context Protocol) is a security enforcement system that integrates with IDEs to provide real-time security scanning and enforcement as developers write code. The system consists of a backend service that manages security rules and a client-side MCP server that interfaces with IDEs.

## Backend API Endpoints

### Authentication

#### POST /api/auth/subscribe
Subscribe a new user and generate an authentication token.

**Request Body:**
```json
{
  "user_id": "string",
  "email": "string"
}
```

**Response:**
```json
{
  "user_id": "string",
  "status": "active",
  "auth_token": "string",
  "expires_at": "ISO 8601 datetime",
  "days_until_expiry": "integer"
}
```

#### GET /api/auth/status
Check the status of an authentication token.

**Headers:**
- `Authorization: Bearer <token>`

**Response:**
```json
{
  "status": "active|expired|grace_period",
  "days_until_expiry": "integer",
  "expires_at": "ISO 8601 datetime",
  "message": "string (optional)"
}
```

### Rule Management

#### GET /api/stats
Get statistics about the rule database.

**Response:**
```json
{
  "total": "integer",
  "cve": "integer",
  "cwe": "integer",
  "dsv": "integer"
}
```

#### GET /api/public/rules
Get all public rules (no authentication required).

**Response:**
```json
{
  "rules": [
    {
      "rule_id": "string",
      "rule_type": "string",
      "source": "string",
      "severity": "string",
      "title": "string",
      "description": "string",
      "cve_refs": ["string"],
      "cwe_refs": ["string"],
      "affected_package": "string",
      "affected_versions": "string",
      "pattern": {
        "type": "string",
        "value": "string",
        "language": "string"
      },
      "applies_to": {
        "languages": ["string"],
        "frameworks": ["string"],
        "contexts": ["string"]
      },
      "source_link": "string",
      "enforcement": {
        "level": "string",
        "message": "string",
        "required_actions": ["string"]
      },
      "expires_at": "ISO 8601 datetime",
      "metadata": {
        "created_at": "ISO 8601 datetime",
        "updated_at": "ISO 8601 datetime",
        "external_refs": ["string"]
      }
    }
  ]
}
```

#### POST /api/rules/telegram
Ingest a security rule from a Telegram message (no auth required - trusted source).

**Request Body:**
```json
{
  "message_text": "string",
  "message_date": "ISO 8601 datetime"
}
```

**Response:**
```json
{
  "status": "success",
  "rule_id": "string"
}
```

#### POST /api/fetch/cve
Manually trigger CVE fetch (last 90 days).

**Response:**
```json
{
  "status": "success",
  "cves_saved": "integer"
}
```

#### POST /api/fetch/cwe
Manually trigger CWE fetch.

**Response:**
```json
{
  "status": "success",
  "cwe_rules_saved": "integer"
}
```

### Quick-Fix Service

#### POST /api/quick-fix/suggest
Generate specific code fixes for security vulnerabilities.

**Query Parameters:**
- `code`: The vulnerable code snippet
- `vulnerability_description`: Description of the vulnerability
- `language`: Programming language (default: javascript)

**Response:**
```json
{
  "status": "success",
  "fixes": [
    {
      "title": "string",
      "description": "string",
      "before": "string",
      "after": "string",
      "confidence": "high|medium|low",
      "complexity": "simple|moderate|complex"
    }
  ]
}
```

### Advanced Authentication Endpoints

#### POST /api/auth/register
Register a new user.

**Query Parameters:**
- `user_id`: Unique user identifier
- `email`: User email
- `password`: User password

**Response:**
```json
{
  "status": "success",
  "user_id": "string",
  "email": "string"
}
```

#### POST /api/auth/login
Authenticate user and return access token.

**Query Parameters:**
- `user_id`: User identifier
- `password`: User password

**Response:**
```json
{
  "status": "success",
  "access_token": "string",
  "token_type": "string",
  "expires_in": "integer (seconds)"
}
```

#### GET /api/auth/me
Get current authenticated user info.

**Headers:**
- `Authorization: Bearer <token>`

**Response:**
```json
{
  "user_id": "string",
  "permissions": ["string"]
}
```

#### GET /api/auth/permissions
Get current user's permissions.

**Headers:**
- `Authorization: Bearer <token>`

**Response:**
```json
{
  "permissions": ["string"]
}
```

#### POST /api/auth/revoke-token
Revoke the current access token.

**Headers:**
- `Authorization: Bearer <token>`

**Response:**
```json
{
  "status": "success",
  "message": "Token revoked successfully"
}
```

## MCP Server Tools

The MCP server exposes several tools that IDEs can call:

### enforce_security
Validate code against security rules.

**Arguments:**
```json
{
  "code": "string",
  "language": "string (optional)"
}
```

### security_scan_file
Scan a specific file for security vulnerabilities.

**Arguments:**
```json
{
  "file_path": "string",
  "include_details": "boolean (default: false)"
}
```

### security_fix_suggestions
Get specific fix suggestions for security vulnerabilities in code.

**Arguments:**
```json
{
  "code": "string",
  "language": "string",
  "vulnerability_type": "string (optional)"
}
```

### security_context_explain
Explain security context and implications of code in plain English.

**Arguments:**
```json
{
  "code": "string",
  "language": "string",
  "audience": "string (developer|manager|security-expert, default: developer)"
}
```

### security_rule_details
Get detailed information about a specific security rule.

**Arguments:**
```json
{
  "rule_id": "string",
  "include_examples": "boolean (default: false)"
}
```

### get_compliance_status
Get current security compliance status of the project.

**Arguments:**
```json
{
  "project_path": "string"
}
```

### acknowledge_fix
Acknowledge that a security violation has been fixed.

**Arguments:**
```json
{
  "violation_id": "string",
  "fix_description": "string"
}
```

### get_infrastructure_profile
Detect project infrastructure (languages, frameworks, etc.).

**Arguments:**
```json
{
  "project_path": "string"
}
```

### sync_rules
Sync latest security rules from backend (requires active subscription).

**Arguments:**
```json
{}
```

## Error Handling

All API endpoints follow standard HTTP status codes:
- `200`: Success
- `400`: Bad request (invalid input)
- `401`: Unauthorized (invalid/expired token)
- `403`: Forbidden (insufficient permissions)
- `404`: Not found
- `500`: Internal server error

Error responses include a message:
```json
{
  "detail": "Error message"
}
```

## Rate Limits

The API implements rate limiting to prevent abuse. Exceeding limits results in a `429 Too Many Requests` response.

## Security Best Practices

1. Always use HTTPS in production
2. Store API keys securely and never expose them in client-side code
3. Rotate authentication tokens regularly
4. Validate and sanitize all inputs
5. Monitor API usage for suspicious patterns