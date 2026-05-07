# Severity Determination Guidelines

## Automatic Severity Assignment (LLM)

For DSV rules from Telegram articles, the LLM determines severity based on:

### CRITICAL
- Remote code execution (RCE)
- Authentication bypass
- Data exfiltration vulnerabilities
- Full system compromise

**Examples:**
- "Firebase rules allow any user to read all database"
- "Express middleware allows arbitrary code execution"
- "API endpoint returns all user passwords in plaintext"

---

### HIGH
- Privilege escalation
- Sensitive data exposure (PII, credentials)
- SQL injection with data access
- Cross-site scripting (XSS) with session hijacking

**Examples:**
- "User can escalate to admin role via API manipulation"
- "Debug endpoint exposes environment variables with API keys"
- "GraphQL introspection reveals sensitive schema"

---

### MEDIUM
- Denial of Service (DoS)
- Limited impact bugs
- Information disclosure (non-sensitive)
- Security misconfigurations

**Examples:**
- "Rate limiting missing on login endpoint"
- "Error messages reveal stack traces"
- "CORS allows any origin"

---

### LOW
- Minor information disclosure
- Best practice violations
- Code quality issues with security implications

**Examples:**
- "Variable name 'password' could be more descriptive"
- "Missing security headers (X-Frame-Options)"
- "Console.log in production code"

---

## User Override

Include severity in Telegram message to override LLM:

```
New Firebase auth bypass found in production apps.
severity: critical
https://twitter.com/hacker/status/12345
```

---

## Enforcement Levels

| Severity | MCP Action |
|----------|------------|
| CRITICAL | Block |
| HIGH | Block |
| MEDIUM | Block |
| LOW | Warn |

---

## Examples by Category

### Authentication/Authorization

| Issue | Severity |
|-------|----------|
| Auth bypass | CRITICAL |
| Privilege escalation | HIGH |
| Session fixation | HIGH |
| Missing rate limiting | MEDIUM |
| Weak password requirements | LOW |

### Data Protection

| Issue | Severity |
|-------|----------|
| Plaintext passwords | CRITICAL |
| PII exposure | HIGH |
| Missing encryption at rest | HIGH |
| Verbose error messages | MEDIUM |
| Missing security headers | LOW |

### Code Execution

| Issue | Severity |
|-------|----------|
| Remote code execution | CRITICAL |
| Command injection | CRITICAL |
| SQL injection | HIGH |
| Path traversal | HIGH |
| SSRF | HIGH |

### Configuration

| Issue | Severity |
|-------|----------|
| Exposed admin panel | HIGH |
| Open S3 bucket | HIGH |
| Debug mode in production | MEDIUM |
| Missing CSP | MEDIUM |
| Outdated dependencies | LOW |
