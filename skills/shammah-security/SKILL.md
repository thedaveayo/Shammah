---
name: shammah-security
description: Security checklist for writing and reviewing code. Use whenever you write, edit or review code that handles user input, secrets, databases, files, shell commands, authentication, network requests, HTML, or dependencies. Gives plain rules for what to avoid and exactly what to do instead.
---

# Shammah security checklist

Follow these rules whenever you write or change code. Each rule says what to look for, why it matters, and what to do instead. If you find a problem, fix it before you finish, then tell the user what you fixed.

If the Shammah MCP tools are available, use them too: call `security_scan_file` on each file you changed before you finish, and `security_check_dependencies` after adding or upgrading packages. Fix anything marked BLOCKED.

Severity: **Critical** and **High** must be fixed before you finish. **Medium** should be fixed. **Low** is worth mentioning.

## Secrets

1. **Critical. No real keys in code.** Look for strings like `AKIA...`, `ghp_...`, `sk_live_...`, `xoxb-...` or `-----BEGIN PRIVATE KEY-----`. Leaked keys are found and abused within minutes. Do instead: read them from environment variables or a secrets manager, and tell the user to rotate the key.
2. **High. No passwords or tokens written in code.** Look for `password = "..."`, `api_key: "..."`, `secret = "..."` with a real value. Do instead: `os.environ["API_KEY"]` / `process.env.API_KEY`, and add the name to `.env.example` without the value.
3. **High. Never commit `.env` files.** Do instead: add `.env` to `.gitignore`; commit only `.env.example` with empty values.
4. **Medium. Don't log secrets or full tokens.** Do instead: log only the last 4 characters, or nothing.

## Injection

5. **Critical. No SQL built from strings.** Look for f-strings, `+`, `%` or `.format()` inside a query, or template literals like `` `SELECT ... ${id}` ``. Attackers can change the query and read or delete data. Do instead: parameters, e.g. `cursor.execute("... WHERE id = %s", (id,))`, `db.query("... WHERE id = $1", [id])`, or the ORM's query builder.
6. **High. No shell commands built from variables.** Look for `os.system(...)`, `subprocess.run(..., shell=True)`, `exec(`/`execSync(` with a string containing variables. Do instead: pass an argument list, e.g. `subprocess.run(["ls", path])`, `execFile("ls", [path])`.
7. **High. No `eval`, `exec`, `new Function` or string `setTimeout` on data.** They run any text as code. Do instead: `JSON.parse` / `json.loads` for data, `ast.literal_eval` for Python literals, or explicit logic.
8. **High. No user input in file paths without checks.** Look for `open(base + user_path)` or `path.join(dir, req.params.file)`. `../` lets attackers read any file. Do instead: resolve the full path and confirm it stays inside the allowed folder; better, map IDs to file names.
9. **High. No user input in redirects.** Look for `redirect(req.query.next)`. Do instead: only allow relative paths or an allowlist of hosts.
10. **Medium. Validate input at the edge.** Do instead: check type, length and format of every request field (e.g. pydantic, zod) before using it.

## Web output (XSS)

11. **High. Don't put raw HTML into the page.** Look for `innerHTML =`, `outerHTML =`, `insertAdjacentHTML`, `document.write`. Do instead: `textContent`, or sanitize with DOMPurify first.
12. **Medium. Avoid `dangerouslySetInnerHTML` and `v-html`.** Do instead: render text normally; if HTML is required, sanitize it first.
13. **Medium. Don't turn off template escaping.** Look for `|safe`, `Markup(...)`, `{!! !!}`, `mark_safe` on user data. Do instead: keep auto-escaping on.

## Authentication and sessions

14. **Critical. Every endpoint that changes or reads private data checks who is calling.** Do instead: require authentication, then check the user owns or may access the record (not just that they're logged in).
15. **High. Hash passwords with a slow hash.** Never MD5, SHA-1 or plain SHA-256 for passwords. Do instead: bcrypt, scrypt or Argon2.
16. **High. Always verify token signatures.** Look for `verify_signature: False`, `algorithms=["none"]`, or `jwt.decode` without a key. Do instead: verify with the key and pin the algorithm.
17. **High. Compare secrets in constant time.** Look for `if token == expected`. Do instead: `hmac.compare_digest` / `crypto.timingSafeEqual`.
18. **Medium. Secure cookies.** Do instead: set `HttpOnly`, `Secure` and `SameSite=Lax` (or `Strict`) on session cookies.
19. **Medium. Don't store auth tokens in `localStorage`.** Any injected script can read it. Do instead: an `HttpOnly` cookie.
20. **Medium. Rate-limit login, sign-up and password-reset endpoints.**
21. **High. Use a secure random source for tokens.** Look for `Math.random()` or `random.random()` making IDs, tokens or codes. Do instead: `crypto.randomUUID()`, `crypto.randomBytes`, `secrets.token_urlsafe()`.

## Data handling

22. **High. Never unpickle or deserialize untrusted data.** Look for `pickle.load(s)`, `yaml.load` without `SafeLoader`, Java `ObjectInputStream`, PHP `unserialize`. Do instead: JSON, or `yaml.safe_load`.
23. **High. Don't fetch URLs the user controls from the server without checks (SSRF).** Do instead: allowlist hosts and block internal addresses (127.0.0.1, 169.254.169.254, 10.x, 192.168.x).
24. **Medium. Limit upload size and type.** Do instead: check size, extension and content type; store uploads outside the web root with generated names.
25. **Medium. Don't return stack traces or internal errors to users.** Do instead: log the details, return a generic message.

## Configuration

26. **High. Keep TLS certificate checks on.** Look for `verify=False`, `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`. Do instead: remove the override or supply the right CA certificate.
27. **High. No debug mode in production.** Look for `app.run(debug=True)`, `DEBUG = True`. Flask's debugger lets visitors run code. Do instead: read the setting from an environment variable, default off.
28. **Medium. Don't allow every origin with credentials.** Look for CORS `*` together with `allow_credentials=True`. Do instead: list the exact origins.
29. **Medium. Bind development servers to `127.0.0.1`, not `0.0.0.0`,** unless the user asks for network access.
30. **Medium. Set security headers on web apps:** Content-Security-Policy, `X-Content-Type-Options: nosniff`, `frame-ancestors` / `X-Frame-Options`.

## Dependencies

31. **High. Don't add packages with known vulnerabilities.** After adding or upgrading a dependency, check it (`npm audit`, `pip-audit`, or Shammah's `security_check_dependencies`) and upgrade to the fixed version it names.
32. **Medium. Pin versions in a lockfile** (`package-lock.json`, `poetry.lock`, `requirements.txt` with `==`). Commit the lockfile.
33. **Medium. Check package names before installing.** Typos like `reqeusts` or `lodahs` are often malware. Prefer well-known packages.
34. **Low. Remove packages you no longer use.**

## Cryptography

35. **Medium. Don't use MD5 or SHA-1 for anything security-related** (signatures, integrity, tokens). Do instead: SHA-256 or better.
36. **High. Don't write your own encryption.** Do instead: a vetted library (e.g. `cryptography`'s Fernet, libsodium, Web Crypto) with authenticated encryption (AES-GCM, ChaCha20-Poly1305).
37. **Medium. Never reuse or hard-code IVs/nonces.** Do instead: generate a new random one per encryption.

## Before you finish

38. Re-read every changed file against this list.
39. Fix every Critical and High issue; mention any Medium or Low you left and why.
40. Tell the user, in one or two sentences per item, what you fixed and anything they must do themselves (for example, rotating a leaked key).
