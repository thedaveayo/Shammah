# Contributing to Shammah

Thanks for your interest in improving Shammah! Bug reports, rule improvements, docs fixes and code are all welcome.

## Ground rules

- Be kind. Everyone taking part must follow the [Code of Conduct](CODE_OF_CONDUCT.md).
- **Don't report security vulnerabilities in public issues.** Follow [SECURITY.md](SECURITY.md).
- By contributing, you agree that your contributions are licensed under the [AGPL-3.0](LICENSE), the same license as the project.

## Getting set up

```bash
git clone https://github.com/thedaveayo/Shammah.git
cd Shammah
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r backend/requirements.txt -r mcp-server/requirements.txt pytest httpx
```

Copy `backend/.env.example` to `backend/.env` and `mcp-server/.env.example` to `mcp-server/.env`. Never commit `.env` files or real API keys.

## Running tests

The backend and MCP server each have their own test suite. Run them from their folder:

```bash
cd backend && python -m pytest tests
cd mcp-server && python -m pytest tests
```

Some older tests currently fail (see "Known issues" in the README). Please make sure your change doesn't add new failures.

## Making a change

1. Open an issue first for anything bigger than a small fix, so we can agree on the approach.
2. Create a branch from `main`.
3. Keep pull requests focused on one change, and add or update tests where it makes sense.
4. Update the docs if you change behavior, configuration or an API.
5. Open a pull request and fill in the template.

## Adding or improving rules

Rules live in the backend database and are exported to `exports/rules.json`. When proposing a new rule or a fix to an existing one, include:

- the CVE/CWE or other source it comes from,
- a small code sample that should match, and one that should not,
- the severity you suggest, using [docs/severity-guide.md](docs/severity-guide.md).

## Style

- Python: follow PEP 8, use type hints where practical, and keep functions small.
- Keep secrets out of code. Read configuration from environment variables.
