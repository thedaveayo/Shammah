# Shammah

**Security rules your AI coding agent can follow.** Shammah checks the code your agent writes (and the packages it installs) for security problems, and explains each one in words simple enough for any agent to fix without back-and-forth.

It works with Claude Code, Codex, Cursor, VS Code and any agent that supports MCP (Model Context Protocol), and in GitHub Actions on every push.

> **Status: early stage.** Core features work and are tested; expect rough edges. See [Known issues](#known-issues).

## What's included

| Piece | What it does | Cost |
|---|---|---|
| [Skill](skills/) | A 40-rule security checklist any agent can follow | Free |
| [MCP server](mcp-server/) | Agents call it to check code and dependencies while they work; 21 tested starter rules | Free, open source |
| `shammah init` | Connects the MCP server to your agents, writes their instructions and installs a check-every-edit hook | Free |
| [GitHub Action](action.yml) | Scans on every push, pull request or schedule; results in the job summary and GitHub code scanning | Free |
| Shammah Pro | The full, always-updated rule feed, plus a dashboard with scan history | Paid |

```
CVE / CWE / OSV data ─► Shammah Pro rule feed ──rules only──► MCP server, hook, GitHub Action
                                                                    │
                                                    your code stays on your machine / your CI
```

## Quick start

Requires Python 3.10+ and Git.

```bash
git clone https://github.com/thedaveayo/Shammah.git
cd Shammah/mcp-server
pip install -r requirements.txt
python main.py init /path/to/your/project
```

`init` sets up Claude Code, Cursor, Codex and VS Code for that project:

- registers the MCP server (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`; for Codex it prints the `~/.codex/config.toml` lines, or add `--codex-global`),
- adds a short instruction block to `CLAUDE.md`, `AGENTS.md` and `.cursor/rules/shammah.mdc` telling the agent when to call Shammah,
- installs a Claude Code hook that scans every file the agent edits and hands problems back to it.

It merges with what's already there and is safe to run again. Use `--dry-run` to preview, `--agent claude` to pick agents. Restart your agent afterwards.

### Scan from the command line

```bash
python main.py scan /path/to/project            # code + dependencies, cached between runs
python main.py check src/app.py                  # one file
python main.py scan . --format sarif -o shammah.sarif --fail-on high
```

Exit code 1 means something at or above `--fail-on` (default `high`) was found.

### Scan on every push (GitHub Action)

Copy [`examples/shammah-workflow.yml`](examples/shammah-workflow.yml) to `.github/workflows/shammah.yml`:

```yaml
- uses: actions/checkout@v4
- uses: thedaveayo/Shammah@main
  with:
    fail-on: high
    upload-sarif: "true"
```

It runs on push, on pull requests and daily; unchanged files are skipped thanks to a cache.

## What it checks

- **Code:** leaked keys and passwords, SQL and shell commands built from strings, `eval`, XSS, unsafe deserialization, disabled TLS checks, debug mode, unverified JWTs, weak hashes. Every rule ships with examples it must flag and must not flag (`python main.py test-rules`).
- **Dependencies:** checked against [OSV.dev](https://osv.dev) (GitHub advisories, PyPA, RustSec, Go and more, with CVE IDs). Each vulnerable package gets one finding with the version that fixes everything. Only package names and versions leave your machine. Supported files:

  | Ecosystem | Files |
  |---|---|
  | JavaScript | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml` |
  | Python | `requirements*.txt` (exact `==` pins), `Pipfile.lock`, `poetry.lock`, `uv.lock` |
  | PHP | `composer.lock` |
  | .NET | `packages.lock.json`, `*.csproj` / `*.fsproj` / `*.vbproj`, `Directory.Packages.props` |
  | Java | `gradle.lockfile`, `pom.xml` |
  | Rust, Ruby, Go | `Cargo.lock`, `Gemfile.lock`, `go.mod` |

  Lockfiles list every installed package. `pom.xml` and .NET project files only list direct dependencies, so the scan adds a note saying packages pulled in by those weren't checked. For a full check, turn on [Gradle dependency locking](https://docs.gradle.org/current/userguide/dependency_locking.html) or NuGet lock files (`RestorePackagesWithLockFile`).

Findings carry the rule's CWE/CVE references. Critical, high and medium findings block; low ones warn.

## Per-project settings

`.shammah/config.json` in your project:

```json
{ "muted_rules": ["SHAMMAH-0018"], "exclude": ["tests/**", "*.min.js"], "fail_on": "high" }
```

`python main.py mute RULE_ID` adds to `muted_rules`. Agents can also call `report_false_positive`, which mutes the rule and (with Shammah Pro) reports it so the rule gets fixed.

## Shammah Pro

Set two environment variables and the MCP server, hook and Action use the full rule feed instead of the starter rules:

```bash
SHAMMAH_API_KEY=shm_live_...
SHAMMAH_FEED_URL=https://your-shammah-pro-host
```

With `--report` (or `report: "true"` in the Action), a scan summary is sent to your dashboard: counts, rule IDs, repository and commit. Never code.

## Self-hosting the rule builder

[`backend/`](backend/) fetches CVE and CWE data and uses an LLM to draft more rules, served to MCP servers through `/api/sync`. See [docs/deployment.md](docs/deployment.md).

## Documentation

- [MCP tools and command line](docs/mcp-tools.md)
- [User guide](docs/user-guide-tutorial.md)
- [Backend API](docs/api.md)
- [Severity guide](docs/severity-guide.md)
- [Deployment](docs/deployment.md)

## Known issues

- Code matching is pattern-based (regular expressions): expect some false positives and misses. Report both with the "Rule request or false positive" issue template.
- `poetry.lock`, `uv.lock` and `Cargo.lock` need Python 3.11+. Maven versions inherited from a parent POM or BOM aren't resolved.
- The VS Code extension and JetBrains plugin aren't on their marketplaces yet; build them from source. The JetBrains plugin has no settings page (set `SHAMMAH_BRIDGE_URL`).
- Some older tests in `backend/tests` and `mcp-server/tests` fail because their mocks no longer match the code; CI skips them by name.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and our [Code of Conduct](CODE_OF_CONDUCT.md). To report a security vulnerability, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## License

Shammah is licensed under the [GNU Affero General Public License v3.0](LICENSE). If you run a modified version as a network service, you must offer its source code to the users of that service.

Rule data is derived from MITRE CWE, the NIST National Vulnerability Database and OSV.dev. See [NOTICE](NOTICE) for attributions.
