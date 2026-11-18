# Shammah skill

[`shammah-security/SKILL.md`](shammah-security/SKILL.md) is a 40-rule security checklist written so any coding agent can follow it without security expertise. It's free and works without the Shammah MCP server; with the server installed, it also tells the agent when to call it.

## Install

**Claude Code** (personal, all projects)
```bash
mkdir -p ~/.claude/skills
cp -r skills/shammah-security ~/.claude/skills/
```
or per project: copy it to `.claude/skills/shammah-security/` in your repository.

**Claude apps:** zip the `shammah-security` folder and upload it under Settings → Capabilities → Skills.

**Codex, Cursor and other agents:** paste the content of `SKILL.md` (without the `---` header) into `AGENTS.md` or `.cursor/rules/shammah.mdc`.

## Keep it short

The checklist covers the mistakes agents make most often. The full, always-updated rule set (and automatic checks on every push) is what the Shammah MCP server and Shammah Pro add.
