"""
`python main.py init [PROJECT]` connects Shammah to coding agents in one step.

For each agent it:
  1. registers the Shammah MCP server in the agent's project config,
  2. writes a short instruction block telling the agent when to call it,
  3. (Claude Code) installs a hook that scans every file the agent edits.

Existing files are merged, never overwritten: other MCP servers, hooks and
instructions are kept, and running init again updates Shammah's parts in place.
"""
import json
import os
import shlex
import sys
from typing import Dict, List, Optional, Tuple

MAIN_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.py")
START, END = "<!-- shammah:start -->", "<!-- shammah:end -->"
ALL_AGENTS = ["claude", "cursor", "codex", "vscode"]

INSTRUCTIONS = """## Security checks (Shammah)

- Before finishing any task that changed code, call the Shammah `security_scan_file` tool on each file you changed.
- If a result says BLOCKED, fix every listed issue, then scan again until it passes.
- After adding or upgrading dependencies, call `security_check_dependencies` and upgrade anything it flags.
- Tell the user which security issues you fixed.
- If a finding is clearly wrong, explain why. Only with the user's agreement, call `report_false_positive`."""


def _command() -> Tuple[str, List[str]]:
    return sys.executable, [MAIN_PY]


def _hook_command() -> str:
    exe, args = _command()
    if os.name == "nt":
        return f'"{exe}" "{args[0]}" hook'
    return f"{shlex.quote(exe)} {shlex.quote(args[0])} hook"


class Changes:
    def __init__(self, project: str, dry_run: bool):
        self.project, self.dry_run = project, dry_run
        self.done: List[str] = []
        self.problems: List[str] = []

    def rel(self, path: str) -> str:
        return os.path.relpath(path, self.project)

    def write(self, path: str, text: str, what: str) -> None:
        old = None
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                old = fh.read()
        if old == text:
            self.done.append(f"unchanged  {self.rel(path)} ({what})")
            return
        self.done.append(f"{'would write' if self.dry_run else ('updated' if old is not None else 'created')}  "
                         f"{self.rel(path)} ({what})")
        if not self.dry_run:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)


def _load_json(changes: Changes, path: str) -> Optional[Dict]:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return data
    except ValueError:
        pass
    changes.problems.append(f"skipped {changes.rel(path)}: it isn't valid JSON, so it was left untouched")
    return None


def _merge_server(changes: Changes, path: str, key: str, entry: Dict) -> None:
    data = _load_json(changes, path)
    if data is None:
        return
    servers = data.setdefault(key, {})
    servers["shammah"] = entry
    changes.write(path, json.dumps(data, indent=2) + "\n", "MCP server")


def _upsert_block(changes: Changes, path: str, block: str, what: str, header: str = "") -> None:
    text = ""
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    wrapped = f"{START}\n{block}\n{END}"
    if START in text and END in text:
        new = text[:text.index(START)] + wrapped + text[text.index(END) + len(END):]
    elif text:
        new = text.rstrip("\n") + "\n\n" + wrapped + "\n"
    else:
        new = header + wrapped + "\n"
    changes.write(path, new, what)


def setup_claude(changes: Changes, with_hook: bool) -> None:
    exe, args = _command()
    _merge_server(changes, os.path.join(changes.project, ".mcp.json"), "mcpServers",
                  {"command": exe, "args": args})
    _upsert_block(changes, os.path.join(changes.project, "CLAUDE.md"), INSTRUCTIONS, "instructions")
    if not with_hook:
        return
    path = os.path.join(changes.project, ".claude", "settings.json")
    data = _load_json(changes, path)
    if data is None:
        return
    hooks = data.setdefault("hooks", {})
    post = hooks.setdefault("PostToolUse", [])
    command = _hook_command()
    # drop any earlier Shammah hook, then add the current one
    def is_ours(cmd: str) -> bool:
        cmd = cmd or ""
        return MAIN_PY in cmd or ("main.py" in cmd and cmd.rstrip().endswith(" hook") and "shammah" in cmd.lower())

    for group in post:
        group["hooks"] = [h for h in group.get("hooks", []) if not is_ours(h.get("command", ""))]
    post[:] = [g for g in post if g.get("hooks")]
    post.append({"matcher": "Edit|Write|MultiEdit", "hooks": [{"type": "command", "command": command, "timeout": 60}]})
    changes.write(path, json.dumps(data, indent=2) + "\n", "hook: scan each edited file")


def setup_cursor(changes: Changes) -> None:
    exe, args = _command()
    _merge_server(changes, os.path.join(changes.project, ".cursor", "mcp.json"), "mcpServers",
                  {"command": exe, "args": args})
    rule = ("---\ndescription: Check code for security issues with Shammah\nalwaysApply: true\n---\n\n"
            + INSTRUCTIONS + "\n")
    changes.write(os.path.join(changes.project, ".cursor", "rules", "shammah.mdc"), rule, "instructions")


def setup_vscode(changes: Changes) -> None:
    exe, args = _command()
    _merge_server(changes, os.path.join(changes.project, ".vscode", "mcp.json"), "servers",
                  {"type": "stdio", "command": exe, "args": args})


def codex_toml() -> str:
    exe, args = _command()
    return (f"[mcp_servers.shammah]\ncommand = {json.dumps(exe)}\nargs = {json.dumps(args)}\n")


def setup_codex(changes: Changes, write_global: bool) -> None:
    _upsert_block(changes, os.path.join(changes.project, "AGENTS.md"), INSTRUCTIONS, "instructions")
    if not write_global:
        changes.done.append("note       Codex reads MCP servers from ~/.codex/config.toml. Add this, "
                            "or rerun with --codex-global:\n\n" + codex_toml())
        return
    path = os.path.join(os.path.expanduser("~"), ".codex", "config.toml")
    text = ""
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    if "[mcp_servers.shammah]" in text:
        changes.done.append(f"unchanged  {path} (Shammah already registered)")
        return
    new = (text.rstrip("\n") + "\n\n" if text else "") + codex_toml()
    changes.done.append(f"{'would update' if changes.dry_run else 'updated'}  {path} (MCP server)")
    if not changes.dry_run:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(new)


def setup_project(changes: Changes) -> None:
    from services.project_config import DEFAULT_CONFIG
    config_path = os.path.join(changes.project, ".shammah", "config.json")
    if not os.path.exists(config_path):
        changes.write(config_path, json.dumps(DEFAULT_CONFIG, indent=2) + "\n", "project settings")
    changes.write(os.path.join(changes.project, ".shammah", ".gitignore"),
                  "# Scan cache: safe to delete, don't commit\ncache.json\n", "ignore the scan cache")


def run_init(project: str, agents: Optional[List[str]] = None, dry_run: bool = False,
             with_hook: bool = True, codex_global: bool = False) -> int:
    if not os.path.isdir(project):
        print(f"Folder does not exist: {project}")
        return 2
    selected = ALL_AGENTS if not agents or "all" in agents else [a for a in ALL_AGENTS if a in agents]
    changes = Changes(project, dry_run)
    setup_project(changes)
    if "claude" in selected:
        setup_claude(changes, with_hook)
    if "cursor" in selected:
        setup_cursor(changes)
    if "codex" in selected:
        setup_codex(changes, codex_global)
    if "vscode" in selected:
        setup_vscode(changes)

    print(f"Shammah {'dry run for' if dry_run else 'set up in'} {project}\n")
    for line in changes.done:
        print("  " + line)
    for line in changes.problems:
        print("  WARNING " + line)
    print("\nThe agent configs point at this Python and this copy of Shammah:\n"
          f"  {sys.executable}\n  {MAIN_PY}\n"
          "They're specific to this computer; teammates should run init themselves.\n"
          "Restart your agent so it picks up the new MCP server.")
    return 1 if changes.problems else 0
