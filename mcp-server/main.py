"""
Shammah - entry point

    python main.py                      MCP server over stdio (what coding agents run)
    python main.py bridge               Local HTTP bridge for IDE extensions
    python main.py scan [PATH]          Scan a project (code + dependencies); for CI and humans
    python main.py check FILE           Scan one file
    python main.py init [PATH]          Connect Shammah to your coding agents in one step
    python main.py hook                 Agent hook: scan the file the agent just edited
    python main.py sync                 Pull new rules (backend and/or Shammah Pro feed)
    python main.py mute RULE_ID         Turn a rule off for a project
    python main.py test-rules [FILE]    Check rules against their good/bad examples

The older flags --bridge, --check FILE and --sync still work.
"""
import argparse
import json
import logging
import os
import sys

# Make imports work no matter which folder the agent starts us from
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# stdout is reserved for the MCP protocol, so all logs go to stderr
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), stream=sys.stderr,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")

VERSION = "0.3.0"
SEVERITIES = ["critical", "high", "medium", "low"]


def _db():
    from database import SessionLocal
    return SessionLocal()


def cmd_serve(args) -> int:
    from bootstrap import prepare_rules
    from config import AUTO_SYNC_ON_START
    from mcp_server import create_server
    prepare_rules(sync=AUTO_SYNC_ON_START and not args.no_sync)
    create_server().run("stdio")
    return 0


def cmd_bridge(args) -> int:
    from bootstrap import prepare_rules
    from config import AUTO_SYNC_ON_START, BRIDGE_HOST, BRIDGE_PORT
    from http_bridge import run
    prepare_rules(sync=AUTO_SYNC_ON_START and not args.no_sync)
    run(BRIDGE_HOST, args.port or BRIDGE_PORT)
    return 0


def cmd_sync(args) -> int:
    from bootstrap import prepare_rules
    from tools import handlers
    prepare_rules(sync=False)
    db = _db()
    try:
        text, result = handlers.sync_rules(db, full=getattr(args, "full", False))
    finally:
        db.close()
    print(text)
    return 0 if result.get("status") == "success" else 1


def cmd_check(args) -> int:
    from bootstrap import prepare_rules
    from tools import handlers
    prepare_rules(sync=False)
    db = _db()
    try:
        text, result = handlers.security_scan_file(db, args.file)
    finally:
        db.close()
    print(text)
    if "error" in result:
        return 2
    return 1 if any(v["severity"] in handlers.BLOCKING for v in result.get("violations", [])) else 0


def _step_summary(result) -> str:
    c = result["counts"]
    lines = ["## Shammah security scan", "",
             f"Scanned {result['files_scanned'] + result['files_from_cache']} files and "
             f"{result['dependencies']['packages']} dependencies.", "",
             "| Critical | High | Medium | Low |", "| --- | --- | --- | --- |",
             f"| {c['critical']} | {c['high']} | {c['medium']} | {c['low']} |", ""]
    if result["violations"]:
        lines += ["| Severity | Issue | Where | Fix |", "| --- | --- | --- | --- |"]
        for f in result["violations"][:50]:
            fix = "; ".join(f["required_actions"]).replace("|", "\\|")
            lines.append(f"| {f['severity']} | {f['title'].replace('|', '/')} ({f['rule_id']}) | "
                         f"`{f['file_path']}:{f['line']}` | {fix} |")
        if len(result["violations"]) > 50:
            lines.append(f"\n...and {len(result['violations']) - 50} more.")
    if result["dependencies"].get("error"):
        lines += ["", result["dependencies"]["error"]]
    return "\n".join(lines) + "\n"


def cmd_scan(args) -> int:
    from bootstrap import prepare_rules
    from services.feed_client import FeedClient, scan_summary
    from services.project_config import load_config
    from services.project_scan import blocking_count, format_text, scan_project
    from services.sarif import to_sarif

    project = os.path.abspath(args.path)
    if not os.path.isdir(project):
        print(f"Folder does not exist: {project}", file=sys.stderr)
        return 2
    prepare_rules(sync=args.sync, background=False)
    db = _db()
    try:
        result = scan_project(db, project, max_files=args.max_files, use_cache=not args.no_cache,
                              include_dependencies=not args.no_deps)
    finally:
        db.close()

    if args.format == "json":
        out = json.dumps(result, indent=2)
    elif args.format == "sarif":
        out = json.dumps(to_sarif(result["violations"], VERSION), indent=2)
    else:
        out = format_text(result, limit=args.limit)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        print(format_text(result, limit=args.limit) if args.format != "text" else out)
    else:
        print(out)

    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_path:
        try:
            with open(summary_path, "a", encoding="utf-8") as fh:
                fh.write(_step_summary(result))
        except OSError:
            pass

    if args.report:
        sent = FeedClient().report_scan(scan_summary(
            result,
            repository=os.getenv("GITHUB_REPOSITORY", os.path.basename(project)),
            commit=os.getenv("GITHUB_SHA", ""),
            branch=os.getenv("GITHUB_REF_NAME", ""),
            trigger=os.getenv("GITHUB_EVENT_NAME", "manual"),
        ))
        if sent["status"] == "error":
            print(sent["message"], file=sys.stderr)

    fail_on = args.fail_on or load_config(project).get("fail_on") or "high"
    if fail_on == "none":
        return 0
    return 1 if blocking_count(result, fail_on) else 0


def cmd_hook(args) -> int:
    """
    Agent hook. Claude Code sends JSON on stdin after each Edit/Write; exit code 2
    with a message on stderr hands the findings back to the agent to fix.
    """
    # The agent reads stderr; keep it to the findings only
    logging.getLogger().setLevel(logging.WARNING)
    from bootstrap import prepare_rules
    from tools import handlers

    path = args.file
    if not path:
        try:
            payload = json.load(sys.stdin)
        except ValueError:
            return 0
        tool_input = payload.get("tool_input") or {}
        path = tool_input.get("file_path") or tool_input.get("path")
    if not path or not os.path.isfile(path):
        return 0

    prepare_rules(sync=False)
    db = _db()
    try:
        text, result = handlers.security_scan_file(db, path)
    finally:
        db.close()
    blocking = [v for v in result.get("violations", []) if v["severity"] in handlers.BLOCKING]
    if not blocking:
        return 0
    print("Shammah found security issues in the file you just edited. Fix them before continuing.\n\n" + text,
          file=sys.stderr)
    return 2


def cmd_init(args) -> int:
    from shammah_init import run_init
    return run_init(project=os.path.abspath(args.path), agents=args.agent, dry_run=args.dry_run,
                    with_hook=not args.no_hook, codex_global=args.codex_global)


def cmd_mute(args) -> int:
    from services.project_config import mute_rule
    muted = mute_rule(os.path.abspath(args.project), args.rule_id, unmute=args.unmute)
    print(f"{'Unmuted' if args.unmute else 'Muted'} {args.rule_id}. Muted rules: {', '.join(muted) or 'none'}")
    return 0


def cmd_test_rules(args) -> int:
    from config import STARTER_RULES_PATH
    from services.rule_quality import check_rules
    path = args.file or str(STARTER_RULES_PATH)
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    rules = data.get("rules", data) if isinstance(data, dict) else data
    report = check_rules(rules, require_examples=not args.allow_missing_examples)
    for rid, problems in report["failed"].items():
        for p in problems:
            print("FAIL", p)
    print(f"{len(report['passed'])} rule(s) passed, {len(report['failed'])} failed.")
    return 1 if report["failed"] else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="shammah", description="Shammah: security checks for AI coding agents")
    parser.add_argument("--version", action="version", version=f"shammah {VERSION}")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("serve", help="MCP server over stdio (default)")
    p.add_argument("--no-sync", action="store_true", help="don't pull new rules on start")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("bridge", help="local HTTP bridge for IDE extensions")
    p.add_argument("--port", type=int)
    p.add_argument("--no-sync", action="store_true")
    p.set_defaults(func=cmd_bridge)

    p = sub.add_parser("scan", help="scan a project: code and dependencies")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    p.add_argument("--output", "-o", help="write the formatted result to this file")
    p.add_argument("--fail-on", choices=SEVERITIES + ["none"],
                   help="exit 1 if anything this severe or worse is found (default: config, else high)")
    p.add_argument("--no-deps", action="store_true", help="skip the dependency check")
    p.add_argument("--no-cache", action="store_true", help="ignore and don't write .shammah/cache.json")
    p.add_argument("--sync", action="store_true", help="pull new rules before scanning")
    p.add_argument("--report", action="store_true", help="send a summary (no code) to Shammah Pro")
    p.add_argument("--max-files", type=int, default=5000)
    p.add_argument("--limit", type=int, default=25, help="issues to list in text output")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("check", help="scan one file")
    p.add_argument("file")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("init", help="connect Shammah to your coding agents")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--agent", action="append", choices=["claude", "cursor", "codex", "vscode", "all"],
                   help="agent(s) to set up (default: all)")
    p.add_argument("--no-hook", action="store_true", help="don't install the Claude Code hook")
    p.add_argument("--codex-global", action="store_true",
                   help="also add Shammah to ~/.codex/config.toml (Codex reads MCP servers from there)")
    p.add_argument("--dry-run", action="store_true", help="show what would change without writing")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("hook", help="agent hook: scan the file the agent just edited")
    p.add_argument("--file", help="file to scan (default: read the agent's JSON from stdin)")
    p.set_defaults(func=cmd_hook)

    p = sub.add_parser("sync", help="pull new rules")
    p.add_argument("--full", action="store_true", help="download every rule again")
    p.set_defaults(func=cmd_sync)

    p = sub.add_parser("mute", help="turn a rule off (or on) for a project")
    p.add_argument("rule_id")
    p.add_argument("--project", default=".")
    p.add_argument("--unmute", action="store_true")
    p.set_defaults(func=cmd_mute)

    p = sub.add_parser("test-rules", help="check rules against their good/bad examples")
    p.add_argument("file", nargs="?", help="rules JSON (default: the starter rules)")
    p.add_argument("--allow-missing-examples", action="store_true")
    p.set_defaults(func=cmd_test_rules)
    return parser


def _legacy(argv):
    """Map the older flags (--bridge, --check FILE, --sync, --no-sync, --port) onto subcommands"""
    argv = list(argv)
    if "--check" in argv:
        i = argv.index("--check")
        return ["check", argv[i + 1]] if i + 1 < len(argv) else ["check"]
    if "--sync" in argv and (not argv or argv[0].startswith("-")):
        return ["sync"]
    if "--bridge" in argv:
        rest = [a for a in argv if a != "--bridge"]
        return ["bridge"] + rest
    if not argv or argv[0].startswith("-") and argv[0] not in ("-h", "--help", "--version"):
        return ["serve"] + argv
    return argv


def main(argv=None) -> int:
    argv = _legacy(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(argv)
    if not getattr(args, "func", None):
        args = build_parser().parse_args(["serve"])
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
