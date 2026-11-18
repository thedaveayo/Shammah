"""
Shammah MCP Server - entry point

    python main.py              Run as an MCP server over stdio (for coding agents)
    python main.py --bridge     Run the local HTTP bridge for IDE extensions
    python main.py --sync       Sync rules from the backend once and exit
    python main.py --check FILE Scan a file from the command line
"""
import argparse
import logging
import os
import sys

# Make imports work no matter which folder the agent starts us from
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# stdout is reserved for the MCP protocol, so all logs go to stderr
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), stream=sys.stderr,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Shammah security MCP server")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--bridge", action="store_true", help="run the local HTTP bridge for IDE extensions")
    mode.add_argument("--sync", action="store_true", help="sync rules from the backend once and exit")
    mode.add_argument("--check", metavar="FILE", help="scan a file and print the result")
    parser.add_argument("--port", type=int, help="bridge port (default 8765)")
    parser.add_argument("--no-sync", action="store_true", help="don't sync rules from the backend on start")
    args = parser.parse_args(argv)

    from config import AUTO_SYNC_ON_START, BRIDGE_HOST, BRIDGE_PORT
    from database import SessionLocal
    from mcp_server import create_server, prepare_rules
    from tools import handlers

    if args.sync:
        prepare_rules(sync=False)
        db = SessionLocal()
        try:
            text, result = handlers.sync_rules(db)
        finally:
            db.close()
        print(text)
        return 0 if result.get("status") == "success" else 1

    if args.check:
        prepare_rules(sync=False)
        db = SessionLocal()
        try:
            text, result = handlers.security_scan_file(db, args.check)
        finally:
            db.close()
        print(text)
        return 1 if any(v["severity"] in handlers.BLOCKING for v in result.get("violations", [])) else 0

    prepare_rules(sync=AUTO_SYNC_ON_START and not args.no_sync)

    if args.bridge:
        from http_bridge import run
        run(BRIDGE_HOST, args.port or BRIDGE_PORT)
        return 0

    create_server().run("stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())
