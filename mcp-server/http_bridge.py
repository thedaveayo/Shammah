"""
Local HTTP bridge for IDE extensions.

IDE extensions can't easily speak MCP, so this exposes the same tools over a
tiny JSON API on 127.0.0.1:

    POST /api/tools/call   {"name": "enforce_security", "arguments": {...}}
    GET  /health

Run it with:  python main.py --bridge

It only accepts requests from this computer: requests from browsers (which send
an Origin header) or for other host names are refused.
"""
import inspect
import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional, Tuple

from config import BRIDGE_HOST, BRIDGE_PORT
from database import SessionLocal
from models.rule import LocalRule
from tools import handlers

logger = logging.getLogger(__name__)

MAX_BODY_BYTES = 5 * 1024 * 1024
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "[::1]", "::1"}


def call_tool(name: str, arguments: dict) -> Tuple[int, dict]:
    """Run a tool and return (HTTP status, JSON body)"""
    handler = handlers.HANDLERS.get(name)
    if handler is None:
        return 404, {"error": f"Unknown tool: {name}", "tools": sorted(handlers.HANDLERS)}
    if not isinstance(arguments, dict):
        return 400, {"error": "arguments must be an object"}

    params = inspect.signature(handler).parameters
    accepted = {k: v for k, v in arguments.items() if k in params and k != "db"}
    missing = [p.name for p in params.values()
               if p.name != "db" and p.default is inspect.Parameter.empty and p.name not in accepted]
    if missing:
        return 400, {"error": f"Missing argument(s): {', '.join(missing)}"}

    db = SessionLocal()
    try:
        text, data = handler(db, **accepted)
    finally:
        db.close()
    return 200, {"result": text, **data}


class BridgeHandler(BaseHTTPRequestHandler):
    server_version = "ShammahBridge/0.2"

    def log_message(self, fmt, *args):  # route access logs through logging (stderr)
        logger.info("%s - %s", self.address_string(), fmt % args)

    def _send(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def _check_local(self) -> Optional[str]:
        if self.headers.get("Origin"):
            return "Requests from web pages are not allowed"
        host = (self.headers.get("Host") or "").strip().lower()
        hostname = host.rsplit(":", 1)[0] if not host.startswith("[") else host.split("]")[0] + "]"
        if hostname not in ALLOWED_HOSTS:
            return "Only requests to localhost are allowed"
        return None

    def do_GET(self):
        problem = self._check_local()
        if problem:
            return self._send(403, {"error": problem})
        if self.path.rstrip("/") == "/health":
            db = SessionLocal()
            try:
                count = db.query(LocalRule).count()
            finally:
                db.close()
            return self._send(200, {"status": "ok", "rules_loaded": count, "tools": sorted(handlers.HANDLERS)})
        return self._send(404, {"error": "Not found"})

    def do_POST(self):
        problem = self._check_local()
        if problem:
            return self._send(403, {"error": problem})
        if self.path.rstrip("/") != "/api/tools/call":
            return self._send(404, {"error": "Not found"})
        if not (self.headers.get("Content-Type") or "").lower().startswith("application/json"):
            return self._send(415, {"error": "Content-Type must be application/json"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._send(400, {"error": "Invalid Content-Length"})
        if length <= 0 or length > MAX_BODY_BYTES:
            return self._send(413, {"error": "Request body missing or too large"})
        try:
            body = json.loads(self.rfile.read(length))
        except ValueError:
            return self._send(400, {"error": "Body must be JSON"})
        if not isinstance(body, dict) or not isinstance(body.get("name"), str):
            return self._send(400, {"error": 'Body must look like {"name": "...", "arguments": {...}}'})
        try:
            status, result = call_tool(body["name"], body.get("arguments") or {})
        except Exception:
            logger.exception("Tool %s failed", body.get("name"))
            status, result = 500, {"error": "Tool failed; see the bridge logs"}
        return self._send(status, result)


def make_server(host: str = BRIDGE_HOST, port: int = BRIDGE_PORT) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), BridgeHandler)


def run(host: str = BRIDGE_HOST, port: int = BRIDGE_PORT) -> None:
    httpd = make_server(host, port)
    logger.info("Shammah bridge listening on http://%s:%d", host, port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
