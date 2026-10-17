"""HTTP server: static frontend + JSON endpoints + SSE diff stream."""
from __future__ import annotations

import http.server
import json
import mimetypes
import os
import queue
import threading
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from .dates import day_range, timezone_names

from .db import (
    overview_totals, expensive_prompts, project_summary,
    tool_token_breakdown, recent_sessions, session_turns,
    daily_token_breakdown, model_breakdown, skill_breakdown, get_timezone, set_timezone,
)
from .pricing import load_pricing, cost_for, get_plan, set_plan
from .tips import all_tips, dismiss_tip
from .scanner import scan_dir
from .skills import cached_catalog
from . import vendor


WEB_ROOT = Path(__file__).resolve().parent.parent / "web"
PRICING_JSON = Path(__file__).resolve().parent.parent / "pricing.json"

EVENTS: "queue.Queue[dict]" = queue.Queue()

MAX_POST_BYTES = 1_000_000  # 1 MB — we only accept tiny JSON bodies (plan, tip key)
MAX_LIMIT = 1000

LOOPBACK_HOSTNAMES = frozenset({"127.0.0.1", "localhost", "::1"})
WILDCARD_BINDS = frozenset({"0.0.0.0", "::", "*", ""})


def _send_json(handler, obj, status: int = 200) -> None:
    body = json.dumps(obj, default=str).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def _send_error(handler, status: int, msg: str) -> None:
    _send_json(handler, {"error": msg}, status=status)


def _clamp_limit(raw, default: int) -> int:
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return default
    return max(1, min(v, MAX_LIMIT))


def _hostname(authority: str) -> str:
    """Hostname from a Host or Origin authority, minus port and IPv6 brackets."""
    h = (authority or "").strip().lower()
    if h.startswith("["):
        return h[1:].split("]", 1)[0]
    if h.count(":") == 1:  # host:port (a bare IPv6 literal has 2+ colons)
        return h.split(":", 1)[0]
    return h


def allowed_hostnames(bind_host: str = "127.0.0.1") -> frozenset:
    """Hostnames a browser may legitimately use to reach this dashboard.

    Any other Host header means the request arrived under a name that resolves
    to this machine but that we never advertised. That is the signature of DNS
    rebinding, the technique a web page uses to defeat same-origin policy and
    read a loopback API. Since every /api/* response carries prompt text, file
    paths, or project names, an unrecognized Host is refused before routing.

    Ports are deliberately not pinned. Rebinding needs an attacker-controlled
    hostname, so a port match adds nothing, and requiring one would break SSH
    forwarding (localhost:9999 to 8080).

    Set TOKEN_DASHBOARD_ALLOWED_HOSTS (comma-separated) to reach the dashboard
    under another name, for example a LAN IP when you have deliberately bound
    0.0.0.0. Read once at startup.
    """
    hosts = set(LOOPBACK_HOSTNAMES)
    bind = _hostname(bind_host)
    if bind not in WILDCARD_BINDS:
        hosts.add(bind)
    for extra in (os.environ.get("TOKEN_DASHBOARD_ALLOWED_HOSTS") or "").split(","):
        name = _hostname(extra)
        if name:
            hosts.add(name)
    return frozenset(hosts)


def _within(child: Path, parent: Path) -> bool:
    """True if `child` is `parent` or sits underneath it.

    A `str.startswith` prefix test would also accept a sibling whose name
    merely starts with the parent's (web/ vs web-assets/), so compare path
    components instead.
    """
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _serve_static(handler, rel: str) -> None:
    rel = rel.lstrip("/")
    root = WEB_ROOT.resolve()
    p = (WEB_ROOT / rel).resolve()
    if not _within(p, root) or not p.is_file():
        handler.send_response(404)
        handler.end_headers()
        return
    err = vendor.check(p.relative_to(root).as_posix(), p)
    if err:
        return _send_error(handler, 500, err)
    body = p.read_bytes()
    ctype, _ = mimetypes.guess_type(str(p))
    handler.send_response(200)
    handler.send_header("Content-Type", ctype or "application/octet-stream")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def build_handler(db_path: str, projects_dir: str, bind_host: str = "127.0.0.1"):
    pricing = load_pricing(PRICING_JSON)
    allowed = allowed_hostnames(bind_host)

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def _guard(self) -> bool:
            """Refuse rebound and cross-origin requests before any dispatch.

            Sends the error response itself and returns False when the request
            should not be served. See `allowed_hostnames` for the reasoning.
            """
            if _hostname(self.headers.get("Host") or "") not in allowed:
                _send_error(self, 421, "unrecognized Host header")
                return False
            origin = self.headers.get("Origin")
            # Browsers send Origin on same-origin POSTs too, so an Origin that
            # resolves to an allowed hostname is fine. Anything else (including
            # the literal "null" of a sandboxed or file:// document) is not.
            if origin and _hostname(urlparse(origin).netloc) not in allowed:
                _send_error(self, 403, "cross-origin request refused")
                return False
            return True

        def do_HEAD(self):
            return self.do_GET()

        def do_GET(self):
            if not self._guard():
                return
            url = urlparse(self.path)
            qs = parse_qs(url.query or "")
            path = url.path
            since = qs.get("since", [None])[0]
            until = qs.get("until", [None])[0]
            if "days" in qs:
                try:
                    days = int(qs["days"][0])
                    if not 1 <= days <= 3660:
                        raise ValueError()
                    since, until = day_range(days, get_timezone(db_path) or "UTC")
                except ValueError:
                    return _send_error(self, 400, "days must be an integer from 1 to 3660")
            if path in ("/", "/index.html"):
                return _serve_static(self, "index.html")
            if path.startswith("/web/"):
                return _serve_static(self, path[5:])
            if path == "/api/overview":
                totals = overview_totals(db_path, since, until)
                cost_usd = 0.0
                for m in model_breakdown(db_path, since, until):
                    c = cost_for(m["model"], m, pricing)
                    if c["usd"] is not None:
                        cost_usd += c["usd"]
                totals["cost_usd"] = round(cost_usd, 4)
                return _send_json(self, totals)
            if path == "/api/prompts":
                limit = _clamp_limit(qs.get("limit", ["50"])[0], 50)
                sort = qs.get("sort", ["tokens"])[0]
                rows = expensive_prompts(db_path, limit=limit, sort=sort)
                for r in rows:
                    c = cost_for(r["model"], {
                        "input_tokens": 0, "output_tokens": 0,
                        "cache_read_tokens": r["cache_read_tokens"],
                        "cache_create_5m_tokens": 0, "cache_create_1h_tokens": 0,
                    }, pricing)
                    r["estimated_cost_usd"] = c["usd"]
                return _send_json(self, rows)
            if path == "/api/projects":
                return _send_json(self, project_summary(db_path, since, until))
            if path == "/api/tools":
                return _send_json(self, tool_token_breakdown(db_path, since, until))
            if path == "/api/sessions":
                return _send_json(self, recent_sessions(
                    db_path, limit=_clamp_limit(qs.get("limit", ["20"])[0], 20),
                    since=since, until=until,
                ))
            if path == "/api/daily":
                return _send_json(self, daily_token_breakdown(db_path, since, until))
            if path == "/api/skills":
                rows = skill_breakdown(db_path, since, until)
                catalog = cached_catalog()
                for r in rows:
                    info = catalog.get(r["skill"])
                    r["tokens_per_call"] = info["tokens"] if info else None
                return _send_json(self, rows)
            if path == "/api/by-model":
                rows = model_breakdown(db_path, since, until)
                for r in rows:
                    c = cost_for(r["model"], r, pricing)
                    r["cost_usd"] = c["usd"]
                    r["cost_estimated"] = c["estimated"]
                return _send_json(self, rows)
            if path.startswith("/api/sessions/"):
                sid = path.rsplit("/", 1)[1]
                return _send_json(self, session_turns(db_path, sid))
            if path == "/api/tips":
                return _send_json(self, all_tips(db_path))
            if path == "/api/settings":
                return _send_json(self, {
                    "timezone": get_timezone(db_path),
                    "timezones": sorted(timezone_names()),
                })
            if path == "/api/plan":
                return _send_json(self, {"plan": get_plan(db_path), "pricing": pricing})
            if path == "/api/scan":
                n = scan_dir(projects_dir, db_path)
                return _send_json(self, n)
            if path == "/api/stream":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                while True:
                    try:
                        evt = EVENTS.get(timeout=15)
                        chunk = f"data: {json.dumps(evt, default=str)}\n\n".encode()
                    except queue.Empty:
                        chunk = b": ping\n\n"
                    try:
                        self.wfile.write(chunk)
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        return
            self.send_response(404)
            self.end_headers()

        def do_POST(self):
            if not self._guard():
                return
            url = urlparse(self.path)
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return _send_error(self, 400, "invalid Content-Length")
            if length < 0 or length > MAX_POST_BYTES:
                return _send_error(self, 413, f"body too large (max {MAX_POST_BYTES} bytes)")
            try:
                body = json.loads(self.rfile.read(length) or b"{}") if length else {}
            except json.JSONDecodeError:
                return _send_error(self, 400, "invalid JSON")
            if not isinstance(body, dict):
                return _send_error(self, 400, "body must be a JSON object")
            if url.path == "/api/settings":
                try:
                    set_timezone(db_path, body.get("timezone"))
                except ValueError as exc:
                    return _send_error(self, 400, str(exc))
                return _send_json(self, {"ok": True, "timezone": get_timezone(db_path)})
            if url.path == "/api/plan":
                set_plan(db_path, body.get("plan", "api"))
                return _send_json(self, {"ok": True})
            if url.path == "/api/tips/dismiss":
                dismiss_tip(db_path, body.get("key", ""))
                return _send_json(self, {"ok": True})
            self.send_response(404)
            self.end_headers()

    return H


def _scan_loop(db_path: str, projects_dir: str, interval: float = 30.0):
    while True:
        try:
            n = scan_dir(projects_dir, db_path)
            if n["messages"] > 0:
                EVENTS.put({"type": "scan", "n": n, "ts": time.time()})
        except Exception as e:
            EVENTS.put({"type": "error", "message": str(e)})
        time.sleep(interval)


def run(host: str, port: int, db_path: str, projects_dir: str):
    threading.Thread(target=_scan_loop, args=(db_path, projects_dir), daemon=True).start()
    H = build_handler(db_path, projects_dir, bind_host=host)
    httpd = http.server.ThreadingHTTPServer((host, port), H)
    httpd.serve_forever()
