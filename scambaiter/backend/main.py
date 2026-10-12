"""
Scambaiter backend - HTTP API from API_CONTRACT.md + serves the dashboard.

    python -m backend.main                 # http://localhost:8000
    python -m backend.main --port 8080
    python -m backend.main --reset         # start with an empty database

Standard library HTTP server (no FastAPI/uvicorn needed), threaded, CORS open.
Environment:
    OLLAMA_MODEL=qwen2.5:7b     model for the bot (default qwen2.5:7b)
    SCAMBAITER_LLM=fallback     force canned replies (no LLM)
"""
from __future__ import annotations

import argparse
import json
import logging
import mimetypes
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, ValidationError

from contracts.models import CreateSessionRequest, ScammerMessageRequest
from backend import bot
from backend.service import MODULES, NotFound, Service

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASHBOARD = os.path.join(ROOT, "dashboard")
log = logging.getLogger("scambaiter")
SERVICE: Service | None = None

_SESSION = r"(s_[A-Za-z0-9]+)"
_NOT_BUILT = ("<!doctype html><html><body style='font-family:sans-serif;background:#111;color:#eee;padding:40px'>"
              "<h1>Scambaiter backend is running</h1><p>dashboard/ not found. API is at <a href='/api/health' "
              "style='color:#2de2e6'>/api/health</a>.</p></body></html>")


def _to_json(obj):
    if isinstance(obj, BaseModel):
        return obj.model_dump()
    if isinstance(obj, list):
        return [_to_json(o) for o in obj]
    return obj


class Handler(BaseHTTPRequestHandler):
    server_version = "Scambaiter/1.0"
    protocol_version = "HTTP/1.1"

    # ------------------------------------------------------------ plumbing
    def _send(self, code: int, body, ctype: str = "application/json") -> None:
        if isinstance(body, (bytes, bytearray)):
            raw = bytes(body)
        elif isinstance(body, str):
            raw = body.encode("utf-8")
        else:
            raw = json.dumps(_to_json(body), ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        if ctype.startswith(("text/", "application/json", "application/javascript")):
            ctype += "; charset=utf-8"
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n > 1_000_000:
            raise ValueError("body too large")
        raw = self.rfile.read(n) if n else b""
        if not raw.strip():
            return {}
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object")
        return data

    def log_message(self, fmt, *args):  # quieter console: only API calls that change things
        if self.command == "POST":
            log.info("%s %s", self.command, self.path)

    def _dispatch(self, routes) -> None:
        path = urlsplit(self.path).path.rstrip("/") or "/"
        try:
            for pattern, fn in routes:
                m = re.fullmatch(pattern, path)
                if m:
                    return fn(*m.groups())
            if self.command in ("GET", "HEAD") and not path.startswith("/api"):
                return self._static(path)
            self._send(404, {"detail": "not found"})
        except NotFound:
            self._send(404, {"detail": "session not found"})
        except ValidationError as e:
            self._send(422, {"detail": json.loads(e.json())})
        except (ValueError, json.JSONDecodeError) as e:
            self._send(422, {"detail": str(e)})
        except Exception as e:  # noqa: BLE001
            log.exception("error handling %s %s", self.command, self.path)
            self._send(500, {"detail": f"{type(e).__name__}: {e}"})

    # ------------------------------------------------------------ static dashboard
    def _static(self, path: str) -> None:
        if not os.path.isdir(DASHBOARD):
            return self._send(200, _NOT_BUILT, "text/html")
        rel = unquote(path).lstrip("/")
        if rel.startswith("dashboard/"):
            rel = rel[len("dashboard/"):]
        if rel in ("", "dashboard"):
            rel = "index.html"
        elif rel in ("scammer", "phone"):
            rel = "scammer.html"
        full = os.path.realpath(os.path.join(DASHBOARD, rel))
        if not full.startswith(os.path.realpath(DASHBOARD) + os.sep) or not os.path.isfile(full):
            return self._send(404, {"detail": "not found"})
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        with open(full, "rb") as f:
            self._send(200, f.read(), ctype)

    # ------------------------------------------------------------ verbs
    def do_OPTIONS(self):
        self._send(204, b"", "text/plain")

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        S = SERVICE
        self._dispatch([
            (r"/api/health", lambda: self._send(200, S.health())),
            (r"/api/sessions", lambda: self._send(200, S.list_summaries())),
            (rf"/api/sessions/{_SESSION}", lambda sid: self._send(200, S.get(sid))),
            (rf"/api/sessions/{_SESSION}/report", lambda sid: self._send(200, S.report(sid), "text/html")),
            (r"/api/graph", lambda: self._send(200, S.graph())),
            (r"/api/stats", lambda: self._send(200, S.stats())),
        ])

    def do_POST(self):
        S = SERVICE
        self._dispatch([
            (r"/api/sessions", lambda: self._send(200, S.create_session(CreateSessionRequest(**self._body())))),
            (rf"/api/sessions/{_SESSION}/messages",
             lambda sid: self._send(200, S.turn(sid, ScammerMessageRequest(**self._body()).text))),
            (rf"/api/sessions/{_SESSION}/close", lambda sid: (self._body(), self._send(200, S.close(sid)))),
            (r"/api/admin/reset", lambda: (self._body(), S.reset(), self._send(200, {"ok": True}))),
        ])


def _lan_ips() -> list[str]:
    """This laptop's addresses on the local network (for the scammer's phone)."""
    import socket
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))  # no packet is sent; just picks the outgoing interface
        ips.append(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ips and not ip.startswith(("127.", "169.254.")):
                ips.append(ip)
    except OSError:
        pass
    return [ip for ip in ips if not ip.startswith("127.")]


def main(argv=None) -> None:
    global SERVICE
    ap = argparse.ArgumentParser(description="Scambaiter backend")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    ap.add_argument("--reset", action="store_true", help="clear all saved sessions on startup")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(message)s", datefmt="%H:%M:%S")
    SERVICE = Service()
    if args.reset:
        SERVICE.reset()

    llm, model = bot.llm_status()
    print("=" * 64)
    print(" SCAMBAITER backend")
    for name, state in MODULES.items():
        print(f"   {name:<10} {state}")
    print(f"   bot        {'Ollama ' + model if llm == 'ollama' else 'FALLBACK replies (Ollama not reachable or SCAMBAITER_LLM=fallback)'}")
    print(f"   sessions   {len(SERVICE.store.sessions)} loaded from {os.path.relpath(SERVICE.store.path, ROOT)}")
    print(f"   dashboard  http://localhost:{args.port}/")
    for ip in _lan_ips():
        print(f"   phone      http://{ip}:{args.port}/scammer   (scammer's phone, same Wi-Fi)")
    print("=" * 64)
    if llm == "ollama":
        threading.Thread(target=bot.warm_up, daemon=True).start()

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.daemon_threads = True
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    sys.exit(main())
