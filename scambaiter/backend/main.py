"""
Scambaiter backend - HTTP API from API_CONTRACT.md + serves the dashboard.

    python -m backend.main                 # http://localhost:8000 (this laptop only)
    python -m backend.main --lan           # also reachable on the Wi-Fi (scammer's phone page)
    python -m backend.main --reset         # start with an empty database
    python -m backend.main --no-auth       # DEV ONLY: no login (prints a warning)

Standard library HTTP server, threaded. Security (backend/security.py, SECURITY.md):
- people log in (admin / analyst roles); devices and partners use API keys (intake / lookup scopes)
- per-client rate limits, login lockout, request size limits, strict security headers, no open CORS
- every case encrypted at rest and sealed in a hash chain; every sensitive action in a hash-chained audit log
Tools on this laptop (simulator, evaluate, tools/check_contract.py) are trusted without a key when they
call from 127.0.0.1 and are not a browser: they can read data/secrets.json anyway.

Environment:
    OLLAMA_MODEL=qwen2.5:7b     model for the bot (default qwen2.5:7b)
    SCAMBAITER_LLM=fallback     force canned replies (no LLM)
    SCAMBAITER_RETENTION_DAYS   delete cases older than this (default 30)
    SCAMBAITER_CORS_ORIGINS     comma-separated origins allowed to call the API from a browser
    SCAMBAITER_GMAIL_*          Gmail intake, see backend/mail.py
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import mimetypes
import os
import re
import ssl
import sys
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

from pydantic import BaseModel, ValidationError

from contracts.models import CreateSessionRequest, ScammerMessageRequest
from backend import bot, intel, mail, security
from backend.service import MODULES, NotFound, Service

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASHBOARD = os.path.join(ROOT, "dashboard")
log = logging.getLogger("scambaiter")


class Ctx:
    """Everything the handler needs, set up once in main()."""
    service: Service | None = None
    accounts: security.Accounts | None = None
    keys: security.ApiKeys | None = None
    audit: security.Audit | None = None
    mail: mail.MailIntake | None = None
    limiter = security.RateLimiter()
    guard = security.LoginGuard()
    no_auth = False
    trust_local = True
    https = False
    host = "127.0.0.1"
    cors: set[str] = set()
    retention_days = 30
    last_purge: str | None = None


C = Ctx
COOKIE = "sb_auth"
JSON_MAX = 64 * 1024
EMAIL_MAX = 2 * 1024 * 1024
_SESSION = r"(s_[A-Za-z0-9]+)"
_RANK = {"intake": 1, "analyst": 2, "admin": 3}
PUBLIC_FILES = {"login.html", "login.js", "style.css", "scammer.html", "scammer.js", "favicon.svg"}
# the only inline script left is the report's Print button: allow exactly that one handler
_PRINT_HASH = "'sha256-" + base64.b64encode(hashlib.sha256(b"window.print()").digest()).decode() + "'"
CSP_APP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
           "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
           "frame-ancestors 'none'")
CSP_DOC = ("default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; script-src 'unsafe-hashes' "
           + _PRINT_HASH + "; base-uri 'none'; form-action 'none'; frame-ancestors 'self'")
_NOT_BUILT = ("<!doctype html><html><body style='font-family:sans-serif;background:#111;color:#eee;padding:40px'>"
              "<h1>Scambaiter backend is running</h1><p>dashboard/ not found. API is at /api/health.</p></body></html>")


class HttpError(Exception):
    def __init__(self, code: int, detail: str, headers: dict | None = None):
        super().__init__(detail)
        self.code, self.detail, self.headers = code, detail, headers or {}


def _to_json(obj):
    if isinstance(obj, BaseModel):
        return obj.model_dump()
    if isinstance(obj, list):
        return [_to_json(o) for o in obj]
    return obj


def _masked_session(s):
    s = s.model_copy(deep=True)
    for m in s.messages:
        m.text = security.mask_text(m.text)
    return s


def _masked_meta(meta: dict) -> dict:
    meta = dict(meta)
    if meta.get("reporter"):
        meta["reporter"] = security.mask_contact(meta["reporter"])
    meta.pop("thread", None)
    return meta


class Handler(BaseHTTPRequestHandler):
    server_version = "Scambaiter"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # ------------------------------------------------------------ plumbing
    @property
    def ip(self) -> str:
        return self.client_address[0]

    def _send(self, code: int, body, ctype: str = "application/json", headers: dict | None = None) -> None:
        if isinstance(body, (bytes, bytearray)):
            raw = bytes(body)
        elif isinstance(body, str):
            raw = body.encode("utf-8")
        else:
            raw = json.dumps(_to_json(body), ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        if ctype.startswith(("text/", "application/json", "application/javascript", "application/xml")):
            ctype += "; charset=utf-8"
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        if ctype.startswith("text/html"):
            self.send_header("Content-Security-Policy", CSP_DOC if self.path.startswith("/api/") else CSP_APP)
            if not self.path.startswith("/api/"):
                self.send_header("X-Frame-Options", "DENY")
        if C.https:
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        origin = self.headers.get("Origin")
        if origin and origin in C.cors:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-API-Key, Authorization")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def _raw_body(self, limit: int = JSON_MAX) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        if n > limit:
            raise HttpError(413, f"request too large (limit {limit // 1024} KB)")
        return self.rfile.read(n) if n else b""

    def _body(self) -> dict:
        raw = self._raw_body()
        if not raw.strip():
            return {}
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            raise HttpError(415, "send JSON with Content-Type: application/json")
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object")
        return data

    def log_message(self, fmt, *args):  # quieter console: only API calls that change things
        if self.command == "POST":
            log.info("%s %s", self.command, re.sub(r"([?&]key=)[^&]+", r"\1***", self.path))

    # ------------------------------------------------------------ who is calling
    def _token(self) -> str | None:
        c = SimpleCookie()
        try:
            c.load(self.headers.get("Cookie") or "")
        except Exception:  # noqa: BLE001
            return None
        return c[COOKIE].value if COOKIE in c else None

    def _api_key(self) -> str | None:
        key = self.headers.get("X-API-Key")
        auth = self.headers.get("Authorization") or ""
        if not key and auth.lower().startswith("bearer "):
            key = auth[7:].strip()
        if not key and auth.lower().startswith("basic "):      # SMS gateways: https://x:<key>@host/...
            try:
                key = base64.b64decode(auth[6:]).decode().split(":", 1)[1]
            except Exception:  # noqa: BLE001
                key = None
        if not key and urlsplit(self.path).path.startswith("/api/intake/"):
            key = (parse_qs(urlsplit(self.path).query).get("key") or [None])[0]
        return key

    def _local_tool(self) -> bool:
        """A script on this laptop (urllib/httpx), not a browser: browsers always send Sec-Fetch-* headers."""
        return (C.trust_local and self.ip in ("127.0.0.1", "::1")
                and not self.headers.get("Origin") and not self.headers.get("Sec-Fetch-Mode"))

    def principal(self) -> dict | None:
        if C.no_auth:
            return {"name": "dev", "role": "admin", "kind": "dev"}
        info = C.accounts.resolve(self._token())
        if info:
            return {"name": info["user"], "role": info["role"], "kind": "user"}
        key = self._api_key()
        if key:
            rec = C.keys.resolve(key)
            if rec:
                return {"name": "key:" + rec["name"], "role": rec["scope"], "kind": "key", "key_id": rec["id"]}
            raise HttpError(401, "invalid or revoked API key")
        if self._local_tool():
            return {"name": "local-tool", "role": "analyst", "kind": "local"}
        return None

    def _authorize(self, need: str) -> dict:
        p = self.principal()
        if need == "public":
            return p or {"name": "anonymous", "role": "public", "kind": "anon"}
        if p is None:
            raise HttpError(401, "login required")
        role = p["role"]
        ok = role in ("lookup", "analyst", "admin") if need == "lookup" else _RANK.get(role, 0) >= _RANK[need]
        if not ok:
            raise HttpError(403, f"this needs the {need} role")
        # cross-site request forgery: a logged-in browser may only change things from our own pages
        if self.command == "POST" and p["kind"] == "user":
            origin = self.headers.get("Origin")
            host = self.headers.get("Host", "")
            if origin and urlsplit(origin).netloc != host and origin not in C.cors:
                raise HttpError(403, "cross-site request blocked")
        # rate limits (local tools are exempt: the simulator sends hundreds of turns)
        if p["kind"] in ("user", "key"):
            bucket, limit = ("v1", 60) if self.path.startswith("/api/v1/") else \
                ("post", 120 if p["kind"] == "user" else 60) if self.command == "POST" else ("get", 600)
            allowed, retry = C.limiter.allow(bucket, p["name"] + "|" + self.ip, limit)
            if not allowed:
                self.audit(p, "rate_limited", self.path, f"{bucket} limit {limit}/min")
                raise HttpError(429, "too many requests, slow down", {"Retry-After": str(retry)})
        return p

    def audit(self, p: dict, action: str, target: str = "", detail: str = "") -> None:
        if C.audit:
            C.audit.record(p.get("name", "?"), p.get("role", "?"), self.ip, action, target, detail)

    # ------------------------------------------------------------ dispatch
    def _dispatch(self, routes) -> None:
        path = urlsplit(self.path).path.rstrip("/") or "/"
        try:
            for pattern, need, fn in routes:
                m = re.fullmatch(pattern, path)
                if m:
                    p = self._authorize(need)
                    return fn(p, *m.groups())
            if self.command in ("GET", "HEAD") and not path.startswith("/api"):
                return self._static(path)
            self._send(404, {"detail": "not found"})
        except HttpError as e:
            self._send(e.code, {"detail": e.detail}, headers=e.headers)
        except NotFound:
            self._send(404, {"detail": "not found"})
        except ValidationError as e:
            self._send(422, {"detail": json.loads(e.json())})
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as e:
            self._send(422, {"detail": str(e)})
        except Exception as e:  # noqa: BLE001
            log.exception("error handling %s %s", self.command, self.path)
            self._send(500, {"detail": f"internal error ({type(e).__name__})"})

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
        elif rel == "login":
            rel = "login.html"
        full = os.path.realpath(os.path.join(DASHBOARD, rel))
        if not full.startswith(os.path.realpath(DASHBOARD) + os.sep) or not os.path.isfile(full):
            return self._send(404, {"detail": "not found"})
        # the console itself needs a login; its assets, the login page and the phone page do not
        if rel.endswith(".html") and rel not in PUBLIC_FILES and self.principal() is None:
            return self._send(302, b"", "text/plain", {"Location": "/login.html"})
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        if full.endswith(".js"):
            ctype = "application/javascript"
        with open(full, "rb") as f:
            self._send(200, f.read(), ctype)

    # ------------------------------------------------------------ verbs
    def do_OPTIONS(self):
        self._send(204, b"", "text/plain")

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        S = C.service
        q = parse_qs(urlsplit(self.path).query)
        self._dispatch([
            (r"/api/health", "public", lambda p: self._send(200, S.health())),
            (r"/api/me", "public", lambda p: self._send(200, self.me(p))),
            (r"/api/sessions", "analyst", lambda p: self._send(200, S.list_summaries())),
            (rf"/api/sessions/{_SESSION}", "intake", lambda p, sid: self._send(200, self.session_for(p, sid))),
            (rf"/api/sessions/{_SESSION}/report", "analyst", self.report),
            (rf"/api/sessions/{_SESSION}/complaint", "analyst", lambda p, sid: self.complaint(p, sid, q)),
            (rf"/api/sessions/{_SESSION}/verify", "analyst", lambda p, sid: self._send(200, S.verify(sid))),
            (r"/api/graph", "analyst", lambda p: self._send(200, S.graph())),
            (r"/api/stats", "analyst", lambda p: self._send(200, S.stats())),
            (r"/api/decoy", "intake", lambda p: self._send(200, S.decoy())),
            (r"/api/money", "analyst", lambda p: self._send(200, S.money())),
            (r"/api/replays", "analyst", lambda p: self._send(200, S.replays())),
            (r"/api/sources", "analyst", lambda p: self._send(200, self.sources(p))),
            (r"/api/integrations", "analyst", lambda p: self._send(200, self.integrations(p))),
            (r"/api/campaigns/(c_[0-9]+)/dossier", "analyst", self.dossier),
            (r"/api/campaigns/(c_[0-9]+)/alert", "analyst", self.alert),
            (rf"/api/sessions/{_SESSION}/analysis", "analyst", lambda p, sid: self._send(200, S.analysis(sid))),
            (rf"/api/sessions/{_SESSION}/links", "analyst", lambda p, sid: self._send(200, S.links(sid))),
            (r"/api/admin/audit", "admin", lambda p: self._send(200, {
                "entries": C.audit.entries(min(500, int((q.get("limit") or ["200"])[0]))), "chain": C.audit.verify()})),
            (r"/api/admin/keys", "admin", lambda p: self._send(200, C.keys.list())),
            (r"/api/admin/security", "admin", lambda p: self._send(200, self.security_overview())),
            # public API for banks / telecoms (lookup-scoped API key)
            (r"/api/v1/public-key", "public", lambda p: self._send(200, S.store.keys.public_key())),
            (r"/api/v1/lookup", "lookup", lambda p: self.v1_lookup(p, q)),
        ])

    def do_POST(self):
        S = C.service
        self._dispatch([
            (r"/api/login", "public", self.login),
            (r"/api/logout", "public", self.logout),
            (r"/api/sessions", "intake", self.create_session),
            (rf"/api/sessions/{_SESSION}/messages", "intake",
             lambda p, sid: self._send(200, S.turn(sid, ScammerMessageRequest(**self._body()).text))),
            (rf"/api/sessions/{_SESSION}/close", "intake", self.close),
            (r"/api/admin/reset", "admin", self.reset),
            (r"/api/admin/purge", "admin", self.purge),
            (r"/api/admin/keys", "admin", self.create_key),
            (r"/api/admin/keys/([0-9a-f]{8})/revoke", "admin", self.revoke_key),
            (r"/api/decoy", "analyst", self.set_decoy),
            (r"/api/check", "intake", lambda p: self._send(200, S.check(self._body()))),
            (r"/api/replays", "analyst", self.start_replay),
            (rf"/api/sessions/{_SESSION}/save-replay", "analyst",
             lambda p, sid: (self._body(), self.audit(p, "replay_saved", sid), self._send(200, S.save_replay(sid)))),
            (rf"/api/sessions/{_SESSION}/detonate", "analyst", self.detonate),
            (r"/api/intake/sms", "intake", self.intake_sms),
            (r"/api/intake/email", "intake", self.intake_email),
            (r"/api/integrations/gmail/poll", "admin", self.gmail_poll),
            (r"/api/v1/check", "lookup", self.v1_check),
        ])

    # ------------------------------------------------------------ auth routes
    def me(self, p: dict) -> dict:
        return {"user": p["name"], "role": p["role"], "kind": p["kind"], "auth": not C.no_auth}

    def login(self, p):
        wait = C.guard.locked(self.ip)
        if wait:
            self.audit({"name": "?", "role": "-"}, "login_locked", "", f"retry in {wait}s")
            raise HttpError(429, f"too many wrong passwords. Try again in {wait} seconds.", {"Retry-After": str(wait)})
        ok, _ = C.limiter.allow("login", self.ip, 10)
        if not ok:
            raise HttpError(429, "too many login attempts")
        b = self._body()
        user, pw = str(b.get("username", ""))[:64], str(b.get("password", ""))[:256]
        res = C.accounts.login(user, pw)
        if not res:
            C.guard.failed(self.ip)
            self.audit({"name": user or "?", "role": "-"}, "login_failed")
            raise HttpError(401, "wrong username or password")
        C.guard.ok(self.ip)
        self.audit({"name": res["user"], "role": res["role"]}, "login")
        cookie = (f"{COOKIE}={res['token']}; HttpOnly; SameSite=Strict; Path=/; "
                  f"Max-Age={security.SESSION_HOURS * 3600}" + ("; Secure" if C.https else ""))
        self._send(200, {"user": res["user"], "role": res["role"]}, headers={"Set-Cookie": cookie})

    def logout(self, p):
        if p.get("kind") == "user":
            self.audit(p, "logout")
        C.accounts.logout(self._token())
        self._send(200, {"ok": True}, headers={"Set-Cookie": f"{COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"})

    # ------------------------------------------------------------ case routes
    def session_for(self, p: dict, sid: str):
        s = C.service.get(sid)
        # an intake key (the phone page) may only read the cases it started itself
        if p["role"] == "intake" and C.service.store.get_meta(sid).get("created_by") != p["name"]:
            raise HttpError(403, "this key can only read cases it created")
        return s if p["role"] == "admin" else _masked_session(s)

    def sources(self, p: dict) -> dict:
        meta = C.service.sources()
        return {k: (dict(v, thread=None) if p["role"] == "admin" else _masked_meta(v))
                for k, v in meta.items() if v.get("source")}

    def create_session(self, p):
        req = CreateSessionRequest(**self._body())
        s = C.service.create_session(req)
        if p["kind"] == "key":
            C.service.store.set_meta(s.id, {"created_by": p["name"]})
        self.audit(p, "case_created", s.id, f"channel {s.channel}, decoy {s.persona}")
        self._send(200, s)

    def close(self, p, sid):
        self._body()
        s = C.service.close(sid)
        self.audit(p, "case_closed", sid)
        self._send(200, s)

    def report(self, p, sid):
        S = C.service
        s = S.get(sid)
        if p["role"] != "admin":
            s = _masked_session(s)
        html = S.report(sid, s)
        self.audit(p, "report_viewed", sid)
        self._send(200, html, "text/html")

    def complaint(self, p, sid, q):
        c = C.service.complaint(sid)
        if p["role"] != "admin":
            for m in c["scammer_messages"]:
                m["text"] = security.mask_text(m["text"])
        self.audit(p, "complaint_exported", sid, (q.get("format") or ["html"])[0])
        if (q.get("format") or [""])[0] == "json":
            extra = {"Content-Disposition": f'attachment; filename="ncrp-complaint-{sid}.json"'} if q.get("download") else {}
            return self._send(200, json.dumps(c, ensure_ascii=False, indent=2), "application/json", extra)
        self._send(200, intel.complaint_html(c), "text/html")

    def dossier(self, p, cid):
        self.audit(p, "dossier_viewed", cid)
        self._send(200, C.service.dossier(cid))

    def alert(self, p, cid):
        doc = C.service.mule_alert(cid)
        doc["issued_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        doc["issued_by"] = {"node": C.service.store.keys.key_id(), "user": p["name"]}
        doc["signature"] = C.service.store.keys.sign(security.canonical(doc))
        self.audit(p, "mule_alert_exported", cid, f"{len(doc['targets'])} targets")
        self._send(200, json.dumps(doc, ensure_ascii=False, indent=2), "application/json",
                   {"Content-Disposition": f'attachment; filename="mule-alert-{cid}.json"'})

    def set_decoy(self, p):
        r = C.service.set_decoy(self._body())
        self.audit(p, "decoy_changed", r["persona"])
        self._send(200, r)

    def start_replay(self, p):
        r = C.service.start_replay(self._body())
        self.audit(p, "replay_started", r["session_id"], r["recording"])
        self._send(200, r)

    def detonate(self, p, sid):
        url = str(self._body().get("url", ""))
        ok, retry = C.limiter.allow("sandbox", p["name"], 20)
        if not ok:
            raise HttpError(429, "sandbox limit: 20 links a minute", {"Retry-After": str(retry)})
        r = C.service.detonate(sid, url)
        self.audit(p, "link_detonated", sid, f"{url} -> {r['verdict']}")
        self._send(200, r)

    # ------------------------------------------------------------ admin
    def reset(self, p):
        self._body()
        C.service.reset()
        self.audit(p, "database_reset", "", "all cases deleted")
        self._send(200, {"ok": True})

    def purge(self, p):
        b = self._body()
        days = int(b.get("days", C.retention_days))
        if days < 0:
            raise ValueError("days must be >= 0")
        gone = C.service.purge(days)
        C.last_purge = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.audit(p, "retention_purge", "", f"{len(gone)} case(s) older than {days} days deleted")
        self._send(200, {"deleted": gone})

    def create_key(self, p):
        b = self._body()
        k = C.keys.create(str(b.get("name", "")), str(b.get("scope", "")))
        self.audit(p, "api_key_created", k["id"], f"{k['name']} ({k['scope']})")
        self._send(200, k)

    def revoke_key(self, p, kid):
        self._body()
        try:
            k = C.keys.revoke(kid)
        except KeyError:
            raise NotFound(kid)
        self.audit(p, "api_key_revoked", kid, k["name"])
        self._send(200, k)

    def security_overview(self) -> dict:
        st = C.service.store
        return {
            "auth": "off (dev)" if C.no_auth else "on",
            "roles": {"admin": "everything, sees unmasked data", "analyst": "cases, reports, exports (PII masked)",
                      "intake": "API key: send scams in", "lookup": "API key: public lookup API"},
            "users": sorted(C.accounts.users),
            "bind": C.host, "tls": C.https, "trusted_local_tools": C.trust_local,
            "encryption": "AES-256-GCM per case (row id bound as associated data)" if st.encrypted else
                          "OFF: pip install cryptography",
            "evidence_seal": {"algorithm": "HMAC-SHA256 hash chain per message", **C.service.verify_all()},
            "audit_log": C.audit.verify(),
            "retention_days": C.retention_days, "last_purge": C.last_purge,
            "rate_limits": {"login": "10/min per address, 5 wrong passwords = 5 min lock",
                            "writes": "120/min per user, 60/min per API key", "public_api": "60/min per key"},
            "cors": sorted(C.cors) or "same origin only",
            "api_keys": len([k for k in C.keys.list() if not k["revoked"]]),
            "signing_key": C.service.store.keys.key_id(),
            "gmail": C.mail.status if C.mail else {"enabled": False},
            "link_sandbox": C.service.sandbox.status(),
        }

    # ------------------------------------------------------------ integrations
    def integrations(self, p: dict) -> dict:
        phone = None
        if p["role"] == "admin" and C.host != "127.0.0.1":
            scheme = "https" if C.https else "http"
            port = self.server.server_address[1]
            phone = [f"{scheme}://{ip}:{port}/scammer#k={C.service.store.keys.intake_key}" for ip in _lan_ips()]
        return {"gmail": C.mail.status if C.mail else {"enabled": False}, "phone_links": phone,
                "link_sandbox": C.service.sandbox.status(),
                "sms_webhook": "/api/intake/sms", "email_upload": "/api/intake/email",
                "public_api": ["/api/v1/check", "/api/v1/lookup", "/api/v1/public-key"]}

    def intake_sms(self, p):
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype == "application/x-www-form-urlencoded":       # Twilio / Exotel style webhook
            form = parse_qs(self._raw_body().decode("utf-8", "replace"))
            sender, text, twiml = (form.get("From") or [""])[0], (form.get("Body") or [""])[0], True
        else:
            b = self._body()
            sender, text, twiml = str(b.get("from", "")), str(b.get("text", "")), False
        r = C.service.intake_sms(sender, text)
        self.audit(p, "sms_received", r["session_id"], f"from {sender}")
        if twiml:
            from xml.sax.saxutils import escape
            xml = f"<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response><Message>{escape(r['reply'])}</Message></Response>"
            return self._send(200, xml, "application/xml")
        self._send(200, r)

    def intake_email(self, p):
        raw = self._raw_body(EMAIL_MAX)
        if (self.headers.get("Content-Type") or "").startswith("application/json"):
            raw = str(json.loads(raw or b"{}").get("raw", "")).encode("utf-8")
        if not raw.strip():
            raise ValueError("send the email as .eml (message/rfc822)")
        r = C.mail.handle(raw, send_replies=False, via="eml_upload")
        self.audit(p, "email_uploaded", r.get("session_id", ""), r["action"])
        self._send(200, r)

    def gmail_poll(self, p):
        self._body()
        if not (C.mail and C.mail.cfg):
            raise HttpError(409, "Gmail is not configured. Set SCAMBAITER_GMAIL_USER and SCAMBAITER_GMAIL_APP_PASSWORD.")
        n = C.mail.poll_once()
        self.audit(p, "gmail_polled", "", f"{n} new")
        self._send(200, {"fetched": n, **C.mail.status})

    def v1_check(self, p):
        r = C.service.check(self._body())
        self.audit(p, "api_check", "", r["level"])
        self._send(200, r)

    def v1_lookup(self, p, q):
        r = C.service.lookup((q.get("type") or [""])[0], (q.get("value") or [""])[0])
        self.audit(p, "api_lookup", f"{r['type']}:{r['value']}", "known" if r["known"] else "unknown")
        self._send(200, r)


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


def _retention_loop() -> None:
    while True:
        time.sleep(3600)
        gone = C.service.purge(C.retention_days)
        C.last_purge = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if gone and C.audit:
            C.audit.record("system", "system", "-", "retention_purge", "", f"{len(gone)} case(s) deleted")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Scambaiter backend")
    ap.add_argument("--host", default=None, help="address to listen on (default 127.0.0.1, or 0.0.0.0 with --lan)")
    ap.add_argument("--lan", action="store_true", help="listen on the Wi-Fi too (for the scammer's phone page)")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    ap.add_argument("--reset", action="store_true", help="clear all saved sessions on startup")
    ap.add_argument("--no-auth", action="store_true", help="DEV ONLY: turn off login and API keys")
    ap.add_argument("--strict", action="store_true", help="do not trust local tools without an API key")
    ap.add_argument("--tls-cert", help="serve HTTPS with this certificate (PEM)")
    ap.add_argument("--tls-key", help="private key for --tls-cert (PEM)")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(message)s", datefmt="%H:%M:%S")
    C.service = S = Service()
    C.accounts = security.Accounts(os.path.dirname(S.store.path))
    C.keys = security.ApiKeys(S.store.keys, os.path.dirname(S.store.path))
    C.audit = security.Audit(S.store.keys, S.store.path)
    S.audit = C.audit.record
    C.mail = mail.MailIntake(S, mail.load_config())
    C.no_auth, C.trust_local = args.no_auth, not args.strict
    C.host = args.host or ("0.0.0.0" if args.lan else "127.0.0.1")
    C.cors = {o.strip() for o in os.environ.get("SCAMBAITER_CORS_ORIGINS", "").split(",") if o.strip()}
    C.retention_days = int(os.environ.get("SCAMBAITER_RETENTION_DAYS", "30"))
    if args.reset:
        S.reset()
        C.audit.record("operator", "admin", "console", "database_reset", "", "--reset on startup")
    gone = S.purge(C.retention_days)
    C.last_purge = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    C.audit.record("system", "system", "console", "server_started", C.host,
                   f"auth {'off' if C.no_auth else 'on'}, {len(gone)} expired case(s) purged")

    llm, model = bot.llm_status()
    scheme = "https" if args.tls_cert else "http"
    print("=" * 72)
    print(" SCAMBAITER backend")
    for name, state in MODULES.items():
        print(f"   {name:<10} {state}")
    print(f"   bot        {'Ollama ' + model if llm == 'ollama' else 'FALLBACK replies (Ollama not reachable or SCAMBAITER_LLM=fallback)'}")
    print(f"   sessions   {len(S.store.sessions)} loaded from {os.path.relpath(S.store.path, ROOT)}")
    print(f"   security   login {'OFF (--no-auth, dev only!)' if C.no_auth else 'on'} · "
          f"encryption {'AES-256-GCM' if S.store.encrypted else 'OFF (pip install cryptography)'} · "
          f"seal + audit on · retention {C.retention_days} days")
    if C.accounts.created:
        print("   FIRST RUN: logins created (also saved in data/FIRST_LOGIN.txt):")
        for u, pw in C.accounts.created.items():
            print(f"      {u:<8} {pw}")
    sb = S.sandbox.status()
    print(f"   sandbox    links checked in {sb['mode']} mode ({sb['egress']})")
    print(f"   gmail      {'on: ' + C.mail.cfg['user'] if C.mail.cfg else 'off (set SCAMBAITER_GMAIL_USER / _APP_PASSWORD)'}")
    print(f"   dashboard  {scheme}://localhost:{args.port}/")
    if C.host != "127.0.0.1":
        for ip in _lan_ips():
            print(f"   phone      {scheme}://{ip}:{args.port}/scammer#k={S.store.keys.intake_key}")
    else:
        print("   phone      off: start with --lan to let the scammer's phone connect")
    print("=" * 72)
    if llm == "ollama":
        threading.Thread(target=bot.warm_up, daemon=True).start()
    C.mail.start()
    threading.Thread(target=_retention_loop, daemon=True).start()

    httpd = ThreadingHTTPServer((C.host, args.port), Handler)
    httpd.daemon_threads = True
    if args.tls_cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(args.tls_cert, args.tls_key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        C.https = True
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        C.keys.flush()
        httpd.server_close()


if __name__ == "__main__":
    sys.exit(main())
