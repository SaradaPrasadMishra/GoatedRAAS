"""
MOCK BACKEND  - standard library only, no install needed.

    python tools/mock_server.py            # serves http://localhost:8000

It answers every endpoint in API_CONTRACT.md with the sample data in
contracts/sample_data/, so the dashboard and the simulator can be built and
tested BEFORE the real backend exists. Replies are dumb canned lines.
Swap to the real backend later by changing nothing but the process you run.
"""
import json, os, re, sys, uuid, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "contracts", "sample_data")
load = lambda n: json.load(open(os.path.join(DATA, n), encoding="utf-8"))

SESSIONS = {s["id"]: s for s in load("sessions.json")}
GRAPH, STATS = load("graph.json"), load("stats.json")
CANNED = ["Oh beta, one minute, my spectacles are missing.",
          "Which button is it? The phone is very small for me.",
          "My grandson usually does this. Can you explain slowly?",
          "I am searching for my diary, the password is written there."]
UPI = re.compile(r"\b[\w.\-]{2,}@[a-zA-Z]{2,}\b(?!\.)")


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def summary(s):
    camp = next((n["campaign_id"] for n in GRAPH["nodes"] if n["id"] == s["id"]), None)
    return {"id": s["id"], "created_at": s["created_at"], "channel": s["channel"], "scam_type": s["scam_type"],
            "status": s["status"], "message_count": len(s["messages"]), "entity_count": len(s["entities"]),
            "time_wasted_seconds": s["time_wasted_seconds"], "campaign_id": camp}


class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        raw = body.encode() if isinstance(body, str) else json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(raw)

    def do_OPTIONS(self):
        self._send(204, "")

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        p = self.path.split("?")[0].rstrip("/")
        if p == "/api/health":
            return self._send(200, {"ok": True, "contract_version": "1.0", "llm": "fallback", "model": None})
        if p == "/api/sessions":
            return self._send(200, [summary(s) for s in SESSIONS.values()])
        if p == "/api/graph":
            return self._send(200, GRAPH)
        if p == "/api/stats":
            st = dict(STATS); st["sessions"] = len(SESSIONS)
            st["messages"] = sum(len(s["messages"]) for s in SESSIONS.values())
            return self._send(200, st)
        m = re.fullmatch(r"/api/sessions/(s_\w+)(/report)?", p)
        if m and m.group(1) in SESSIONS:
            s = SESSIONS[m.group(1)]
            if m.group(2):
                return self._send(200, f"<html><body><h1>MOCK report {s['id']}</h1><p>SIMULATION</p></body></html>", "text/html")
            return self._send(200, s)
        self._send(404, {"detail": "not found"})

    def do_POST(self):
        p = self.path.rstrip("/")
        if p == "/api/sessions":
            b = self._body()
            sid = "s_" + uuid.uuid4().hex[:8]
            s = {"id": sid, "created_at": now(), "channel": b.get("channel", "simulator"),
                 "persona": b.get("persona", "retired_teacher"), "scam_type": "unknown", "status": "active",
                 "messages": [], "entities": [], "time_wasted_seconds": 0, "is_simulation": True}
            SESSIONS[sid] = s
            if b.get("first_message"):
                self._turn(s, b["first_message"])
            return self._send(200, s)
        m = re.fullmatch(r"/api/sessions/(s_\w+)/messages", p)
        if m and m.group(1) in SESSIONS:
            return self._send(200, self._turn(SESSIONS[m.group(1)], self._body().get("text", "")))
        m = re.fullmatch(r"/api/sessions/(s_\w+)/close", p)
        if m and m.group(1) in SESSIONS:
            SESSIONS[m.group(1)]["status"] = "closed"
            return self._send(200, SESSIONS[m.group(1)])
        self._send(404, {"detail": "not found"})

    def _turn(self, s, text):
        mk = lambda role, t: {"id": "m_" + uuid.uuid4().hex[:8], "session_id": s["id"], "role": role, "text": t, "ts": now()}
        sm = mk("scammer", text)
        bm = mk("bot", CANNED[len(s["messages"]) // 2 % len(CANNED)])
        new = [{"type": "upi_id", "value": u.lower(), "raw": u, "message_id": sm["id"], "confidence": 0.5}
               for u in UPI.findall(text) if u.lower() not in {e["value"] for e in s["entities"]}]
        s["messages"] += [sm, bm]; s["entities"] += new
        return {"session_id": s["id"], "scammer_message": sm, "bot_reply": bm, "new_entities": new, "scam_type": s["scam_type"]}

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    print(f"MOCK backend on http://localhost:{port}  (Ctrl+C to stop)")
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
