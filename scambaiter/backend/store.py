"""
Session storage: in memory, persisted to data/scambaiter.sqlite so a restart
keeps demo data. Thread-safe. Standard library (+ cryptography for AES-GCM).

Security (see backend/security.py):
- every case is stored encrypted with AES-256-GCM (key in data/secrets.json or SCAMBAITER_DATA_KEY)
- every message is sealed into an HMAC-SHA256 hash chain (table `ledger`); verify() re-reads the
  database and reports the first message that no longer matches its seal
- closed cases older than the retention period are deleted by purge()
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone

from contracts.models import Session
from backend.security import HAVE_CRYPTO, Keys, genesis, seal_message

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.environ.get("SCAMBAITER_DB", os.path.join(ROOT, "data", "scambaiter.sqlite"))


def new_id(prefix: str) -> str:
    return prefix + uuid.uuid4().hex[:8]


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


class Store:
    def __init__(self, path: str = DB_PATH):
        self.lock = threading.RLock()
        self.sessions: dict[str, Session] = {}
        self.meta: dict[str, dict] = {}   # where a case came from (gmail, sms gateway...): not part of the contract
        self.version = 0  # bumps on every change; used to cache the graph
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.keys = Keys(os.path.dirname(path))
        self.encrypted = HAVE_CRYPTO
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, created_at TEXT, body TEXT)")
        self.db.execute("CREATE TABLE IF NOT EXISTS ledger (session_id TEXT, seq INTEGER, message_id TEXT,"
                        " prev TEXT, hash TEXT, PRIMARY KEY (session_id, seq))")
        self.db.execute("CREATE TABLE IF NOT EXISTS case_meta (id TEXT PRIMARY KEY, body TEXT)")
        self.db.commit()
        self.sealed: dict[str, tuple[int, str]] = {}  # session id -> (messages sealed, chain head)
        for sid, n, head in self.db.execute(
                "SELECT session_id, COUNT(*), (SELECT hash FROM ledger l2 WHERE l2.session_id = l.session_id "
                "ORDER BY seq DESC LIMIT 1) FROM ledger l GROUP BY session_id"):
            self.sealed[sid] = (n, head)
        plain = []
        for sid, body in self.db.execute("SELECT id, body FROM sessions ORDER BY created_at").fetchall():
            try:
                s = Session.model_validate_json(self.keys.decrypt(body, sid))
                self.sessions[s.id] = s
                if not body.startswith("gcm1:"):
                    plain.append(s)
            except Exception:
                pass  # skip a corrupt row rather than refuse to start
        for sid, body in self.db.execute("SELECT id, body FROM case_meta").fetchall():
            try:
                self.meta[sid] = json.loads(self.keys.decrypt(body, "meta:" + sid))
            except Exception:
                pass
        for s in plain:          # rows written before encryption: encrypt them now
            self.save(s)
        for s in list(self.sessions.values()):
            if s.id not in self.sealed and s.messages:
                self.save(s)     # cases from before the seal existed get sealed from now on

    # ------------------------------------------------------------------ write
    def _seal_new(self, s: Session) -> None:
        n, head = self.sealed.get(s.id, (0, genesis(self.keys, s.id)))
        for i, m in enumerate(s.messages[n:], start=n + 1):
            h = seal_message(self.keys, head, m)
            self.db.execute("INSERT OR REPLACE INTO ledger VALUES (?, ?, ?, ?, ?)", (s.id, i, m.id, head, h))
            head, n = h, i
        self.sealed[s.id] = (n, head)

    def save(self, s: Session) -> None:
        with self.lock:
            self.sessions[s.id] = s
            self.version += 1
            body = self.keys.encrypt(s.model_dump_json(), s.id) if self.encrypted else s.model_dump_json()
            self.db.execute("INSERT OR REPLACE INTO sessions VALUES (?, ?, ?)", (s.id, s.created_at, body))
            self._seal_new(s)
            self.db.commit()

    def set_meta(self, sid: str, meta: dict) -> None:
        with self.lock:
            self.meta[sid] = meta
            body = json.dumps(meta, ensure_ascii=False)
            if self.encrypted:
                body = self.keys.encrypt(body, "meta:" + sid)
            self.db.execute("INSERT OR REPLACE INTO case_meta VALUES (?, ?)", (sid, body))
            self.db.commit()

    # ------------------------------------------------------------------ read
    def get(self, sid: str) -> Session | None:
        with self.lock:
            s = self.sessions.get(sid)
            return s.model_copy(deep=True) if s else None

    def all(self) -> list[Session]:
        with self.lock:
            return [s.model_copy(deep=True) for s in self.sessions.values()]

    def get_meta(self, sid: str) -> dict:
        with self.lock:
            return dict(self.meta.get(sid, {}))

    def all_meta(self) -> dict[str, dict]:
        with self.lock:
            return {k: dict(v) for k, v in self.meta.items()}

    # ------------------------------------------------------------------ evidence seal
    def verify(self, sid: str) -> dict:
        """Re-read the case from disk and check every message against its seal."""
        with self.lock:
            row = self.db.execute("SELECT body FROM sessions WHERE id = ?", (sid,)).fetchone()
            seals = self.db.execute("SELECT seq, message_id, prev, hash FROM ledger WHERE session_id = ? "
                                    "ORDER BY seq", (sid,)).fetchall()
        if row is None:
            return {"ok": False, "messages": 0, "sealed": len(seals), "reason": "case missing from the database"}
        try:
            s = Session.model_validate_json(self.keys.decrypt(row[0], sid))
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "messages": 0, "sealed": len(seals), "reason": f"unreadable: {e}"}
        head = genesis(self.keys, sid)
        for i, m in enumerate(s.messages):
            if i >= len(seals):
                return {"ok": False, "messages": len(s.messages), "sealed": len(seals), "broken_at": i + 1,
                        "reason": f"message {i + 1} was added without a seal"}
            seq, mid, prev, h = seals[i]
            if mid != m.id or prev != head or h != seal_message(self.keys, head, m):
                return {"ok": False, "messages": len(s.messages), "sealed": len(seals), "broken_at": i + 1,
                        "reason": f"message {i + 1} ({m.role}) does not match its seal: it was edited, "
                                  f"reordered or replaced after capture"}
            head = h
        if len(seals) > len(s.messages):
            return {"ok": False, "messages": len(s.messages), "sealed": len(seals), "broken_at": len(s.messages) + 1,
                    "reason": f"{len(seals) - len(s.messages)} sealed message(s) were deleted"}
        return {"ok": True, "messages": len(s.messages), "sealed": len(seals), "head": head,
                "algorithm": "HMAC-SHA256 hash chain", "encrypted": row[0].startswith("gcm1:")}

    def tamper_for_demo(self, sid: str) -> str:
        """DEMO ONLY: what a dishonest insider with database access might do. Changes the first
        scammer message on disk (re-encrypting it properly), but cannot fix the seal."""
        with self.lock:
            row = self.db.execute("SELECT body FROM sessions WHERE id = ?", (sid,)).fetchone()
            if row is None:
                return f"no case {sid}"
            s = Session.model_validate_json(self.keys.decrypt(row[0], sid))
            m = next((m for m in s.messages if m.role == "scammer"), None)
            if m is None:
                return "case has no scammer message"
            m.text = "Hello, this is your bank. Have a nice day."
            body = self.keys.encrypt(s.model_dump_json(), sid) if row[0].startswith("gcm1:") else s.model_dump_json()
            self.db.execute("UPDATE sessions SET body = ? WHERE id = ?", (body, sid))
            self.db.commit()
        return f"edited message 1 of {sid} on disk. The dashboard seal badge turns TAMPERED within 2 s."

    # ------------------------------------------------------------------ delete
    def _delete(self, sid: str) -> None:
        self.sessions.pop(sid, None)
        self.meta.pop(sid, None)
        self.sealed.pop(sid, None)
        for table, col in (("sessions", "id"), ("ledger", "session_id"), ("case_meta", "id")):
            self.db.execute(f"DELETE FROM {table} WHERE {col} = ?", (sid,))

    def purge(self, days: int) -> list[str]:
        """Data minimisation: delete cases whose last activity is older than `days`."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        with self.lock:
            old = [s.id for s in self.sessions.values()
                   if parse_iso(s.messages[-1].ts if s.messages else s.created_at) < cutoff]
            for sid in old:
                self._delete(sid)
            if old:
                self.version += 1
                self.db.commit()
            return old

    def reset(self) -> None:
        with self.lock:
            self.sessions.clear()
            self.meta.clear()
            self.sealed.clear()
            self.version += 1
            for table in ("sessions", "ledger", "case_meta"):
                self.db.execute(f"DELETE FROM {table}")
            self.db.commit()


def time_wasted(s: Session) -> int:
    if len(s.messages) < 2:
        return 0
    return max(0, int((parse_iso(s.messages[-1].ts) - parse_iso(s.messages[0].ts)).total_seconds()))


def dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False)
