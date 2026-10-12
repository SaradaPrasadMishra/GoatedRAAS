"""
Session storage: in memory, persisted to data/scambaiter.sqlite so a restart
keeps demo data. Thread-safe. Standard library only.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

from contracts.models import Session

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
        self.version = 0  # bumps on every change; used to cache the graph
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, created_at TEXT, body TEXT)")
        self.db.commit()
        for (body,) in self.db.execute("SELECT body FROM sessions ORDER BY created_at"):
            try:
                s = Session.model_validate_json(body)
                self.sessions[s.id] = s
            except Exception:
                pass  # skip a corrupt row rather than refuse to start

    def save(self, s: Session) -> None:
        with self.lock:
            self.sessions[s.id] = s
            self.version += 1
            self.db.execute("INSERT OR REPLACE INTO sessions VALUES (?, ?, ?)", (s.id, s.created_at, s.model_dump_json()))
            self.db.commit()

    def get(self, sid: str) -> Session | None:
        with self.lock:
            s = self.sessions.get(sid)
            return s.model_copy(deep=True) if s else None

    def all(self) -> list[Session]:
        with self.lock:
            return [s.model_copy(deep=True) for s in self.sessions.values()]

    def reset(self) -> None:
        with self.lock:
            self.sessions.clear()
            self.version += 1
            self.db.execute("DELETE FROM sessions")
            self.db.commit()


def time_wasted(s: Session) -> int:
    if len(s.messages) < 2:
        return 0
    return max(0, int((parse_iso(s.messages[-1].ts) - parse_iso(s.messages[0].ts)).total_seconds()))


def dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False)
