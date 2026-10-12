"""
Business logic for every API route. No HTTP here, so it is easy to test.
Imports teammates' modules defensively: if one is missing or broken, a stub
from backend/stubs.py is used and the startup log says so.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time

from contracts.models import (CONTRACT_VERSION, CreateSessionRequest, Graph, Health, Message, Session,
                              SessionSummary, Stats, TurnResponse)
from backend import bot, stubs
from backend.store import Store, new_id, now_iso, time_wasted

log = logging.getLogger("scambaiter")
MODULES: dict[str, str] = {}

try:
    from extractor.extract import classify_scam, extract_entities
    MODULES["extractor"] = "real"
except Exception as e:  # noqa: BLE001
    extract_entities, classify_scam = stubs.extract_entities, stubs.classify_scam
    MODULES["extractor"] = f"STUB ({type(e).__name__}: {e})"
try:
    from extractor.campaigns import build_graph
    MODULES["campaigns"] = "real"
except Exception as e:  # noqa: BLE001
    build_graph = stubs.build_graph
    MODULES["campaigns"] = f"STUB ({type(e).__name__}: {e})"
try:
    from report.render import render_report
    MODULES["report"] = "real"
except Exception as e:  # noqa: BLE001
    render_report = stubs.render_report
    MODULES["report"] = f"STUB ({type(e).__name__}: {e})"

try:
    from report.analysis import analyse_session, demanded_amounts, level_for, red_flags
    MODULES["analysis"] = "real"
except Exception as e:  # noqa: BLE001
    analyse_session = demanded_amounts = level_for = red_flags = None
    MODULES["analysis"] = f"MISSING ({type(e).__name__}: {e})"

ENTITY_TYPES = ["upi_id", "phone", "url", "bank_account", "ifsc", "email", "crypto_wallet"]


class NotFound(Exception):
    pass


class Service:
    def __init__(self, store: Store | None = None):
        self.store = store or Store()
        # decoy for new cases that don't name one (e.g. the scammer's phone page); set from the dashboard
        self.default_persona = "retired_teacher"
        # backup replays: recordings live in data/replays/; ids of cases that are replays (shown as REPLAY)
        self.replay_dir = os.path.join(os.path.dirname(self.store.path), "replays")
        self.replay_ids: set[str] = set()
        self._graph_lock = threading.Lock()
        self._graph: Graph | None = None
        self._graph_version = -1
        # one turn at a time per session, but different sessions can run in parallel
        self._turn_locks: dict[str, threading.Lock] = {}
        self._turn_locks_guard = threading.Lock()

    # ------------------------------------------------------------------ helpers
    def _lock_for(self, sid: str) -> threading.Lock:
        with self._turn_locks_guard:
            return self._turn_locks.setdefault(sid, threading.Lock())

    def _require(self, sid: str) -> Session:
        s = self.store.get(sid)
        if s is None:
            raise NotFound(sid)
        return s

    @staticmethod
    def _safe_extract(text: str, mid: str):
        try:
            return extract_entities(text, mid)
        except Exception:  # noqa: BLE001
            log.exception("extract_entities crashed; using stub for this message")
            return stubs.extract_entities(text, mid)

    @staticmethod
    def _safe_classify(text: str) -> str:
        try:
            return classify_scam(text)
        except Exception:  # noqa: BLE001
            log.exception("classify_scam crashed")
            return "unknown"

    # ------------------------------------------------------------------ routes
    def health(self) -> Health:
        llm, model = bot.llm_status()
        return Health(ok=True, contract_version=CONTRACT_VERSION, llm=llm, model=model)

    def create_session(self, req: CreateSessionRequest) -> Session:
        persona = req.persona if req.persona in bot.PERSONAS else self.default_persona
        s = Session(id=new_id("s_"), created_at=now_iso(), channel=req.channel, persona=persona,
                    scam_type="unknown", status="active", messages=[], entities=[],
                    time_wasted_seconds=0, is_simulation=True)
        self.store.save(s)
        if req.first_message and req.first_message.strip():
            self.turn(s.id, req.first_message)
        return self._require(s.id)

    def turn(self, sid: str, text: str, reply_override: str | None = None, reply_delay: float = 0.0) -> TurnResponse:
        text = (text or "").strip()[:4000]
        if not text:
            raise ValueError("text must not be empty")
        with self._lock_for(sid):
            # 1-3: save scammer message, extract, classify (fast, no LLM)
            s = self._require(sid)
            sm = Message(id=new_id("m_"), session_id=sid, role="scammer", text=text, ts=now_iso())
            s.messages.append(sm)
            have = {(e.type, e.value) for e in s.entities}
            new = []
            for e in self._safe_extract(text, sm.id):
                if (e.type, e.value) not in have:
                    have.add((e.type, e.value)); new.append(e)
            s.entities.extend(new)
            s.scam_type = self._safe_classify("\n".join(m.text for m in s.messages if m.role == "scammer"))
            s.status = "active"
            s.time_wasted_seconds = time_wasted(s)
            self.store.save(s)  # dashboard sees the scammer message + entities immediately

            # 4: bot reply (may take a few seconds with the LLM; store is not locked meanwhile).
            #    A replay supplies the recorded reply instead, after a short "typing" pause.
            if reply_override is not None:
                time.sleep(reply_delay)
                reply = reply_override
            else:
                reply = bot.generate_reply(s, s.persona)
            bm = Message(id=new_id("m_"), session_id=sid, role="bot", text=reply, ts=now_iso())
            s = self._require(sid)
            s.messages.append(bm)
            s.time_wasted_seconds = time_wasted(s)  # 5
            self.store.save(s)
            return TurnResponse(session_id=sid, scammer_message=sm, bot_reply=bm,
                                new_entities=new, scam_type=s.scam_type)

    def close(self, sid: str) -> Session:
        with self._lock_for(sid):
            s = self._require(sid)
            s.status = "closed"
            self.store.save(s)
            return s

    def get(self, sid: str) -> Session:
        return self._require(sid)

    def graph(self) -> Graph:
        with self._graph_lock:
            if self._graph is None or self._graph_version != self.store.version:
                version = self.store.version
                sessions = sorted(self.store.all(), key=lambda x: x.created_at)
                try:
                    g = build_graph(sessions)
                    g = Graph.model_validate(g.model_dump() if hasattr(g, "model_dump") else g)
                except Exception:  # noqa: BLE001
                    log.exception("build_graph crashed; using stub")
                    g = stubs.build_graph(sessions)
                self._graph, self._graph_version = g, version
            return self._graph

    def list_summaries(self) -> list[SessionSummary]:
        g = self.graph()
        camp = {n.id: n.campaign_id for n in g.nodes if n.type == "session"}
        out = [SessionSummary(id=s.id, created_at=s.created_at, channel=s.channel, scam_type=s.scam_type,
                              status=s.status, message_count=len(s.messages), entity_count=len(s.entities),
                              time_wasted_seconds=s.time_wasted_seconds, campaign_id=camp.get(s.id))
               for s in self.store.all()]
        return sorted(out, key=lambda x: (x.created_at, x.id), reverse=True)

    def stats(self) -> Stats:
        sessions = self.store.all()
        by_type = {t: 0 for t in ENTITY_TYPES}
        for s in sessions:
            for e in s.entities:
                by_type[e.type] = by_type.get(e.type, 0) + 1
        return Stats(sessions=len(sessions), active_sessions=sum(s.status == "active" for s in sessions),
                     messages=sum(len(s.messages) for s in sessions), entities_total=sum(by_type.values()),
                     entities_by_type=by_type, campaigns=len(self.graph().campaigns),
                     time_wasted_seconds=sum(s.time_wasted_seconds for s in sessions))

    def report(self, sid: str) -> str:
        s = self._require(sid)
        g = self.graph()
        try:
            return render_report(s, g)
        except Exception:  # noqa: BLE001
            log.exception("render_report crashed; using stub")
            return stubs.render_report(s, g)

    def analysis(self, sid: str) -> dict:
        """Red flags, risk level, safety record and money demanded for one case."""
        s = self._require(sid)
        return analyse_session(s) if analyse_session else {}

    def money(self) -> dict:
        """Rupees scammers asked for across all cases, and how many times the decoy paid (always 0)."""
        demanded = paid = 0
        for s in self.store.all():
            if analyse_session:
                a = analyse_session(s)
                demanded += a["demanded"]
                paid += a["paid"]
        return {"demanded": demanded, "paid_times": paid}

    def check(self, body: dict) -> dict:
        """'Is this a scam?' on one message, without starting a decoy conversation."""
        text = str(body.get("text") or "").strip()[:4000]
        if not text:
            raise ValueError("text must not be empty")
        entities = self._safe_extract(text, "check")
        flags = red_flags(text, any(e.type == "url" for e in entities)) if red_flags else []
        level = level_for(flags) if level_for else "LOW"
        return {"scam_type": self._safe_classify(text), "level": level, "flags": flags,
                "entities": [e.model_dump() for e in entities],
                "demanded": sum(demanded_amounts(text)) if demanded_amounts else 0}

    # ------------------------------------------------------------------ gang dossier
    def dossier(self, cid: str) -> dict:
        """Everything about one gang: its cases, identifiers, money asked for and time wasted."""
        g = self.graph()
        camp = next((c for c in g.campaigns if c.id == cid), None)
        if camp is None:
            raise NotFound(cid)
        shared = set(camp.shared_entities)
        cases, ids = [], {}
        for sid in camp.session_ids:
            s = self.store.get(sid)
            if s is None:
                continue
            a = analyse_session(s) if analyse_session else {"demanded": 0, "level": "LOW"}
            cases.append({"id": s.id, "scam_type": s.scam_type, "channel": s.channel, "persona": s.persona,
                          "created_at": s.created_at, "time_wasted_seconds": s.time_wasted_seconds,
                          "demanded": a["demanded"], "level": a["level"], "replay": s.id in self.replay_ids})
            for e in s.entities:
                key = f"{e.type}:{e.value}"
                ids.setdefault(key, {"type": e.type, "value": e.value, "cases": 0, "shared": key in shared})
                ids[key]["cases"] += 1
        cases.sort(key=lambda c: c["created_at"])
        identifiers = sorted(ids.values(), key=lambda i: (not i["shared"], -i["cases"], i["type"]))
        return {"id": camp.id, "size": camp.size, "dominant_scam_type": camp.dominant_scam_type,
                "cases": cases, "identifiers": identifiers,
                "time_wasted_seconds": sum(c["time_wasted_seconds"] for c in cases),
                "demanded": sum(c["demanded"] for c in cases),
                "first_seen": cases[0]["created_at"] if cases else None,
                "last_seen": cases[-1]["created_at"] if cases else None}

    # ------------------------------------------------------------------ backup replay
    def save_replay(self, sid: str) -> dict:
        """Save a case (ideally a good live AI conversation from rehearsal) to replay on stage."""
        s = self._require(sid)
        turns, prev = [], None
        msgs = s.messages
        for i, m in enumerate(msgs):
            if m.role != "scammer":
                continue
            reply = msgs[i + 1].text if i + 1 < len(msgs) and msgs[i + 1].role == "bot" else ""
            gap = 0.0
            if prev is not None:
                from backend.store import parse_iso
                gap = max(0.0, (parse_iso(m.ts) - parse_iso(prev)).total_seconds())
            turns.append({"scammer": m.text, "bot": reply, "gap_s": round(gap, 1)})
            prev = m.ts
        if not turns or not any(t["bot"] for t in turns):
            raise ValueError("this case has no decoy replies to record yet")
        os.makedirs(self.replay_dir, exist_ok=True)
        name = re.sub(r"[^a-z0-9_]+", "_", f"{s.scam_type}_{s.id}".lower())
        rec = {"saved_from": s.id, "llm": bot.llm_status()[0], "channel": s.channel, "persona": s.persona,
               "scam_type": s.scam_type, "turns": turns}
        with open(os.path.join(self.replay_dir, name + ".json"), "w", encoding="utf-8") as f:
            json.dump(rec, f, ensure_ascii=False, indent=2)
        return {"saved": name, "turns": len(turns), "llm": rec["llm"]}

    def replays(self) -> dict:
        names = []
        if os.path.isdir(self.replay_dir):
            files = [f for f in os.listdir(self.replay_dir) if f.endswith(".json")]
            files.sort(key=lambda f: os.path.getmtime(os.path.join(self.replay_dir, f)), reverse=True)
            names = [f[:-5] for f in files]
        return {"recordings": names, "replay_sessions": sorted(self.replay_ids)}

    def start_replay(self, body: dict) -> dict:
        """Replay a recording as a new case at real pace (2-6 s between scammer messages)."""
        names = self.replays()["recordings"]
        name = body.get("name") or (names[0] if names else None)
        if not name or name not in names:
            raise ValueError("no recording yet: open a good case and press 'Save for replay' during rehearsal")
        with open(os.path.join(self.replay_dir, name + ".json"), encoding="utf-8") as f:
            rec = json.load(f)
        persona = rec.get("persona") if rec.get("persona") in bot.PERSONAS else self.default_persona
        channel = rec.get("channel") if rec.get("channel") in ("sms", "whatsapp", "telegram", "call_transcript", "simulator") else "simulator"
        s = Session(id=new_id("s_"), created_at=now_iso(), channel=channel, persona=persona,
                    scam_type="unknown", status="active", messages=[], entities=[],
                    time_wasted_seconds=0, is_simulation=True)
        self.replay_ids.add(s.id)
        self.store.save(s)
        turns = rec.get("turns", [])

        def run():
            try:
                for i, t in enumerate(turns):
                    if i:
                        time.sleep(min(6.0, max(2.0, float(t.get("gap_s") or 0))))
                    self.turn(s.id, t["scammer"], reply_override=t.get("bot") or "", reply_delay=1.5)
                self.close(s.id)
            except Exception:  # noqa: BLE001
                log.exception("replay %s failed", name)
        threading.Thread(target=run, daemon=True).start()
        return {"session_id": s.id, "recording": name, "turns": len(turns), "recorded_with": rec.get("llm")}

    def decoy(self) -> dict:
        return {"persona": self.default_persona, "personas": list(bot.PERSONAS)}

    def set_decoy(self, body: dict) -> dict:
        persona = body.get("persona")
        if persona not in bot.PERSONAS:
            raise ValueError(f"persona must be one of {', '.join(bot.PERSONAS)}")
        self.default_persona = persona
        return self.decoy()

    def reset(self) -> None:
        self.store.reset()
