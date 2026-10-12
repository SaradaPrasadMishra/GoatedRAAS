"""
Business logic for every API route. No HTTP here, so it is easy to test.
Imports teammates' modules defensively: if one is missing or broken, a stub
from backend/stubs.py is used and the startup log says so.
"""
from __future__ import annotations

import logging
import threading

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

    def turn(self, sid: str, text: str) -> TurnResponse:
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

            # 4: bot reply (may take a few seconds with the LLM; store is not locked meanwhile)
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
