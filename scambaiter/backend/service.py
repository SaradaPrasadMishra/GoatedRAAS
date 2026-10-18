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

from contracts.models import (CONTRACT_VERSION, CreateSessionRequest, Entity, Graph, Health, Message, Session,
                              SessionSummary, Stats, TurnResponse)
from contracts.normalize import normalise
from backend import bot, intel, stubs
from backend.sandbox import Sandbox
from backend.security import injection_attempt, mask_text
from backend.store import Store, new_id, now_iso, parse_iso, time_wasted

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
        # set by main.py: audit(actor, role, ip, action, target, detail)
        self.audit = None
        self._meta_lock = threading.Lock()
        # link sandbox: an analyst sends a captured link to it (SCAMBAITER_SANDBOX_AUTO=1 checks every new link)
        self.sandbox = Sandbox(extract=lambda t: [(e.type, e.value) for e in self._safe_extract(t, "sandbox")])
        self.auto_detonate = os.environ.get("SCAMBAITER_SANDBOX_AUTO", "0") == "1"

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

    def turn(self, sid: str, text: str, reply_override: str | None = None, reply_delay: float = 0.0,
             no_reply: bool = False) -> TurnResponse:
        text = (text or "").strip()[:4000]
        if not text:
            raise ValueError("text must not be empty")
        if injection_attempt(text):
            self.audit_event("decoy", "prompt_injection_detected", sid, text[:120])
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
            if self.auto_detonate:
                for e in new:
                    if e.type == "url":
                        threading.Thread(target=self._auto_detonate, args=(sid, e.value), daemon=True).start()

            # 4: bot reply (may take a few seconds with the LLM; store is not locked meanwhile).
            #    A replay supplies the recorded reply instead, after a short "typing" pause.
            if no_reply:   # a reported message (forwarded email, SMS report): evidence only, nobody to answer
                return TurnResponse(session_id=sid, scammer_message=sm,
                                    bot_reply=Message(id="m_none", session_id=sid, role="bot", text="", ts=sm.ts),
                                    new_entities=new, scam_type=s.scam_type)
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

    def report(self, sid: str, shown: Session | None = None) -> str:
        """`shown` is the copy to print (PII-masked for analysts); the seal is checked on the stored case."""
        s = shown or self._require(sid)
        g = self.graph()
        try:
            try:
                return render_report(s, g, seal=self.store.verify(sid), source=self.store.get_meta(sid))
            except TypeError:   # an older render.py without the seal section
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
            src = self.store.get_meta(s.id).get("source")
            channel = {"gmail": "email", "eml_upload": "email", "sms_gateway": "sms"}.get(src, s.channel)
            cases.append({"id": s.id, "scam_type": s.scam_type, "channel": channel, "persona": s.persona,
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
        self.replay_ids.clear()

    # ------------------------------------------------------------------ audit + integrity
    def audit_event(self, actor: str, action: str, target: str = "", detail: str = "") -> None:
        if self.audit:
            self.audit(actor, "system", "-", action, target, mask_text(detail))

    def verify(self, sid: str) -> dict:
        self._require(sid)
        return self.store.verify(sid)

    def verify_all(self) -> dict:
        results = {sid: self.store.verify(sid) for sid in list(self.store.sessions)}
        return {"cases": len(results), "sealed": sum(r["ok"] for r in results.values()),
                "tampered": [sid for sid, r in results.items() if not r["ok"]]}

    # ------------------------------------------------------------------ intake from real channels
    def add_entities(self, sid: str, items: list[tuple[str, str]], message_id: str | None = None,
                     confidence: float = 1.0) -> list[tuple[str, str]]:
        """Identifiers known from outside the text: the sender's email or phone, or a scam page."""
        added = []
        with self._lock_for(sid):
            s = self._require(sid)
            first = next((m for m in s.messages if m.id == message_id), None) or \
                next((m for m in s.messages if m.role == "scammer"), None)
            if first is None:
                return added
            have = {(e.type, e.value) for e in s.entities}
            for etype, raw in items:
                if not raw:
                    continue
                try:
                    value = normalise(etype, raw)
                except Exception:  # noqa: BLE001
                    continue
                if (etype, value) not in have and value.strip("+"):
                    have.add((etype, value))
                    added.append((etype, value))
                    s.entities.append(Entity(type=etype, value=value, raw=raw, message_id=first.id, confidence=confidence))
            self.store.save(s)
        return added

    def _new_session(self, channel: str, persona: str | None = None) -> Session:
        s = Session(id=new_id("s_"), created_at=now_iso(), channel=channel,
                    persona=persona if persona in bot.PERSONAS else self.default_persona,
                    scam_type="unknown", status="active", messages=[], entities=[],
                    time_wasted_seconds=0, is_simulation=True)
        self.store.save(s)
        return s

    def ingest_report(self, text: str, meta: dict, extra_emails=(), extra_phones=(), channel: str = "simulator") -> Session:
        """A scam someone reported (forwarded email, SMS report): a closed case, no decoy reply."""
        s = self._new_session(channel)
        self.store.set_meta(s.id, meta)
        self.turn(s.id, text, no_reply=True)
        self.add_entities(s.id, [("email", e) for e in extra_emails] + [("phone", p) for p in extra_phones])
        return self.close(s.id)

    def create_session_from(self, text: str, meta: dict, channel: str, extra_emails=(), extra_phones=()) -> Session:
        """A scammer reached the decoy on a real channel (email, SMS gateway): the decoy answers."""
        s = self._new_session(channel)
        self.store.set_meta(s.id, meta)
        self.turn(s.id, text)
        self.add_entities(s.id, [("email", e) for e in extra_emails] + [("phone", p) for p in extra_phones])
        return self._require(s.id)

    def find_email_thread(self, refs: list[str]) -> str | None:
        refs = set(refs)
        if not refs:
            return None
        for sid, meta in self.store.all_meta().items():
            if meta.get("mode") == "decoy" and refs & set(meta.get("thread", [])) and sid in self.store.sessions:
                return sid
        return None

    def add_email_thread(self, sid: str, ids: list[str]) -> None:
        with self._meta_lock:
            meta = self.store.get_meta(sid)
            meta["thread"] = list(dict.fromkeys(meta.get("thread", []) + [i for i in ids if i]))
            self.store.set_meta(sid, meta)

    # ------------------------------------------------------------------ link sandbox
    def detonate(self, sid: str, url: str) -> dict:
        """Open a captured link in the sandbox; identifiers printed on the page join the case."""
        s = self._require(sid)
        url = (url or "").strip()
        if not url:
            raise ValueError("url must not be empty")
        r = self.sandbox.detonate(url)
        ent = next((e for e in s.entities if e.type == "url" and (e.value == url or e.raw == url)), None)
        new = self.add_entities(sid, [(i["type"], i["value"]) for i in r.get("identifiers", [])
                                      if i["type"] != "url"], message_id=ent.message_id if ent else None, confidence=0.9)
        r["new_identifiers"] = [{"type": t, "value": v} for t, v in new]
        with self._meta_lock:
            meta = self.store.get_meta(sid)
            links = meta.get("links", {})
            links[url] = r
            meta["links"] = links
            self.store.set_meta(sid, meta)
        self.audit_event("sandbox", "link_detonated", sid, f"{url} -> {r['verdict']}")
        return r

    def _auto_detonate(self, sid: str, url: str) -> None:
        try:
            self.detonate(sid, url)
        except Exception:  # noqa: BLE001
            log.exception("sandbox check of %s failed", url)

    def links(self, sid: str) -> dict:
        self._require(sid)
        return {"sandbox": self.sandbox.status(), "links": self.store.get_meta(sid).get("links", {})}

    def intake_sms(self, sender: str, text: str) -> dict:
        """SMS gateway webhook: the scammer texted the decoy's number. Continues the sender's open case."""
        text = (text or "").strip()
        if not text:
            raise ValueError("text must not be empty")
        sender = (sender or "").strip()[:32]
        if not re.fullmatch(r"\+?[0-9 ()-]{3,20}|[A-Za-z0-9-]{3,11}", sender):
            raise ValueError("from must be a phone number or an SMS sender ID")
        cutoff = time.time() - 6 * 3600
        for sid, meta in self.store.all_meta().items():
            s = self.store.get(sid)
            if (meta.get("source") == "sms_gateway" and meta.get("peer") == sender and s and s.status == "active"
                    and s.messages and parse_iso(s.messages[-1].ts).timestamp() > cutoff):
                t = self.turn(sid, text)
                return {"session_id": sid, "reply": t.bot_reply.text, "new_case": False}
        meta = {"source": "sms_gateway", "mode": "decoy", "peer": sender}
        phones = [sender] if len(re.sub(r"\D", "", sender)) >= 10 else []
        s = self.create_session_from(text, meta, channel="sms", extra_phones=phones)
        self.audit_event("sms-gateway", "sms_decoy_started", s.id, f"from {sender}")
        reply = next((m.text for m in reversed(s.messages) if m.role == "bot"), "")
        return {"session_id": s.id, "reply": reply, "new_case": True}

    def sources(self) -> dict:
        return self.store.all_meta()

    # ------------------------------------------------------------------ real-world outputs
    def complaint(self, sid: str) -> dict:
        s = self._require(sid)
        a = analyse_session(s) if analyse_session else {}
        return intel.complaint(s, self.graph(), a, self.store.verify(sid), self.store.get_meta(sid))

    def mule_alert(self, cid: str) -> dict:
        d = self.dossier(cid)
        sessions = [x for x in (self.store.get(c["id"]) for c in d["cases"]) if x]
        return intel.mule_alert(d, sessions, {x.id: self.store.verify(x.id) for x in sessions})

    def lookup(self, etype: str, value: str) -> dict:
        if etype not in ENTITY_TYPES:
            raise ValueError(f"type must be one of {', '.join(ENTITY_TYPES)}")
        value = (value or "").strip()[:200]
        if not value:
            raise ValueError("value must not be empty")
        return intel.lookup(etype, normalise(etype, value), self.store.all(), self.graph())

    def purge(self, days: int) -> list[str]:
        gone = self.store.purge(days)
        for sid in gone:
            self.replay_ids.discard(sid)
        return gone
