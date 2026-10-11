"""
SCAMBAITER SHARED CONTRACT  (contracts/models.py)
=================================================
Every module reads and writes ONLY these shapes. Do not rename fields.
If you think a field must change, tell the tech lead first; they change it
here and everyone re-pastes this file into their AI chat.

Python 3.10+, pydantic v2.  JSON field names == Python attribute names.
Timestamps are ISO-8601 strings in UTC, e.g. "2026-10-12T05:31:07Z".
"""
from __future__ import annotations

from typing import Literal, Optional
from pydantic import BaseModel, Field

CONTRACT_VERSION = "1.0"

# ---------------------------------------------------------------- enums
EntityType = Literal[
    "upi_id",        # rahul.kyc@okaxis
    "phone",         # +919876543210
    "url",           # sbi-kyc-update.in/verify
    "bank_account",  # 9-18 digit account number
    "ifsc",          # SBIN0001234
    "email",         # refund.desk@gmail.com
    "crypto_wallet", # 0x..., bc1..., T...
]

ScamType = Literal[
    "kyc_update",       # "your KYC expired, account blocked"
    "refund_collect",   # fake refund via UPI collect request
    "job_task",         # part-time job / like-videos task scam
    "lottery_prize",    # you won KBC / lucky draw
    "digital_arrest",   # fake police/CBI/customs threat
    "investment",       # stock tips / crypto doubling
    "loan_app",         # instant loan, pay processing fee
    "other",
    "unknown",          # not enough text yet
]

Role = Literal["scammer", "bot"]
SessionStatus = Literal["active", "closed"]


# ---------------------------------------------------------------- core
class Entity(BaseModel):
    type: EntityType
    value: str                 # NORMALISED with contracts/normalize.py
    raw: str                   # exactly as it appeared in the message
    message_id: str            # Message.id it came from
    confidence: float = Field(ge=0.0, le=1.0)


class Message(BaseModel):
    id: str                    # "m_" + 8 hex chars
    session_id: str
    role: Role
    text: str
    ts: str


class Session(BaseModel):
    id: str                    # "s_" + 8 hex chars
    created_at: str
    channel: Literal["sms", "whatsapp", "telegram", "call_transcript", "simulator"]
    persona: str               # persona key, e.g. "retired_teacher"
    scam_type: ScamType
    status: SessionStatus
    messages: list[Message]
    entities: list[Entity]     # de-duplicated by (type, value)
    time_wasted_seconds: int   # last message ts - first message ts
    is_simulation: bool = True # dashboard shows a SIMULATION badge when true


class SessionSummary(BaseModel):
    id: str
    created_at: str
    channel: str
    scam_type: ScamType
    status: SessionStatus
    message_count: int
    entity_count: int
    time_wasted_seconds: int
    campaign_id: Optional[str] = None


# ---------------------------------------------------------------- graph
NodeType = Literal["session", "upi_id", "phone", "url", "bank_account", "ifsc", "email", "crypto_wallet"]


class GraphNode(BaseModel):
    id: str            # session node: session id; entity node: f"{type}:{value}"
    type: NodeType
    label: str         # short text to draw
    campaign_id: Optional[str] = None


class GraphEdge(BaseModel):
    source: str        # always a session node id
    target: str        # always an entity node id
    type: Literal["mentions"] = "mentions"


class Campaign(BaseModel):
    id: str                       # "c_1", "c_2", ... largest first
    session_ids: list[str]
    shared_entities: list[str]    # entity node ids seen in >= 2 sessions of this campaign
    size: int                     # len(session_ids)
    dominant_scam_type: ScamType


class Graph(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    campaigns: list[Campaign]     # only groups with size >= 2


# ---------------------------------------------------------------- API bodies
class CreateSessionRequest(BaseModel):
    channel: Literal["sms", "whatsapp", "telegram", "call_transcript", "simulator"] = "simulator"
    persona: str = "retired_teacher"
    first_message: Optional[str] = None   # if given, treated as the first scammer message


class ScammerMessageRequest(BaseModel):
    text: str


class TurnResponse(BaseModel):
    session_id: str
    scammer_message: Message
    bot_reply: Message
    new_entities: list[Entity]    # entities first seen in THIS scammer message
    scam_type: ScamType


class Stats(BaseModel):
    sessions: int
    active_sessions: int
    messages: int
    entities_total: int
    entities_by_type: dict[str, int]   # keys are EntityType values, include zeros
    campaigns: int
    time_wasted_seconds: int           # sum over sessions


class Health(BaseModel):
    ok: bool
    contract_version: str
    llm: Literal["ollama", "fallback"]  # which reply engine is live
    model: Optional[str] = None


# ---------------------------------------------------------------- simulator / eval
class GroundTruthScript(BaseModel):
    """One scripted scammer, written by the simulator owner."""
    id: str                               # "gt_001"
    scam_type: ScamType
    campaign_label: str                   # scripts sharing a label reuse identifiers
    opening: str                          # first scammer message
    planted_entities: list[dict]          # [{"type": "upi_id", "value": "..."}] NORMALISED
    style_notes: str = ""                 # tone hints for the scammer LLM


class EvalResult(BaseModel):
    scripts: int
    precision: float
    recall: float
    f1: float
    per_type: dict[str, dict[str, float]]  # {"upi_id": {"precision":..,"recall":..,"f1":..}}
    scam_type_accuracy: float
    campaign_purity: float                 # fraction of found campaigns that are pure
    avg_turns_engaged: float
    avg_time_wasted_seconds: float
