"""
Fallbacks used ONLY if extractor/ or report/ fail to import, so the backend
always starts. The real modules from P2 / P3 replace these automatically.
"""
from __future__ import annotations

import html
import re
from collections import Counter

from contracts.models import Campaign, Entity, Graph, GraphEdge, GraphNode, ScamType, Session
from contracts.normalize import clean_text, node_id, normalise

_PATTERNS = [
    ("email", r"[\w.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z.]{2,}"),
    ("upi_id", r"[\w.-]{2,}@[a-zA-Z]{2,}(?![\w.]*\.[a-zA-Z])"),
    ("url", r"(?:https?://|www\.)\S+|\b[a-zA-Z0-9-]+\.(?:in|com|app|ly|xyz|online|info|net|org|top)(?:/\S*)?"),
    ("phone", r"(?<!\d)(?:\+?91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)"),
]


def extract_entities(text: str, message_id: str) -> list[Entity]:
    t = clean_text(text)
    out, spans, seen = [], [], set()
    for typ, pat in _PATTERNS:
        for m in re.finditer(pat, t):
            if any(m.start() < b and a < m.end() for a, b in spans):
                continue
            raw = m.group().rstrip(".,;:!?)")
            val = normalise(typ, raw)
            if (typ, val) in seen:
                continue
            seen.add((typ, val)); spans.append(m.span())
            out.append(Entity(type=typ, value=val, raw=raw if raw in text else text[m.start():m.start() + len(raw)],
                              message_id=message_id, confidence=0.7))
    return out


def classify_scam(text: str) -> ScamType:
    s = text.lower()
    for typ, words in [("kyc_update", ["kyc"]), ("refund_collect", ["refund", "collect"]), ("job_task", ["task", "job"]),
                       ("lottery_prize", ["lottery", "prize", "won"]), ("digital_arrest", ["police", "fir", "cbi"]),
                       ("investment", ["invest", "crypto", "double"]), ("loan_app", ["loan"])]:
        if any(w in s for w in words):
            return typ
    return "other" if extract_entities(text, "m") else "unknown"


def build_graph(sessions: list[Session]) -> Graph:
    import networkx as nx
    g = nx.Graph()
    ents = {}
    sid = {s.id: s for s in sessions}
    for s in sessions:
        g.add_node(s.id)
        for e in s.entities:
            n = node_id(e.type, e.value); ents[n] = e; g.add_edge(s.id, n)
    comps = sorted([c for c in nx.connected_components(g) if sum(x in sid for x in c) >= 2],
                   key=lambda c: -sum(x in sid for x in c))
    cmap, camps = {}, []
    for i, c in enumerate(comps, 1):
        ss = sorted(x for x in c if x in sid)
        for x in c:
            cmap[x] = f"c_{i}"
        camps.append(Campaign(id=f"c_{i}", session_ids=ss, size=len(ss),
                              shared_entities=sorted(n for n in c if n not in sid and g.degree(n) >= 2),
                              dominant_scam_type=Counter(sid[x].scam_type for x in ss).most_common(1)[0][0]))
    nodes = [GraphNode(id=s.id, type="session", label=s.scam_type, campaign_id=cmap.get(s.id)) for s in sessions]
    nodes += [GraphNode(id=n, type=e.type, label=e.value, campaign_id=cmap.get(n)) for n, e in ents.items()]
    edges = [GraphEdge(source=a if a in sid else b, target=b if a in sid else a) for a, b in g.edges]
    return Graph(nodes=nodes, edges=edges, campaigns=camps)


def render_report(session: Session, graph: Graph) -> str:
    rows = "".join(f"<li>{html.escape(e.type)}: {html.escape(e.value)}</li>" for e in session.entities)
    return (f"<!doctype html><html><body><h1>SIMULATION - Scam Evidence Report {html.escape(session.id)}</h1>"
            f"<ul>{rows}</ul><p>Report at https://cybercrime.gov.in or call 1930.</p></body></html>")
