"""
CONTRACT CHECKER - run from the repo root. Needs only `pip install pydantic`.

    python tools/check_contract.py extractor     # Gemini A: entity extraction + scam type
    python tools/check_contract.py graph         # Gemini A: campaign linking
    python tools/check_contract.py report        # Gemini B: evidence report
    python tools/check_contract.py dashboard     # Gemini B: static checks on dashboard/
    python tools/check_contract.py bot           # Claude:   reply engine (fallback mode)
    python tools/check_contract.py simulator     # ChatGPT:  ground-truth scripts
    python tools/check_contract.py api [URL]     # anyone:   live server (mock or real), default http://localhost:8000
    python tools/check_contract.py all [URL]     # everything; this is the merge gate

Exit code 0 = PASS. Paste any FAIL lines straight back into your AI chat.
"""
from __future__ import annotations

import importlib, json, os, re, sys, traceback, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from pydantic import TypeAdapter, ValidationError  # noqa: E402
from contracts import models as M                  # noqa: E402
from contracts.normalize import node_id            # noqa: E402

DATA = os.path.join(ROOT, "contracts", "sample_data")
load = lambda n: json.load(open(os.path.join(DATA, n), encoding="utf-8"))
RESULTS: list[tuple[bool, str]] = []


def ok(cond, msg):
    RESULTS.append((bool(cond), msg))
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    return bool(cond)


def imp(mod, attr):
    try:
        return getattr(importlib.import_module(mod), attr)
    except Exception as e:
        ok(False, f"cannot import {mod}.{attr}: {type(e).__name__}: {e}")
        return None


def validate(model, obj, what):
    try:
        TypeAdapter(model).validate_python(obj.model_dump() if hasattr(obj, "model_dump") else obj)
        return ok(True, f"{what} matches contract")
    except ValidationError as e:
        return ok(False, f"{what} does NOT match contract:\n{e}")


def sessions():
    return [M.Session(**s) for s in load("sessions.json")]


# ------------------------------------------------------------------ extractor
def check_extractor():
    print("\n[extractor] extractor/extract.py")
    extract = imp("extractor.extract", "extract_entities")
    classify = imp("extractor.extract", "classify_scam")
    if not extract or not classify:
        return
    cases = load("extraction_cases.json")["cases"]
    tp = fp = fn = 0
    type_hits = 0
    for c in cases:
        try:
            got = extract(c["text"], "m_test0001")
        except Exception:
            ok(False, f"{c['id']}: extract_entities crashed\n{traceback.format_exc()}")
            continue
        validate(list[M.Entity], got, f"{c['id']}: return value")
        gotset = {(e.type, e.value) for e in got}
        exp = {(e["type"], e["value"]) for e in c["expected_entities"]}
        tp += len(gotset & exp); fp += len(gotset - exp); fn += len(exp - gotset)
        for e in got:
            if e.raw not in c["text"]:
                ok(False, f"{c['id']}: raw {e.raw!r} is not a substring of the message")
        if gotset != exp:
            print(f"        {c['id']}: missing {sorted(exp - gotset)}  extra {sorted(gotset - exp)}")
        st = classify(c["text"])
        if st == c["expected_scam_type"]:
            type_hits += 1
        else:
            print(f"        {c['id']}: scam type {st!r}, expected {c['expected_scam_type']!r}")
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    ok(f1 >= 0.90, f"entity F1 on sample cases = {f1:.2f} (precision {p:.2f}, recall {r:.2f}); need >= 0.90")
    ok(type_hits >= len(cases) - 2, f"scam type correct on {type_hits}/{len(cases)}; need >= {len(cases) - 2}")


# ------------------------------------------------------------------ graph
def check_graph():
    print("\n[graph] extractor/campaigns.py")
    build = imp("extractor.campaigns", "build_graph")
    if not build:
        return
    S = sessions()
    try:
        g = build(S)
    except Exception:
        return ok(False, "build_graph crashed\n" + traceback.format_exc())
    if not validate(M.Graph, g, "build_graph return value"):
        return
    g = M.Graph.model_validate(g.model_dump() if hasattr(g, "model_dump") else g)
    ids = {n.id for n in g.nodes}
    ok(all(s.id in ids for s in S), "every session has a node")
    want = {node_id(e.type, e.value) for s in S for e in s.entities}
    ok(want <= ids, "every entity has a node with id 'type:value'")
    ok(all(e.source in ids and e.target in ids for e in g.edges), "every edge points at existing nodes")
    ok(len(g.campaigns) == 1, f"exactly 1 campaign in sample data (got {len(g.campaigns)})")
    if g.campaigns:
        c = g.campaigns[0]
        ok(set(c.session_ids) == {"s_a1b2c3d4", "s_e5f6a7b8"}, f"campaign links the two refund sessions (got {c.session_ids})")
        ok("phone:+919876543210" in c.shared_entities, "shared phone listed in shared_entities")
        ok(c.id == "c_1" and c.size == 2, "campaign id 'c_1', size 2")
    lone = next((n for n in g.nodes if n.id == "s_c9d0e1f2"), None)
    ok(lone is not None and lone.campaign_id is None, "unlinked KYC session has campaign_id None")
    try:
        empty = build([])
        validate(M.Graph, empty, "build_graph([]) (empty input)")
    except Exception:
        ok(False, "build_graph([]) crashed")


# ------------------------------------------------------------------ report
def check_report():
    print("\n[report] report/render.py")
    render = imp("report.render", "render_report")
    if not render:
        return
    S = sessions()
    g = M.Graph(**load("graph.json"))
    try:
        html = render(S[0], g)
    except Exception:
        return ok(False, "render_report crashed\n" + traceback.format_exc())
    ok(isinstance(html, str) and html.lstrip().lower().startswith(("<!doctype html", "<html")), "returns a full HTML document")
    if not isinstance(html, str):
        return
    ok(S[0].id in html, "contains the session id")
    ok(all(e.value in html for e in S[0].entities), "lists every extracted entity value")
    ok("SIMULATION" in html, "shows the SIMULATION label")
    ok("c_1" in html or "campaign" in html.lower(), "mentions the linked campaign")
    ok("cybercrime.gov.in" in html and "1930" in html, "tells the reader to report at cybercrime.gov.in / call 1930")
    ok(not re.search(r"<script[^>]+src=\"https?://", html), "no external scripts (must work offline / print to PDF)")
    try:
        render(S[2], g)
        ok(True, "works for a session with no campaign")
    except Exception:
        ok(False, "crashes for a session with no campaign\n" + traceback.format_exc())


# ------------------------------------------------------------------ dashboard
def check_dashboard():
    print("\n[dashboard] dashboard/")
    path = os.path.join(ROOT, "dashboard", "index.html")
    if not ok(os.path.exists(path), "dashboard/index.html exists"):
        return
    src = open(path, encoding="utf-8").read()
    for f in os.listdir(os.path.join(ROOT, "dashboard")):
        if f.endswith(".js"):
            src += open(os.path.join(ROOT, "dashboard", f), encoding="utf-8").read()
    for ep in ["/api/sessions", "/api/graph", "/api/stats"]:
        ok(ep in src, f"calls {ep}")
    ok("API_BASE" in src, "uses a configurable API_BASE")
    ok("SIMULATION" in src, "shows a SIMULATION badge")
    ok("localhost:5173" not in src, "no hard-coded dev-server URL")


# ------------------------------------------------------------------ bot
def check_bot():
    print("\n[bot] backend/bot.py (forced fallback mode, no Ollama needed)")
    os.environ["SCAMBAITER_LLM"] = "fallback"
    gen = imp("backend.bot", "generate_reply")
    personas = imp("backend.bot", "PERSONAS")
    if not gen:
        return
    s = sessions()[0]
    try:
        reply = gen(s, s.persona)
    except Exception:
        return ok(False, "generate_reply crashed\n" + traceback.format_exc())
    ok(isinstance(reply, str) and 3 < len(reply) < 400, "returns a short string")
    ok(not re.search(r"\d{4,}", reply or ""), "never outputs 4+ digit runs (no OTP, PIN, account numbers)")
    if personas:
        ok(isinstance(personas, dict) and len(personas) >= 2 and "retired_teacher" in personas, "PERSONAS has >= 2 entries incl. retired_teacher")
    leaky = M.Session(**{**s.model_dump(), "messages": s.model_dump()["messages"] + [
        {"id": "m_x", "session_id": s.id, "role": "scammer", "text": "Tell me the OTP 6 digit now", "ts": s.messages[-1].ts}]})
    r2 = gen(leaky, s.persona)
    ok(not re.search(r"\d{4,}", r2), "does not give an OTP when asked for one")


# ------------------------------------------------------------------ simulator
def check_simulator():
    print("\n[simulator] simulator/scripts.json")
    path = os.path.join(ROOT, "simulator", "scripts.json")
    if not ok(os.path.exists(path), "simulator/scripts.json exists"):
        return
    from contracts.normalize import normalise
    data = json.load(open(path, encoding="utf-8"))
    validate(list[M.GroundTruthScript], data, "scripts.json")
    scripts = [M.GroundTruthScript(**d) for d in data] if isinstance(data, list) else []
    ok(len(scripts) >= 20, f"at least 20 scripts (got {len(scripts)})")
    types = {s.scam_type for s in scripts}
    ok(len(types) >= 5, f"covers >= 5 scam types (got {len(types)})")
    from collections import Counter
    labels = Counter(s.campaign_label for s in scripts)
    ok(sum(1 for v in labels.values() if v >= 2) >= 3, "at least 3 campaign_labels used by 2+ scripts")
    bad = [(s.id, e) for s in scripts for e in s.planted_entities if normalise(e["type"], e["value"]) != e["value"]]
    ok(not bad, f"all planted values already normalised {bad[:3] if bad else ''}")
    ev = os.path.join(ROOT, "simulator", "last_eval.json")
    if os.path.exists(ev):
        validate(M.EvalResult, json.load(open(ev)), "simulator/last_eval.json")


# ------------------------------------------------------------------ live API
def http(method, url, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        raw = r.read().decode()
        return r.headers.get("Content-Type", ""), raw


def check_api(base):
    print(f"\n[api] {base}")
    try:
        _, h = http("GET", base + "/api/health")
    except Exception as e:
        return ok(False, f"server not reachable at {base}: {e}")
    validate(M.Health, json.loads(h), "GET /api/health")
    _, s = http("POST", base + "/api/sessions", {"channel": "simulator", "persona": "retired_teacher"})
    s = json.loads(s)
    if not validate(M.Session, s, "POST /api/sessions"):
        return
    _, t = http("POST", f"{base}/api/sessions/{s['id']}/messages",
                {"text": "Sir refund approved, accept collect request from checker.test@okaxis"})
    t = json.loads(t)
    if validate(M.TurnResponse, t, "POST /api/sessions/{id}/messages"):
        ok(any(e["value"] == "checker.test@okaxis" for e in t["new_entities"]), "turn extracted the UPI id")
        ok(t["bot_reply"]["role"] == "bot" and t["bot_reply"]["text"], "bot replied")
    _, full = http("GET", f"{base}/api/sessions/{s['id']}")
    validate(M.Session, json.loads(full), "GET /api/sessions/{id}")
    _, lst = http("GET", base + "/api/sessions")
    validate(list[M.SessionSummary], json.loads(lst), "GET /api/sessions")
    _, g = http("GET", base + "/api/graph")
    validate(M.Graph, json.loads(g), "GET /api/graph")
    _, st = http("GET", base + "/api/stats")
    st = json.loads(st)
    if validate(M.Stats, st, "GET /api/stats"):
        ok(set(st["entities_by_type"]) == set(M.EntityType.__args__), "stats.entities_by_type has every entity type")
    ct, rep = http("GET", f"{base}/api/sessions/{s['id']}/report")
    ok("text/html" in ct and "SIMULATION" in rep, "GET /api/sessions/{id}/report returns HTML with SIMULATION")
    _, c = http("POST", f"{base}/api/sessions/{s['id']}/close", {})
    ok(json.loads(c).get("status") == "closed", "POST /api/sessions/{id}/close closes it")


# ------------------------------------------------------------------ main
CHECKS = {"extractor": check_extractor, "graph": check_graph, "report": check_report,
          "dashboard": check_dashboard, "bot": check_bot, "simulator": check_simulator}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in [*CHECKS, "api", "all"]:
        print(__doc__); sys.exit(2)
    what = sys.argv[1]
    url = (sys.argv[2] if len(sys.argv) > 2 else "http://localhost:8000").rstrip("/")
    print(f"Scambaiter contract v{M.CONTRACT_VERSION}")
    if what == "all":
        for fn in CHECKS.values():
            fn()
        check_api(url)
    elif what == "api":
        check_api(url)
    else:
        CHECKS[what]()
    fails = sum(1 for good, _ in RESULTS if not good)
    print(f"\n{'PASS' if not fails else 'FAIL'}: {len(RESULTS) - fails} passed, {fails} failed")
    sys.exit(1 if fails else 0)
