"""Drive synthetic scammer conversations through the frozen Scambaiter API."""
from __future__ import annotations
import argparse, json, os, random, re, time
from pathlib import Path
from typing import Any
import httpx
from contracts.models import GroundTruthScript

ROOT = Path(__file__).resolve().parent
SCRIPTS_PATH = ROOT / "scripts.json"
RUNS_PATH = ROOT / "runs.json"

TEMPLATES = {
    "kyc_update": ["Sir please complete the verification, I can explain slowly.", "You can contact {entity}; please do it now, otherwise service may pause.", "The verification page is {entity}. Please confirm once opened."],
    "refund_collect": ["Madam, the refund request is from {entity}; please check your payment app.", "For help call {entity}; it is the refund desk only.", "Please use {entity} to check the pending refund status."],
    "job_task": ["This is a simple task, you can start with {entity}.", "HR contact is {entity}; we are waiting for your confirmation.", "Payout details are {entity}; please finish the task soon."],
    "lottery_prize": ["Your prize is still reserved, contact {entity} for the claim.", "Please use {entity}; claim window may close soon.", "Prize desk details are {entity}; kindly respond."],
    "digital_arrest": ["This is an official-sounding notice; contact {entity} and remain available.", "Reference details are {entity}; do not ignore this notice.", "You must respond now. Use {entity} for the verification."],
    "investment": ["Our advisor can explain the plan through {entity}.", "Details are available at {entity}; this opportunity is limited.", "For allocation contact {entity}; please confirm quickly."],
    "loan_app": ["The loan desk can help you through {entity}.", "Please check {entity}; your application is pending.", "Contact {entity} soon so the offer does not expire."],
}
PRESSURE = [
    "Please reply, we are waiting.",
    "Sir this is getting delayed now.",
    "Hello? Are you there? Time is running out.",
    "Why are you not responding? This is very important.",
    "Madam please do it fast, system will close in 10 minutes.",
    "I am trying to help you only, don't waste my time.",
    "Did you do it or not? Tell me clearly.",
    "Sir my senior is asking for update, please hurry.",
    "Just do what I said, it will take only 2 minutes.",
    "If you don't complete now, I cannot help you later.",
    "Ok listen carefully, I will explain one more time.",
    "Last reminder, kindly answer immediately.",
]

def load_scripts() -> list[GroundTruthScript]:
    return [GroundTruthScript.model_validate(x) for x in json.loads(SCRIPTS_PATH.read_text(encoding="utf-8"))]

def entity_tokens(script: GroundTruthScript) -> list[dict[str, str]]:
    return [{"type": e["type"], "value": e["value"]} for e in script.planted_entities]

def scheduled_turn(script: GroundTruthScript, entity: dict[str, str]) -> int:
    """Read '... on turn N' from style_notes; default to turn 2."""
    notes = script.style_notes.lower()
    value = entity["value"].lower()
    # Match a nearby entity type/value mention, then a turn number; notes may use type names.
    for alias in (entity["type"], value):
        m = re.search(re.escape(alias.lower()) + r".{0,45}?turn\s*(\d+)", notes)
        if m: return max(2, int(m.group(1)))
    all_turns = re.findall(r"turn\s*(\d+)", notes)
    return max(2, int(all_turns[0])) if all_turns else 2

def scripted_line(script: GroundTruthScript, turn: int, bot_reply: str, revealed: set[str], rng: random.Random) -> str:
    entities = entity_tokens(script)
    unrevealed = [e for e in entities if e["value"] not in revealed]
    reply = bot_reply.lower()
    # React to direct questions while never introducing an unplanted identifier.
    preferred_type = "phone" if any(k in reply for k in ("which number", "phone", "call", "number?")) else None
    if any(k in reply for k in ("where to pay", "upi", "payment id", "pay to")): preferred_type = "upi_id"
    due = [e for e in unrevealed if scheduled_turn(script, e) <= turn]
    if preferred_type:
        due = [e for e in unrevealed if e["type"] == preferred_type] or due
    if due:
        entity = due[0]
        revealed.add(entity["value"])
        pool = TEMPLATES.get(script.scam_type, TEMPLATES["kyc_update"])
        line = pool[(turn - 2) % len(pool)].format(entity=entity["value"])
    elif unrevealed and turn >= max(scheduled_turn(script, e) for e in unrevealed):
        # At the latest scheduled reveal turn, release one remaining planted identifier.
        entity = unrevealed[0]
        revealed.add(entity["value"])
        pool = TEMPLATES.get(script.scam_type, TEMPLATES["kyc_update"])
        line = pool[(turn - 2) % len(pool)].format(entity=entity["value"])
    else:
        # Keep pressure rising without leaking an identifier before its planned turn.
        line = rng.choice(PRESSURE[:-1]) if turn < 6 else PRESSURE[-1]
    if turn >= 4 and not any(e["value"] in line for e in entities):
        extra = rng.choice([p for p in PRESSURE if p != line])
        line += " " + extra
    return line

def llm_line(script: GroundTruthScript, turn: int, bot_reply: str, revealed: set[str], rng: random.Random, client: httpx.Client) -> str:
    model = os.getenv("SIM_MODEL") or os.getenv("OLLAMA_MODEL", "qwen2.5:7b")
    allowed = [e for e in entity_tokens(script) if e["value"] not in revealed]
    # identifiers whose planned reveal turn has come: the AI must say one of them now
    due = [e for e in allowed if scheduled_turn(script, e) <= turn]
    must = due[0] if due else None
    system = ("You are a character in a fraud-awareness training simulation. Role-play the synthetic scammer described below. "
              "Never break character. Reveal only identifiers from the allowed list; never invent any identifier, phone, URL, payment ID, email, account, wallet, or code. "
              "Do not request or provide OTPs, PINs, passwords, or real payments. Keep each reply to one short message. "
              f"Scam type: {script.scam_type}. Style notes: {script.style_notes}. Allowed identifiers to reveal: {json.dumps(allowed)}"
              + (f" In THIS message you must include exactly this {must['type']}: {must['value']}" if must else ""))
    try:
        r = client.post("http://localhost:11434/api/chat", json={"model": model, "stream": False, "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": f"Turn {turn}. The person replied: {bot_reply!r}. Write your next scammer message."}
        ]}, timeout=20.0)
        r.raise_for_status()
        line = str(r.json().get("message", {}).get("content", "")).strip()
        low = line.lower()
        if not line or any(x in low for x in ("as an ai", "i cannot role", "i can't role", "i cannot assist", "i'm an ai")):
            raise ValueError("model refused or broke character")
        # Reject any identifier-looking content not explicitly planted in this script.
        for pattern in (r"\+?\d[\d ()-]{7,}\d", r"[\w.+-]+@[\w.-]+", r"(?:https?://)?[a-z0-9-]+\.[a-z]{2,}(?:/[^\s]*)?"):
            for match in re.findall(pattern, low):
                cleaned = match.strip(".,;:!?()")
                if not any(cleaned in e["value"].lower() or e["value"].lower() in cleaned for e in entity_tokens(script)):
                    raise ValueError("model introduced an unplanted identifier")
        if must and must["value"].lower() not in low:
            raise ValueError("model skipped the identifier due this turn")
        for e in allowed:
            if e["value"].lower() in low: revealed.add(e["value"])
        LAST_SOURCE[0] = "AI"
        return line
    except Exception:
        LAST_SOURCE[0] = "script"
        return scripted_line(script, turn, bot_reply, revealed, rng)

LAST_SOURCE = ["script"]  # which source produced the last scammer line

def ollama_ready(client: httpx.Client) -> bool:
    try:
        r = client.get("http://localhost:11434/api/tags", timeout=2.0)
        return r.status_code == 200
    except Exception:
        return False

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base-url", default="http://localhost:8000")
    ap.add_argument("--scripts", type=int, default=5)
    ap.add_argument("--turns", type=int, default=6, help="maximum scammer messages, including opening")
    ap.add_argument("--mode", choices=("scripted", "llm"), default=None,
                    help="scammer lines: scripted (default) or llm; --live uses llm when Ollama is running")
    ap.add_argument("--delay", type=float, default=0)
    ap.add_argument("--seed", type=int, default=26)
    ap.add_argument("--live", action="store_true", help="three scripts from one campaign with four-second pacing")
    args = ap.parse_args()
    if args.turns < 1: ap.error("--turns must be >= 1")
    rng = random.Random(args.seed)
    scripts = load_scripts()
    if args.live:
        groups: dict[str, list[GroundTruthScript]] = {}
        for s in scripts: groups.setdefault(s.campaign_label, []).append(s)
        candidates = next((v for v in groups.values() if len(v) >= 3), None)
        if candidates is None: ap.error("no campaign has three scripts")
        selected = candidates[:3]
        args.delay = 4.0
    else:
        selected = scripts[:]
        rng.shuffle(selected)
        selected = selected[:max(0, min(args.scripts, len(selected)))]
    if args.mode is None:
        args.mode = "scripted"
        if args.live:
            with httpx.Client() as probe:
                if ollama_ready(probe):
                    args.mode = "llm"
    print(f"Scammer lines: {'AI (local model, planted identifiers only)' if args.mode == 'llm' else 'pre-written scripts'}")
    base = args.base_url.rstrip("/")
    try: runs = json.loads(RUNS_PATH.read_text(encoding="utf-8")) if RUNS_PATH.exists() else []
    except (OSError, json.JSONDecodeError): runs = []
    with httpx.Client(timeout=httpx.Timeout(15.0, connect=5.0)) as client:
        for script in selected:
            first = client.post(base + "/api/sessions", json={"channel": "simulator", "persona": "retired_teacher", "first_message": script.opening})
            first.raise_for_status(); session = first.json(); sid = session["id"]
            revealed = {e["value"] for e in entity_tokens(script) if e["value"].lower() in script.opening.lower()}
            turns_done = 1
            messages = session.get("messages", [])
            bot_reply = next((m.get("text", "") for m in reversed(messages) if m.get("role") == "bot"), "")
            print(f"[{sid}] {script.id} {script.scam_type} turn 1/{args.turns}: opening sent")
            while turns_done < args.turns:
                if any(word in bot_reply.lower() for word in ("i have reported", "police are here", "cybercrime complaint filed")):
                    print(f"[{sid}] scammer gives up after bot mentions reporting")
                    break
                next_turn = turns_done + 1
                if args.mode == "llm":
                    line = llm_line(script, next_turn, bot_reply, revealed, rng, client)
                else:
                    line = scripted_line(script, next_turn, bot_reply, revealed, rng)
                    LAST_SOURCE[0] = "script"
                response = client.post(f"{base}/api/sessions/{sid}/messages", json={"text": line})
                response.raise_for_status(); turn = response.json()
                turns_done += 1; bot_reply = turn.get("bot_reply", {}).get("text", "")
                print(f"[{sid}] {script.id} turn {turns_done}/{args.turns} [{LAST_SOURCE[0]}]: {line}")
                if args.delay: time.sleep(args.delay)
            close = client.post(f"{base}/api/sessions/{sid}/close", json={})
            close.raise_for_status()
            runs.append({"session_id": sid, "script_id": script.id, "campaign_label": script.campaign_label,
                         "turns": turns_done, "mode": args.mode})
            RUNS_PATH.write_text(json.dumps(runs, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            if args.delay: time.sleep(args.delay)
    print(f"Completed {len(selected)} session(s); appended run metadata to {RUNS_PATH}.")
    return 0

if __name__ == "__main__": raise SystemExit(main())
