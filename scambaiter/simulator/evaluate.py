"""Evaluate recorded simulator runs against the frozen API and Pydantic contract."""
from __future__ import annotations
import argparse, json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
import httpx
import os
from contracts.models import EvalResult, GroundTruthScript
from contracts.normalize import normalise

# Only needed when the backend runs with --strict; local tools are trusted otherwise.
API_HEADERS = {"X-API-Key": os.environ["SCAMBAITER_API_KEY"]} if os.environ.get("SCAMBAITER_API_KEY") else {}

ROOT = Path(__file__).resolve().parent
RUNS_PATH = ROOT / "runs.json"
SCRIPTS_PATH = ROOT / "scripts.json"
OUT_PATH = ROOT / "last_eval.json"
ENTITY_TYPES = ("upi_id", "phone", "url", "bank_account", "ifsc", "email", "crypto_wallet")

def f1(p: float, r: float) -> float: return 2*p*r/(p+r) if p+r else 0.0

def metric(tp: int, fp: int, fn: int) -> dict[str, float]:
    p = tp/(tp+fp) if tp+fp else 0.0
    r = tp/(tp+fn) if tp+fn else 0.0
    return {"precision": p, "recall": r, "f1": f1(p,r)}

def truth_for(script: GroundTruthScript, session: dict[str, Any]) -> set[tuple[str, str]]:
    # Only count planted identifiers which actually appear in at least one scammer message.
    scammer_text = "\n".join(m.get("text", "") for m in session.get("messages", []) if m.get("role") == "scammer")
    found = set()
    for e in script.planted_entities:
        typ, value = e.get("type"), e.get("value")
        if typ and value and value.lower() in scammer_text.lower():
            # Confirm the value is canonical under the project's normaliser.
            try: canonical = normalise(typ, value)
            except (KeyError, TypeError): continue
            if canonical == value: found.add((typ, value))
    return found

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base-url", default="http://localhost:8000")
    ap.add_argument("--md", action="store_true", help="also write pitch/metrics.md")
    args = ap.parse_args(); base = args.base_url.rstrip("/")
    if not RUNS_PATH.exists():
        print(f"No runs found at {RUNS_PATH}. Run simulator.run first."); return 1
    runs = json.loads(RUNS_PATH.read_text(encoding="utf-8"))
    scripts = {s.id: s for s in (GroundTruthScript.model_validate(x) for x in json.loads(SCRIPTS_PATH.read_text(encoding="utf-8")))}
    if not runs:
        print("runs.json is empty; run simulator.run first."); return 1
    sessions: dict[str, dict[str, Any]] = {}
    with httpx.Client(timeout=httpx.Timeout(15.0, connect=5.0), headers=API_HEADERS) as client:
        for run in runs:
            sid = run["session_id"]
            r = client.get(f"{base}/api/sessions/{sid}"); r.raise_for_status(); sessions[sid] = r.json()
        r = client.get(base + "/api/graph"); r.raise_for_status(); graph = r.json()
    total_tp = total_fp = total_fn = 0
    type_counts = {t: [0,0,0] for t in ENTITY_TYPES}
    type_hits = 0; valid_type_runs = 0; turns = []; wasted = []
    truths: dict[str, set[tuple[str,str]]] = {}; predictions: dict[str, set[tuple[str,str]]] = {}
    label_by_session = {}
    for run in runs:
        sid = run["session_id"]; script = scripts.get(run.get("script_id")); session = sessions[sid]
        if script is None: continue
        label_by_session[sid] = run.get("campaign_label", script.campaign_label)
        gt = truth_for(script, session)
        pred = {(e.get("type"), e.get("value")) for e in session.get("entities", [])}
        truths[sid] = gt; predictions[sid] = pred
        tp_set = gt & pred; fp_set = pred - gt; fn_set = gt - pred
        total_tp += len(tp_set); total_fp += len(fp_set); total_fn += len(fn_set)
        for typ in ENTITY_TYPES:
            type_counts[typ][0] += sum(1 for x in tp_set if x[0] == typ)
            type_counts[typ][1] += sum(1 for x in fp_set if x[0] == typ)
            type_counts[typ][2] += sum(1 for x in fn_set if x[0] == typ)
        if session.get("scam_type") == script.scam_type: type_hits += 1
        valid_type_runs += 1
        turns.append(sum(1 for m in session.get("messages", []) if m.get("role") == "scammer"))
        wasted.append(float(session.get("time_wasted_seconds", 0)))
    overall = metric(total_tp,total_fp,total_fn)
    per_type = {t: metric(*type_counts[t]) for t in ENTITY_TYPES}
    campaigns = graph.get("campaigns", [])
    pure = 0
    for campaign in campaigns:
        labels = {label_by_session[sid] for sid in campaign.get("session_ids", []) if sid in label_by_session}
        if labels and len(labels) == 1: pure += 1
    campaign_purity = pure/len(campaigns) if campaigns else 0.0
    label_sessions: dict[str, set[str]] = defaultdict(set)
    for sid, label in label_by_session.items(): label_sessions[label].add(sid)
    true_multi = {label: ids for label, ids in label_sessions.items() if len(ids) >= 2}
    found_multi = 0
    for label, ids in true_multi.items():
        if any(ids.issubset(set(c.get("session_ids", []))) for c in campaigns): found_multi += 1
    campaign_recall = found_multi/len(true_multi) if true_multi else 0.0
    result = EvalResult(scripts=len(label_by_session), precision=overall["precision"], recall=overall["recall"], f1=overall["f1"],
                        per_type=per_type, scam_type_accuracy=type_hits/valid_type_runs if valid_type_runs else 0.0,
                        campaign_purity=campaign_purity, avg_turns_engaged=sum(turns)/len(turns) if turns else 0.0,
                        avg_time_wasted_seconds=sum(wasted)/len(wasted) if wasted else 0.0)
    OUT_PATH.write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")
    print("ENTITY EXTRACTION (micro metrics)")
    print(f"{'scope':<20} {'precision':>10} {'recall':>10} {'F1':>10}")
    print(f"{'overall':<20} {result.precision:>10.3f} {result.recall:>10.3f} {result.f1:>10.3f}")
    for typ, vals in per_type.items(): print(f"{typ:<20} {vals['precision']:>10.3f} {vals['recall']:>10.3f} {vals['f1']:>10.3f}")
    print("\nSESSION / CAMPAIGN METRICS")
    print(f"Scripts evaluated:          {result.scripts}")
    print(f"Scam-type accuracy:         {result.scam_type_accuracy:.3f}")
    print(f"Campaign purity:            {result.campaign_purity:.3f}")
    print(f"Campaign recall:             {campaign_recall:.3f} ({found_multi}/{len(true_multi)} true multi-session campaign(s))")
    print(f"Average scammer turns:      {result.avg_turns_engaged:.2f}")
    print(f"Average time wasted (sec):  {result.avg_time_wasted_seconds:.2f}")
    print(f"Saved contract-valid EvalResult to {OUT_PATH}")
    if args.md:
        md_path = ROOT.parent / "pitch" / "metrics.md"
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md = ["# Latest simulator metrics", "", "Generated by `python -m simulator.evaluate --md`. Mock-server values are expected to be low because its extractor is intentionally simplistic.", "",
              "| Metric | Result |", "|---|---:|", f"| Scripts evaluated | {result.scripts} |", f"| Entity precision (micro) | {result.precision:.3f} |", f"| Entity recall (micro) | {result.recall:.3f} |", f"| Entity F1 (micro) | {result.f1:.3f} |", f"| Scam-type accuracy | {result.scam_type_accuracy:.3f} |", f"| Campaign purity | {result.campaign_purity:.3f} |", f"| Campaign recall | {campaign_recall:.3f} |", f"| Average scammer turns | {result.avg_turns_engaged:.2f} |", f"| Average time wasted (seconds) | {result.avg_time_wasted_seconds:.2f} |", "", "**Interpretation:** these are measured results from the current backend/API, not promised product performance. Replace with a fresh run before presenting."]
        md_path.write_text("\n".join(md)+"\n", encoding="utf-8")
        print(f"Wrote {md_path}")
    return 0

if __name__ == "__main__": raise SystemExit(main())
