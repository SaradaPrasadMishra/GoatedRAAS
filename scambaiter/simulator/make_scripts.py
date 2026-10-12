"""Validate simulator/scripts.json against the frozen contract and normalisers."""
from __future__ import annotations
import json
from collections import Counter, defaultdict
from pathlib import Path
from pydantic import TypeAdapter, ValidationError
from contracts.models import GroundTruthScript
from contracts.normalize import normalise

ROOT = Path(__file__).resolve().parent
PATH = ROOT / "scripts.json"

def main() -> int:
    try:
        raw = json.loads(PATH.read_text(encoding="utf-8"))
        scripts = TypeAdapter(list[GroundTruthScript]).validate_python(raw)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        print(f"Invalid scripts.json: {exc}")
        return 1
    types = Counter(s.scam_type for s in scripts)
    campaigns = defaultdict(list)
    errors = []
    for s in scripts:
        campaigns[s.campaign_label].append(s)
        if not 2 <= len(s.planted_entities) <= 4:
            errors.append(f"{s.id}: expected 2–4 planted entities")
        for e in s.planted_entities:
            try:
                if normalise(e["type"], e["value"]) != e["value"]:
                    errors.append(f"{s.id}: {e['type']} value is not normalised: {e['value']}")
            except (KeyError, TypeError) as exc:
                errors.append(f"{s.id}: invalid planted entity {e!r}: {exc}")
    if len(scripts) < 30: errors.append(f"expected at least 30 scripts, found {len(scripts)}")
    expected = {"kyc_update", "refund_collect", "job_task", "lottery_prize", "digital_arrest", "investment", "loan_app"}
    if not expected.issubset(types): errors.append(f"missing scam types: {sorted(expected - set(types))}")
    repeated = sum(len(v) >= 2 for v in campaigns.values())
    if repeated < 6: errors.append(f"expected 6+ repeated campaign labels, found {repeated}")
    print("PER-SCAM-TYPE COUNTS")
    print(f"{'scam_type':<20} {'scripts':>7}")
    for key, count in sorted(types.items()): print(f"{key:<20} {count:>7}")
    print("\nPER-CAMPAIGN COUNTS")
    print(f"{'campaign_label':<24} {'scripts':>7} {'scam types':>12}")
    for label, group in sorted(campaigns.items()):
        print(f"{label:<24} {len(group):>7} {len({s.scam_type for s in group}):>12}")
    if errors:
        print("\nVALIDATION ERRORS")
        for err in errors: print(f"- {err}")
        return 1
    print(f"\nPASS: {len(scripts)} valid scripts; {len(campaigns)} campaign labels.")
    return 0

if __name__ == "__main__": raise SystemExit(main())
