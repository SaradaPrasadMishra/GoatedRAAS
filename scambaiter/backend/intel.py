"""
Real-world outputs: an NCRP-ready complaint (cybercrime.gov.in / 1930), a signed mule-account alert a
bank fraud desk can act on, and the identifier lookup behind the public API. Offline: the bank tables
below are built in (IFSC prefixes and UPI handles of the larger Indian banks and apps).
"""
from __future__ import annotations

import hashlib
import html
import re

from contracts.models import Graph, Session

# First 4 letters of an IFSC code -> bank
IFSC_BANKS = {
    "SBIN": "State Bank of India", "HDFC": "HDFC Bank", "ICIC": "ICICI Bank", "UTIB": "Axis Bank",
    "PUNB": "Punjab National Bank", "BARB": "Bank of Baroda", "CNRB": "Canara Bank", "UBIN": "Union Bank of India",
    "KKBK": "Kotak Mahindra Bank", "YESB": "Yes Bank", "IDIB": "Indian Bank", "IOBA": "Indian Overseas Bank",
    "BKID": "Bank of India", "MAHB": "Bank of Maharashtra", "INDB": "IndusInd Bank", "FDRL": "Federal Bank",
    "IDFB": "IDFC FIRST Bank", "UCBA": "UCO Bank", "CBIN": "Central Bank of India", "PSIB": "Punjab & Sind Bank",
    "KVBL": "Karur Vysya Bank", "TMBL": "Tamilnad Mercantile Bank", "CIUB": "City Union Bank", "SIBL": "South Indian Bank",
    "KARB": "Karnataka Bank", "RATN": "RBL Bank", "AUBL": "AU Small Finance Bank", "ESFB": "Equitas Small Finance Bank",
    "AIRP": "Airtel Payments Bank", "PYTM": "Paytm Payments Bank", "IPOS": "India Post Payments Bank",
    "FINO": "Fino Payments Bank", "JAKA": "Jammu & Kashmir Bank", "DBSS": "DBS Bank India",
}

# UPI handle (after the @) -> app and the bank that runs it
UPI_HANDLES = {
    "okaxis": ("Google Pay", "Axis Bank"), "okhdfcbank": ("Google Pay", "HDFC Bank"),
    "okicici": ("Google Pay", "ICICI Bank"), "oksbi": ("Google Pay", "State Bank of India"),
    "ybl": ("PhonePe", "Yes Bank"), "ibl": ("PhonePe", "ICICI Bank"), "axl": ("PhonePe", "Axis Bank"),
    "paytm": ("Paytm", "Paytm Payments Bank"), "ptyes": ("Paytm", "Yes Bank"), "ptaxis": ("Paytm", "Axis Bank"),
    "pthdfc": ("Paytm", "HDFC Bank"), "ptsbi": ("Paytm", "State Bank of India"),
    "apl": ("Amazon Pay", "Axis Bank"), "yapl": ("Amazon Pay", "Yes Bank"), "upi": ("BHIM", "NPCI"),
    "sbi": ("SBI", "State Bank of India"), "hdfcbank": ("HDFC", "HDFC Bank"), "icici": ("iMobile", "ICICI Bank"),
    "axisbank": ("Axis", "Axis Bank"), "kotak": ("Kotak", "Kotak Mahindra Bank"), "pnb": ("PNB", "Punjab National Bank"),
    "barodampay": ("Bank of Baroda", "Bank of Baroda"), "fbl": ("Federal", "Federal Bank"),
    "freecharge": ("Freecharge", "Axis Bank"), "jupiteraxis": ("Jupiter", "Axis Bank"), "slc": ("slice", "SBM Bank"),
    "fam": ("FamPay", "IDFC FIRST Bank"), "waaxis": ("WhatsApp Pay", "Axis Bank"), "wahdfcbank": ("WhatsApp Pay", "HDFC Bank"),
}

# Our scam type -> NCRP "Online Financial Fraud" sub-category (closest match; the officer can change it)
NCRP_SUBCATEGORY = {
    "kyc_update": "Fraud Call/Vishing",
    "refund_collect": "UPI Related Frauds",
    "job_task": "Online Job Fraud",
    "lottery_prize": "Advance Fee Fraud",
    "digital_arrest": "Impersonation of Govt. Servant",
    "investment": "Investment Scam/Trading Scam",
    "loan_app": "Online Loan Fraud",
}
PLATFORM = {"sms": "SMS", "whatsapp": "WhatsApp", "telegram": "Telegram", "call_transcript": "Phone call",
            "simulator": "Simulator", "email": "Email"}


def bank_for(entity_type: str, value: str) -> str | None:
    if entity_type == "ifsc":
        return IFSC_BANKS.get(value[:4].upper())
    if entity_type == "upi_id" and "@" in value:
        app = UPI_HANDLES.get(value.rsplit("@", 1)[1].lower())
        return f"{app[1]} (via {app[0]})" if app else None
    return None


def bank_accounts(s: Session) -> list[dict]:
    """Pair each account number with the IFSC mentioned closest after it (same message first)."""
    accts = [e for e in s.entities if e.type == "bank_account"]
    ifscs = [e for e in s.entities if e.type == "ifsc"]
    out = []
    for a in accts:
        same = [i for i in ifscs if i.message_id == a.message_id]
        ifsc = (same or ifscs or [None])[0]
        out.append({"account": a.value, "ifsc": ifsc.value if ifsc else None,
                    "bank": bank_for("ifsc", ifsc.value) if ifsc else None})
    return out


def transcript_sha256(s: Session) -> str:
    lines = [f"{m.ts}|{m.role}|{m.text}" for m in s.messages]
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------- NCRP complaint
def complaint(s: Session, g: Graph, analysis: dict, seal: dict, source: dict) -> dict:
    """Fields in the order the 'Report Financial Fraud' form on cybercrime.gov.in asks for them."""
    ents = {t: [e.value for e in s.entities if e.type == t] for t in
            ("phone", "email", "upi_id", "url", "crypto_wallet")}
    camp = next((c for c in g.campaigns if s.id in c.session_ids), None)
    scam_msgs = [m for m in s.messages if m.role == "scammer"]
    src = source.get("source")
    platform = PLATFORM["email"] if src in ("gmail", "eml_upload") else "SMS" if src == "sms_gateway" else PLATFORM.get(s.channel, s.channel)
    first = s.messages[0].ts if s.messages else s.created_at
    pay = f"to pay {_rupees(analysis.get('demanded', 0))}" if analysis.get("demanded") else "to make a payment"
    desc = (f"I received {len(scam_msgs)} message(s) on {platform} from a person who "
            f"{'pretended to be from a bank, company or government office and ' if 'Fake authority' in analysis.get('flags', []) else ''}"
            f"asked me {pay if analysis.get('pay_asked') else 'to take action'}"
            f"{' and to share an OTP/PIN' if analysis.get('otp_asked') else ''}. "
            f"Warning signs: {', '.join(analysis.get('flags', [])) or 'none detected'}. "
            f"I did not share any OTP, PIN or bank details and did not send money. "
            f"The scammer used the identifiers listed below. "
            + (f"The same identifiers appear in {camp.size - 1} other reported case(s), which suggests an organised group. " if camp else "")
            + "The full transcript is attached with a tamper-evident seal.")
    return {
        "schema": "scambaiter.ncrp-complaint.v1",
        "portal": "https://cybercrime.gov.in  (National Cyber Crime Reporting Portal) · helpline 1930",
        "simulation": s.is_simulation,
        "complaint_category": "Online Financial Fraud",
        "sub_category": NCRP_SUBCATEGORY.get(s.scam_type, "Any Other Online Financial Fraud"),
        "incident": {"date_time_utc": first, "platform": platform, "scam_type": s.scam_type,
                     "money_lost_inr": 0, "money_demanded_inr": analysis.get("demanded", 0)},
        "suspect": {
            "mobile_numbers": ents["phone"], "email_ids": ents["email"], "upi_ids": [
                {"upi_id": u, "bank": bank_for("upi_id", u)} for u in ents["upi_id"]],
            "bank_accounts": bank_accounts(s), "websites": ents["url"], "crypto_wallets": ents["crypto_wallet"],
        },
        "transactions": [],
        "description": desc,
        "linked_cases": {"campaign": camp.id, "case_ids": [x for x in camp.session_ids if x != s.id]} if camp else None,
        "evidence": {"case_id": s.id, "messages": len(s.messages), "transcript_sha256": transcript_sha256(s),
                     "seal": "verified" if seal.get("ok") else "BROKEN", "seal_head": (seal.get("head") or "")[:32],
                     "red_flags": analysis.get("flags", []), "risk": analysis.get("level")},
        "scammer_messages": [{"time_utc": m.ts, "text": m.text} for m in scam_msgs],
        "link_analysis": [{"url": u, "verdict": r.get("verdict"), "final_url": r.get("final_url"), "ip": r.get("ip"),
                           "findings": [f["finding"] for f in r.get("findings", [])], "checked_at": r.get("checked_at"),
                           "simulation": r.get("simulation")} for u, r in source.get("links", {}).items()],
        "note": "Identifiers are machine-extracted. Verify before legal action.",
    }


def complaint_html(c: dict) -> str:
    e = html.escape
    sus = c["suspect"]
    rows = []
    for label, items in (("Mobile number(s)", sus["mobile_numbers"]), ("Email ID(s)", sus["email_ids"]),
                         ("UPI ID(s)", [u["upi_id"] + (f"  ({u['bank']})" if u["bank"] else "") for u in sus["upi_ids"]]),
                         ("Bank account(s)", [f"{b['account']}  IFSC {b['ifsc'] or '-'}  {b['bank'] or ''}" for b in sus["bank_accounts"]]),
                         ("Website(s)", sus["websites"]), ("Crypto wallet(s)", sus["crypto_wallets"])):
        if items:
            rows.append(f"<tr><th>{e(label)}</th><td>{'<br>'.join(e(i) for i in items)}</td></tr>")
    msgs = "".join(f"<li><span>{e(m['time_utc'])}</span>{e(m['text'])}</li>" for m in c["scammer_messages"])
    ev = c["evidence"]
    linked = c["linked_cases"]
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>NCRP complaint · {e(ev['case_id'])}</title>
<style>
body{{font-family:"Segoe UI",Arial,sans-serif;background:#f1eadc;color:#16130f;margin:0;padding:32px}}
main{{max-width:860px;margin:0 auto;background:#fff;padding:36px 40px;border-top:8px solid #ff3b1f}}
h1{{font-family:Bahnschrift,"Arial Narrow",sans-serif;text-transform:uppercase;font-size:30px;margin:0 0 4px}}
.sub{{color:#5c5348;margin:0 0 20px}} .sim{{background:#16130f;color:#ffd60a;padding:2px 8px;font-weight:700;font-size:12px;letter-spacing:1px}}
table{{width:100%;border-collapse:collapse;margin:8px 0 20px}} th,td{{text-align:left;vertical-align:top;padding:8px 10px;border-bottom:1px solid #e6dfd1;font-size:14px}}
th{{width:230px;color:#5c5348;font-weight:600}} h2{{font-size:15px;text-transform:uppercase;letter-spacing:1px;margin:24px 0 6px;color:#c4210d}}
ol{{padding-left:20px}} li{{margin:6px 0;font-size:14px}} li span{{display:block;color:#8f877c;font-family:Consolas,monospace;font-size:12px}}
.desc{{background:#faf6ee;padding:14px;font-size:14px;line-height:1.5}} .ok{{color:#0f8a5f;font-weight:700}} .bad{{color:#c4210d;font-weight:700}}
.tools a{{display:inline-block;margin:0 8px 16px 0;padding:8px 14px;background:#16130f;color:#f1eadc;text-decoration:none;font-weight:600}}
code{{font-family:Consolas,monospace;font-size:12px;word-break:break-all}}
@media print{{.tools{{display:none}} body{{background:#fff;padding:0}}}}
</style></head><body><main>
<div class="tools"><a href="?format=json&download=1">Download JSON</a><a href="https://cybercrime.gov.in" rel="noopener noreferrer">Open cybercrime.gov.in</a></div>
<h1>Cyber fraud complaint</h1>
<p class="sub">Pre-filled for the National Cyber Crime Reporting Portal · helpline <b>1930</b> {'<span class="sim">SIMULATION</span>' if c['simulation'] else ''}</p>
<table>
<tr><th>Complaint category</th><td>{e(c['complaint_category'])}</td></tr>
<tr><th>Sub-category</th><td>{e(c['sub_category'])}</td></tr>
<tr><th>Date and time (UTC)</th><td>{e(c['incident']['date_time_utc'])}</td></tr>
<tr><th>Platform</th><td>{e(c['incident']['platform'])}</td></tr>
<tr><th>Money lost</th><td>₹0 (amount demanded: {_rupees(c['incident']['money_demanded_inr'])})</td></tr>
</table>
<h2>Suspect details</h2>
<table>{''.join(rows) or '<tr><td>No identifiers captured yet</td></tr>'}</table>
<h2>Description</h2><p class="desc">{e(c['description'])}</p>
{f"<h2>Linked cases</h2><p>Gang {e(linked['campaign'].upper())}: {e(', '.join(linked['case_ids']))}</p>" if linked else ''}
<h2>Scammer's messages</h2><ol>{msgs}</ol>
{_links_html(c.get('link_analysis') or [])}
<h2>Evidence integrity</h2>
<table>
<tr><th>Case</th><td>{e(ev['case_id'])} · {ev['messages']} message{'' if ev['messages'] == 1 else 's'} · risk {e(str(ev['risk']))}</td></tr>
<tr><th>Seal</th><td class="{'ok' if ev['seal'] == 'verified' else 'bad'}">{'Verified: no message changed since capture' if ev['seal'] == 'verified' else 'BROKEN: the transcript was changed after capture'}</td></tr>
<tr><th>Transcript SHA-256</th><td><code>{e(ev['transcript_sha256'])}</code></td></tr>
<tr><th>Seal chain head</th><td><code>{e(ev['seal_head'])}</code></td></tr>
</table>
<p class="sub">{e(c['note'])}</p>
</main></body></html>"""


def _links_html(links: list[dict]) -> str:
    if not links:
        return ""
    e = html.escape
    rows = "".join(f"<tr><th>{e(l['url'])}</th><td><b>{e(l['verdict'] or '')}</b>{' (simulation)' if l.get('simulation') else ''}"
                   f"<br>{'<br>'.join(e(f) for f in l['findings']) or 'no findings'}</td></tr>" for l in links)
    return f"<h2>Link analysis (sandbox)</h2><table>{rows}</table>"


# ---------------------------------------------------------------------------- bank alert
def mule_alert(dossier: dict, sessions: list[Session], seals: dict[str, dict]) -> dict:
    """Mule-account alert for a gang: what each bank / UPI app should freeze or review."""
    targets, by_bank = [], {}
    accts = {}
    for s in sessions:
        for a in bank_accounts(s):
            accts[a["account"]] = a
    for i in dossier["identifiers"]:
        if i["type"] not in ("upi_id", "bank_account", "ifsc", "phone", "url", "crypto_wallet"):
            continue
        t = {"type": i["type"], "value": i["value"], "seen_in_cases": i["cases"], "links_cases": i["shared"]}
        if i["type"] == "upi_id":
            t["bank"] = bank_for("upi_id", i["value"])
            t["action"] = "freeze / enhanced due diligence on the VPA and linked account"
        elif i["type"] == "bank_account":
            a = accts.get(i["value"], {})
            t["ifsc"], t["bank"] = a.get("ifsc"), a.get("bank")
            t["action"] = "debit freeze and lien under RBI fraud-risk guidelines; trace onward transfers"
        elif i["type"] == "phone":
            t["action"] = "report to DoT Chakshu for re-verification / disconnection"
        elif i["type"] == "url":
            t["action"] = "block / takedown request (CERT-In)"
        elif i["type"] == "ifsc":
            t["bank"] = bank_for("ifsc", i["value"])
            t["action"] = "branch to review accounts named in this alert"
        else:
            t["action"] = "flag to the exchange"
        targets.append(t)
        if t.get("bank"):
            by_bank.setdefault(t["bank"], []).append(t["value"])
    return {
        "schema": "scambaiter.mule-alert.v1",
        "alert_type": "MULE_ACCOUNT_ALERT",
        "simulation": True,
        "campaign": {k: dossier[k] for k in ("id", "size", "dominant_scam_type", "first_seen", "last_seen", "demanded")},
        "targets": targets,
        "by_bank": by_bank,
        "evidence": [{"case_id": s.id, "messages": len(s.messages), "transcript_sha256": transcript_sha256(s),
                      "seal": "verified" if seals.get(s.id, {}).get("ok") else "BROKEN",
                      "seal_head": (seals.get(s.id, {}).get("head") or "")[:32]} for s in sessions],
        "recipients": ["Bank / PSP fraud-risk desk", "I4C (Indian Cyber Crime Coordination Centre)", "NPCI"],
        "note": "Machine-extracted from decoy conversations. Verify before freezing. SIMULATION data.",
    }


# ---------------------------------------------------------------------------- lookup API
def lookup(entity_type: str, value: str, sessions: list[Session], g: Graph) -> dict:
    hits = [s for s in sessions if any(e.type == entity_type and e.value == value for e in s.entities)]
    node = f"{entity_type}:{value}"
    camp = next((c for c in g.campaigns if node in c.shared_entities or any(x in c.session_ids for x in [s.id for s in hits])), None)
    times = sorted(m.ts for s in hits for m in s.messages)
    return {"type": entity_type, "value": value, "known": bool(hits), "cases": len(hits),
            "campaign": camp.id if camp else None, "campaign_size": camp.size if camp else 0,
            "scam_types": sorted({s.scam_type for s in hits}), "bank": bank_for(entity_type, value),
            "first_seen": times[0] if times else None, "last_seen": times[-1] if times else None,
            "risk": "HIGH" if camp else "MEDIUM" if hits else "UNKNOWN"}


def _rupees(n: int) -> str:
    s = str(int(n or 0))
    if len(s) > 3:
        head, tail = s[:-3], s[-3:]
        head = re.sub(r"(\d)(?=(\d\d)+$)", r"\1,", head)
        s = head + "," + tail
    return "₹" + s
