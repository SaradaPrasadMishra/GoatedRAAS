import html
import re
from datetime import datetime

from contracts.models import Session, Graph

# Darker variants of the dashboard entity colours, so they stay readable on white paper
COLORS = {
    "upi_id": "#0f8a5f",
    "phone": "#2448c9",
    "url": "#b45309",
    "bank_account": "#c0262d",
    "ifsc": "#7c3aed",
    "email": "#0e7490",
    "crypto_wallet": "#a16207",
}

LABELS = {
    "upi_id": "UPI ID",
    "phone": "Phone",
    "url": "Link",
    "bank_account": "Bank account",
    "ifsc": "IFSC",
    "email": "Email",
    "crypto_wallet": "Crypto wallet",
}


# Same red flags as the dashboard (dashboard/app.js RED_FLAGS), checked on the scammer's messages
RED_FLAGS = [
    ("Urgency", r"\b(urgent|immediately|right now|today|hurry|fast|quick(ly)?|expire[sd]?|last (reminder|chance)|time is running|within \d+ ?(min|minutes|hours?))\b"),
    ("Asks for OTP / PIN", r"\b(otp|pin|cvv|password|passcode)\b"),
    ("Demands payment", r"\b(pay|payment|transfer|deposit|fee|charges?|send (money|rs|₹)|collect request|(accept|approve) (the )?(collect )?request|scan (the )?qr)\b|₹|\brs\.? ?\d"),
    ("Fake authority", r"\b(rbi|police|cbi|cyber ?cell|customs|income tax|trai|court|government|ministry|bank (official|manager|head office)|kyc (team|department)|sbi|hdfc|icici|amazon|flipkart|electricity board)\b"),
    ("Threat", r"\b(block(ed)?|suspend(ed)?|arrest|legal action|penalty|freeze|frozen|disconnect(ed)?|fir|warrant|money laundering|case (is )?(registered|filed))\b"),
    ("Too good to be true", r"\b(won|winner|lottery|prize|reward|cashback|double|guaranteed|profit|returns?|loan (is )?approved|earn(ings)?|bonus|refund)\b"),
    ("Secrecy", r"\b(do not (tell|inform|share with)|don'?t tell|keep (it|this) (secret|confidential)|stay on (the|this) call)\b"),
]
_OTP = re.compile(r"\b(otp|pin|cvv|password|passcode)\b", re.I)
_PAY = re.compile(RED_FLAGS[2][1], re.I)
_DIGITS4 = re.compile(r"\d(?:[\s-]?\d){3,}")
_PAID = re.compile(r"\bi(?: have|'ve)? (?:sent|paid|transferred)\b", re.I)


def _analyse(session: Session) -> dict:
    scam = [m.text for m in session.messages if m.role == "scammer"]
    bot = [m.text for m in session.messages if m.role == "bot"]
    joined = "\n".join(scam)
    flags = [name for name, rx in RED_FLAGS if re.search(rx, joined, re.I)]
    if any(e.type == "url" for e in session.entities):
        flags.append("Suspicious link")
    level = "HIGH" if len(flags) >= 4 else "MEDIUM" if len(flags) >= 2 else "LOW"
    return {
        "flags": flags, "level": level,
        "otp_asked": sum(bool(_OTP.search(t)) for t in scam),
        "pay_asked": sum(bool(_PAY.search(t)) for t in scam),
        "shared": sum(bool(_DIGITS4.search(t)) for t in bot),
        "paid": sum(bool(_PAID.search(t)) for t in bot),
    }


def _fmt_ts(ts: str) -> str:
    """ISO timestamp -> '12 Oct 2026, 05:41:00'. Falls back to the raw string."""
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%d %b %Y, %H:%M:%S")
    except (ValueError, AttributeError):
        return html.escape(str(ts))


def _fmt_clock(ts: str) -> str:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%H:%M:%S")
    except (ValueError, AttributeError):
        return html.escape(str(ts))


def render_report(session: Session, graph: Graph) -> str:
    # Safely escape all identifiers upfront
    escaped_entities = [
        {
            "type": e.type,
            "label": LABELS.get(e.type, e.type),
            "value": html.escape(e.value),
            "raw": html.escape(e.raw),
            "msg_id": e.message_id,
            "color": COLORS.get(e.type, "#111827"),
            "ts": next((_fmt_ts(m.ts) for m in session.messages if m.id == e.message_id), "Unknown"),
            "confidence": f"{e.confidence * 100:.0f}%",
        }
        for e in session.entities
    ]

    # Campaign Logic
    campaign_id = None
    campaign_size = 0
    shared_html = "<li>No shared identifiers linked yet.</li>"
    for c in graph.campaigns:
        if session.id in c.session_ids:
            campaign_id = html.escape(c.id)
            campaign_size = c.size - 1
            shared_items = [html.escape(se.split(":", 1)[1]) for se in c.shared_entities]
            shared_html = "".join(f"<li><code>{s}</code></li>" for s in shared_items)
            break

    # Format time wasted
    h, rem = divmod(session.time_wasted_seconds, 3600)
    mins, secs = divmod(rem, 60)
    time_str = f"{h}h {mins}m" if h else f"{mins}m {secs}s"

    first_ts = _fmt_ts(session.messages[0].ts) if session.messages else "N/A"
    last_ts = _fmt_ts(session.messages[-1].ts) if session.messages else "N/A"
    scammer_msgs = sum(1 for msg in session.messages if msg.role == "scammer")

    # Transcript with highlighted identifiers
    transcript_html = ""
    for msg in session.messages:
        text = html.escape(msg.text)
        for e in escaped_entities:
            if e["msg_id"] == msg.id:
                mark = f'<mark style="color:{e["color"]};border-color:{e["color"]}">{e["raw"]}</mark>'
                text = text.replace(e["raw"], mark)
        who = "Scammer" if msg.role == "scammer" else "Decoy (AI)"
        transcript_html += f"""
            <div class="msg msg-{html.escape(msg.role)}">
                <div class="msg-who">{who} <span>{_fmt_clock(msg.ts)}</span></div>
                <div class="msg-text">{text}</div>
            </div>"""

    # Identifiers table
    if escaped_entities:
        table_rows = "".join(f"""
                <tr>
                    <td><span class="tag" style="color:{e['color']};border-color:{e['color']}">{e['label']}</span></td>
                    <td class="val">{e['value']}</td>
                    <td>{e['ts']}</td>
                    <td class="num">{e['confidence']}</td>
                </tr>""" for e in escaped_entities)
    else:
        table_rows = "<tr><td colspan='4' class='empty'>No identifiers extracted.</td></tr>"

    if campaign_id:
        campaign_html = (
            f"<p class='camp-id'>Campaign <strong>{campaign_id}</strong></p>"
            f"<p>This session is linked to <strong>{campaign_size}</strong> other session(s) "
            f"that reuse these identifiers, which suggests one organised group:</p><ul>{shared_html}</ul>"
        )
    else:
        campaign_html = "<p>No linked campaign yet. This appears to be an isolated incident.</p>"

    a = _analyse(session)
    flags_html = "".join(f'<span class="flag">{html.escape(f)}</span>' for f in a["flags"]) or '<span class="flag">none detected</span>'
    sid = html.escape(session.id)
    scam_type = html.escape(session.scam_type.replace("_", " ").title())
    channel = html.escape(session.channel.title())

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Evidence Report: {sid}</title>
<style>
    @page {{ size: A4; margin: 14mm; }}
    * {{ box-sizing: border-box; }}
    body {{
        margin: 0; padding: 24px; background: #e9ecf5; color: #111827;
        font-family: "Segoe UI Variable Text", "Segoe UI", system-ui, sans-serif;
        font-size: 14px; line-height: 1.55;
        -webkit-print-color-adjust: exact; print-color-adjust: exact;
    }}
    .sheet {{
        position: relative; max-width: 210mm; margin: 0 auto; background: #fff;
        border-radius: 14px; overflow: hidden; box-shadow: 0 20px 60px -20px rgba(6, 10, 48, .35);
    }}
    .display {{ font-family: "Bahnschrift SemiBold Condensed", "Bahnschrift Condensed", Bahnschrift, "Arial Narrow", Impact, sans-serif; font-stretch: condensed; font-weight: 700; text-transform: uppercase; }}
    .mono {{ font-family: "Cascadia Mono", Consolas, monospace; }}

    /* brand header band */
    .band {{
        position: relative; color: #fff; padding: 26px 32px 22px;
        background: radial-gradient(70% 140% at 100% 0%, rgba(255, 59, 31, .35), transparent 60%), #0e0c0b;
        border-bottom: 8px solid #ff3b1f;
    }}
    .brand {{ display: flex; align-items: center; gap: 12px; }}
    .orb {{
        width: 34px; height: 34px; display: grid; place-items: center;
        background: #ff3b1f; box-shadow: 3px 3px 0 #f1eadc;
    }}
    .orb i {{ width: 0; height: 0; border-left: 9px solid transparent; border-right: 9px solid transparent; border-bottom: 14px solid #0e0c0b; }}
    .brand-name {{ font-size: 22px; letter-spacing: .02em; }}
    .brand-sub {{ font-size: 10px; letter-spacing: .08em; opacity: .75; }}
    .sim {{
        position: absolute; top: 24px; right: 28px; background: #ffd60a; color: #0e0c0b;
        font-size: 11px; font-weight: 700; letter-spacing: .08em; padding: 6px 12px;
    }}
    .sim::before {{ content: "\\25B2  "; }}
    h1 {{ margin: 18px 0 4px; font-size: 52px; line-height: .9; letter-spacing: -.005em; }}
    h1 .outline {{ color: #ff3b1f; font-style: italic; }}
    .meta {{ font-size: 11px; opacity: .8; }}

    /* SIMULATION watermark across the page */
    .watermark {{
        position: absolute; top: 46%; left: 50%; transform: translate(-50%, -50%) rotate(-28deg);
        font-size: 120px; color: rgba(255, 59, 31, .07); white-space: nowrap; pointer-events: none; z-index: 0;
    }}

    main {{ position: relative; z-index: 1; padding: 22px 32px 30px; }}
    .kpis {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 22px; }}
    .kpi {{ border: 1px solid #e3e7f3; border-radius: 12px; padding: 10px 12px; background: #f7f8fd; }}
    .kpi b {{ display: block; font-size: 10px; letter-spacing: .08em; color: #5b6380; font-weight: 600; }}
    .kpi span {{ font-size: 26px; line-height: 1.1; color: #0a0d24; }}
    .kpi.hero {{ background: #ff3b1f; border-color: #0e0c0b; box-shadow: 4px 4px 0 #0e0c0b; }}
    .kpi.hero b, .kpi.hero span {{ color: #0e0c0b; }}

    h2 {{ display: flex; align-items: baseline; gap: 10px; font-size: 22px; margin: 26px 0 10px; color: #0a0d24; }}
    h2 small {{ font-size: 11px; color: #7b83a3; font-weight: 600; letter-spacing: .06em; }}
    .timeframe {{ font-size: 12px; color: #5b6380; margin: -6px 0 6px; }}

    table {{ width: 100%; border-collapse: collapse; }}
    th {{ text-align: left; font-size: 10px; letter-spacing: .08em; text-transform: uppercase; color: #5b6380; padding: 8px 10px; border-bottom: 2px solid #0a0d24; }}
    td {{ padding: 9px 10px; border-bottom: 1px solid #e8ebf4; vertical-align: top; }}
    td.val {{ font-family: "Cascadia Mono", Consolas, monospace; font-weight: 700; overflow-wrap: anywhere; }}
    td.num {{ font-variant-numeric: tabular-nums; }}
    td.empty {{ text-align: center; color: #7b83a3; }}
    .tag {{ display: inline-block; font-size: 10.5px; font-weight: 700; letter-spacing: .04em; padding: 2px 8px; border: 1.5px solid; border-radius: 999px; white-space: nowrap; }}

    .flags-box {{ display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }}
    .flag {{ font-size: 12px; font-weight: 600; padding: 3px 9px; border: 1.5px solid #ff3b1f; color: #c4210d; background: #fff4f1; }}
    .risk {{ font-size: 16px; padding: 3px 10px; color: #0e0c0b; background: #ffd60a; }}
    .risk-high {{ background: #ff3b1f; }}
    .risk-low {{ background: #e6dcc8; }}
    .safety {{ flex-basis: 100%; margin: 8px 0 0; font-size: 12px; color: #3a332b; }}
    .safety b {{ color: #0f8a5f; }}
    .campaign {{ border-radius: 12px; padding: 14px 16px; background: #fff8eb; border: 1px solid #f6d58a; }}
    .campaign p {{ margin: 0 0 6px; }}
    .campaign ul {{ margin: 6px 0 0; padding-left: 20px; }}
    .camp-id strong {{ font-family: "Cascadia Mono", Consolas, monospace; }}
    code {{ font-family: "Cascadia Mono", Consolas, monospace; font-weight: 700; }}

    .transcript {{ border: 1px solid #e3e7f3; border-radius: 12px; padding: 14px; }}
    .msg {{ max-width: 82%; margin-bottom: 10px; padding: 9px 12px; border-radius: 12px; break-inside: avoid; }}
    .msg-scammer {{ background: #fff1f3; border-left: 4px solid #e11d48; }}
    .msg-bot {{ margin-left: auto; background: #f3f1ec; border-right: 4px solid #0e0c0b; }}
    .msg-who {{ font-size: 10px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; color: #5b6380; }}
    .msg-who span {{ font-weight: 400; margin-left: 6px; }}
    .msg-text {{ font-size: 14.5px; overflow-wrap: anywhere; }}
    mark {{ background: #fff; border: 1.5px solid; border-radius: 5px; padding: 0 4px; font-family: "Cascadia Mono", Consolas, monospace; font-weight: 700; font-size: .92em; }}

    .action {{ margin-top: 26px; padding: 16px 18px; background: #0e0c0b; color: #fff; border-left: 8px solid #ff3b1f; }}
    .action h2 {{ color: #fff; margin: 0 0 8px; }}
    .action ul {{ margin: 0; padding-left: 20px; }}
    .action a {{ color: #ffd60a; }}
    .action .note {{ opacity: .7; font-size: 12px; }}
    .big {{ font-size: 20px; }}

    footer {{ display: flex; justify-content: space-between; font-size: 10px; color: #7b83a3; padding: 12px 32px 18px; border-top: 1px solid #eef0f7; }}

    .toolbar {{ max-width: 210mm; margin: 0 auto 14px; display: flex; justify-content: flex-end; }}
    .toolbar button {{
        font: inherit; font-weight: 700; cursor: pointer; border: 0; border-radius: 999px; padding: 10px 18px;
        background: #ff3b1f; color: #0e0c0b;
    }}
    .toolbar button:focus-visible {{ outline: 2px solid #2f5bff; outline-offset: 3px; }}

    @media print {{
        body {{ background: #fff; padding: 0; }}
        .sheet {{ box-shadow: none; border-radius: 0; max-width: none; }}
        .no-print {{ display: none !important; }}
    }}
</style>
</head>
<body>
    <div class="toolbar no-print"><button type="button" onclick="window.print()">Print / Save as PDF</button></div>
    <div class="sheet">
        <div class="watermark display" aria-hidden="true">SIMULATION</div>
        <header class="band">
            <div class="brand">
                <div class="orb"><i></i></div>
                <div>
                    <div class="brand-name display">Scambaiter</div>
                    <div class="brand-sub mono">They call. We answer. Slowly.</div>
                </div>
            </div>
            <span class="sim mono">SIMULATION</span>
            <h1 class="display">Scam <span class="outline">evidence</span> report</h1>
            <div class="meta mono">REPORT ID {sid} &nbsp;·&nbsp; GENERATED {_fmt_ts(session.created_at)}</div>
        </header>

        <main>
            <section class="kpis" aria-label="Summary">
                <div class="kpi"><b class="mono">[01] SCAM TYPE</b><span class="display">{scam_type}</span></div>
                <div class="kpi"><b class="mono">[02] CHANNEL</b><span class="display">{channel}</span></div>
                <div class="kpi"><b class="mono">[03] IDENTIFIERS</b><span class="display">{len(escaped_entities)}</span></div>
                <div class="kpi hero"><b class="mono">[04] TIME WASTED</b><span class="display" style="text-transform:none">{time_str}</span></div>
            </section>

            <h2 class="display">Why this was flagged</h2>
            <div class="flags-box">
                <span class="risk risk-{a["level"].lower()} display">{a["level"]} RISK</span>
                {flags_html}
                <p class="safety mono">Safety record: OTP/PIN requested {a["otp_asked"]}× · shared <b>{a["shared"]}</b> &nbsp;|&nbsp;
                payment requested {a["pay_asked"]}× · paid <b>{a["paid"]}</b> &nbsp;|&nbsp; links opened <b>0</b></p>
            </div>

            <h2 class="display">Extracted identifiers <small class="mono">[ {scammer_msgs} SCAMMER MESSAGES ]</small></h2>
            <p class="timeframe mono">{first_ts} → {last_ts}</p>
            <table>
                <thead><tr><th>Type</th><th>Value</th><th>First seen</th><th>Confidence</th></tr></thead>
                <tbody>{table_rows}
                </tbody>
            </table>

            <h2 class="display">Campaign linkage</h2>
            <div class="campaign">{campaign_html}</div>

            <h2 class="display">Full transcript</h2>
            <div class="transcript">{transcript_html}
            </div>

            <section class="action">
                <h2 class="display">What to do now</h2>
                <ul>
                    <li class="big">Report it at <strong><a href="https://cybercrime.gov.in">cybercrime.gov.in</a></strong> or call <strong>1930</strong>.</li>
                    <li>If you shared banking details, call your bank now to freeze your account and cards.</li>
                    <li>Do not click any links and never share an OTP or UPI PIN.</li>
                    <li class="note">Identifiers in this report are machine-extracted. Verify them before taking legal action.</li>
                </ul>
            </section>
        </main>

        <footer class="mono">
            <span>SCAMBAITER · SIMULATION · NO REAL PAYMENTS, NO REAL PEOPLE</span>
            <span>{sid}</span>
        </footer>
    </div>
</body>
</html>"""
