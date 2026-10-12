import html
from contracts.models import Session, Graph

COLORS = {
    "upi_id": "#22c55e",
    "phone": "#3b82f6",
    "url": "#f59e0b",
    "bank_account": "#ef4444",
    "ifsc": "#a855f7",
    "email": "#06b6d4",
    "crypto_wallet": "#eab308"
}

def render_report(session: Session, graph: Graph) -> str:
    # Safely escape all identifiers upfront
    escaped_entities = [
        {
            "type": e.type,
            "value": html.escape(e.value),
            "raw": html.escape(e.raw),
            "msg_id": e.message_id,
            "color": COLORS.get(e.type, "#000"),
            "ts": next((m.ts for m in session.messages if m.id == e.message_id), "Unknown"),
            "confidence": f"{e.confidence * 100:.0f}%"
        }
        for e in session.entities
    ]

    # Campaign Logic
    campaign_id = None
    campaign_size = 0
    shared_html = "<li>No shared identifiers linked yet.</li>"
    for c in graph.campaigns:
        if session.id in c.session_ids:
            campaign_id = c.id
            campaign_size = c.size - 1
            shared_items = [html.escape(se.split(":", 1)[1]) for se in c.shared_entities]
            shared_html = "".join(f"<li><strong>{s}</strong></li>" for s in shared_items)
            break

    # Format time wasted
    h, m = divmod(session.time_wasted_seconds, 3600)
    m, s = divmod(m, 60)
    time_str = f"{h}h {m}m" if h else f"{m}m {s}s"
    
    first_ts = session.messages[0].ts if session.messages else "N/A"
    last_ts = session.messages[-1].ts if session.messages else "N/A"

    # Transcript Generation with highlights
    transcript_html = ""
    for m in session.messages:
        text = html.escape(m.text)
        # Highlight entities in this specific message
        for e in escaped_entities:
            if e["msg_id"] == m.id:
                mark = f'<span style="color: {e["color"]}; font-weight: bold; background-color: #f3f4f6; padding: 0 4px; border-radius: 3px;">{e["raw"]}</span>'
                text = text.replace(e["raw"], mark)

        align = "left" if m.role == "scammer" else "right"
        bg = "#f9fafb" if m.role == "scammer" else "#eff6ff"
        border = f"4px solid {COLORS.get('bank_account', 'red')}" if m.role == "scammer" else f"4px solid {COLORS.get('phone', 'blue')}"
        transcript_html += f"""
        <div style="margin-bottom: 15px; text-align: {align};">
            <div style="display: inline-block; max-width: 80%; background: {bg}; border-{align}: {border}; padding: 12px; border-radius: 6px; text-align: left; border: 1px solid #e5e7eb;">
                <div style="font-size: 14px; margin-bottom: 4px; color: #6b7280; text-transform: uppercase;">{m.role}</div>
                <div style="font-size: 16px; line-height: 1.5; color: #111827;">{text}</div>
                <div style="font-size: 12px; color: #9ca3af; margin-top: 6px;">{m.ts}</div>
            </div>
        </div>
        """

    # Identifiers Table
    if escaped_entities:
        table_rows = "".join(f"""
            <tr>
                <td style="padding: 8px; border-bottom: 1px solid #e5e7eb; color: {e['color']}; font-weight: bold;">{e['type']}</td>
                <td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">{e['value']}</td>
                <td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">{e['ts']}</td>
                <td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">{e['confidence']}</td>
            </tr>
        """ for e in escaped_entities)
    else:
        table_rows = "<tr><td colspan='4' style='padding: 8px; text-align: center; color: #6b7280;'>No identifiers extracted.</td></tr>"

    html_template = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Evidence Report: {session.id}</title>
        <style>
            body {{ font-family: sans-serif; color: #111827; line-height: 1.6; max-width: 210mm; margin: 0 auto; padding: 20px; }}
            @media print {{ body {{ padding: 0; }} .no-print {{ display: none; }} }}
            .header {{ text-align: center; border-bottom: 2px solid #e5e7eb; padding-bottom: 20px; margin-bottom: 20px; position: relative; }}
            .watermark {{ position: absolute; top: 0; left: 0; background: #ef4444; color: white; padding: 4px 12px; font-weight: bold; border-radius: 4px; font-size: 12px; }}
            .section {{ margin-bottom: 30px; }}
            h1 {{ margin: 0 0 10px 0; }}
            h2 {{ color: #374151; font-size: 18px; border-bottom: 1px solid #e5e7eb; padding-bottom: 5px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            th {{ text-align: left; padding: 8px; background: #f9fafb; border-bottom: 2px solid #e5e7eb; }}
            .campaign-box {{ background: #fffbeb; border: 1px solid #fde68a; padding: 15px; border-radius: 6px; }}
            .action-box {{ background: #fef2f2; border: 1px solid #fca5a5; padding: 20px; border-radius: 6px; margin-top: 40px; }}
            .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }}
            .metric strong {{ display: block; color: #6b7280; font-size: 12px; text-transform: uppercase; }}
            .metric span {{ font-size: 18px; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="header">
            {'<div class="watermark">SIMULATION</div>' if session.is_simulation else ''}
            <h1>Scam Evidence Report</h1>
            <p style="color: #6b7280; margin: 0;">Report ID: {session.id} | Generated Time: {session.created_at}</p>
        </div>

        <div class="section grid">
            <div class="metric"><strong>Scam Type</strong><span>{session.scam_type.replace('_', ' ').title()}</span></div>
            <div class="metric"><strong>Platform/Channel</strong><span>{session.channel.title()}</span></div>
            <div class="metric"><strong>Timeframe</strong><span>{first_ts} — {last_ts}</span></div>
            <div class="metric"><strong>Scammer Time Wasted</strong><span>{time_str}</span></div>
        </div>

        <div class="section">
            <h2>Extracted Identifiers</h2>
            <table>
                <thead><tr><th>Type</th><th>Value</th><th>First Seen</th><th>Confidence</th></tr></thead>
                <tbody>{table_rows}</tbody>
            </table>
        </div>

        <div class="section">
            <h2>Campaign Linkage</h2>
            <div class="campaign-box">
                {f'<p><strong>Campaign ID: {campaign_id}</strong></p><p>This session is linked to <strong>{campaign_size}</strong> other session(s) sharing these identifiers:</p><ul>{shared_html}</ul>' if campaign_id else '<p style="margin: 0; color: #92400e;">No linked campaign yet. This appears to be an isolated incident.</p>'}
            </div>
        </div>

        <div class="section">
            <h2>Full Transcript</h2>
            <div style="background: #ffffff; border: 1px solid #e5e7eb; border-radius: 6px; padding: 20px;">
                {transcript_html}
            </div>
        </div>

        <div class="section action-box">
            <h2 style="border-color: #fca5a5; margin-top: 0;">What to do now</h2>
            <ul style="margin-bottom: 0;">
                <li>Report this incident immediately at <strong><a href="https://cybercrime.gov.in" style="color: #dc2626;">https://cybercrime.gov.in</a></strong> or call <strong>1930</strong>.</li>
                <li>If you shared banking details, call your bank immediately to freeze your account/cards.</li>
                <li>Do not click any links or share OTPs/PINs.</li>
                <li><em>Note: Identifiers in this report are machine-extracted and should be verified before taking legal action.</em></li>
            </ul>
        </div>
    </body>
    </html>"""
    return html_template