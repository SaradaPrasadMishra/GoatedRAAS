"""
Gmail integration: a real inbox for the decoy. Standard library only (imaplib + smtplib).

Two ways an email reaches Scambaiter:
  1. REPORT  - a person forwards a suspicious email to the Scambaiter address. It becomes a case and
               the person gets a reply with the verdict: risk, red flags, identifiers, what to do.
  2. DECOY   - a "scammer" writes to the Scambaiter address directly. The decoy persona answers in the
               same email thread, and every reply in the thread continues the same case.
               The decoy only writes back to addresses on SCAMBAITER_GMAIL_DECOY_ALLOW (your team's
               demo addresses); everyone else is logged as a case without a reply.

Setup (Gmail needs 2-step verification and an App Password: myaccount.google.com/apppasswords):
    set SCAMBAITER_GMAIL_USER=scambaiter.demo@gmail.com
    set SCAMBAITER_GMAIL_APP_PASSWORD=abcd efgh ijkl mnop
    set SCAMBAITER_GMAIL_DECOY_ALLOW=friend1@gmail.com,friend2@gmail.com
Or the same keys in data/gmail.json ({"user": ..., "app_password": ..., "decoy_allow": [...]}).
Offline, an .eml file dropped on the dashboard goes through the same code (no reply is sent).
"""
from __future__ import annotations

import email
import email.policy
import email.utils
import html
import imaplib
import json
import logging
import os
import re
import smtplib
import threading
import time
from email.message import EmailMessage

log = logging.getLogger("scambaiter")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_FWD = re.compile(r"^-{2,}\s*Forwarded message\s*-{2,}|^Begin forwarded message:|^-{2,}\s*Original Message\s*-{2,}",
                  re.I | re.M)
_QUOTE_START = re.compile(r"^On .{5,200}wrote:\s*$|^-{2,}\s*Original Message|^From: .+$\n^(Sent|Date): ", re.M)
_ADDR = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")

WHY = {
    "Urgency": "Rushes you so you do not stop to think.",
    "Asks for OTP / PIN": "No bank or agency ever asks for your OTP or PIN.",
    "Demands payment": "Real refunds, prizes and jobs never ask you to pay first.",
    "Fake authority": "Pretends to be a bank, police or a big company.",
    "Threat": "Scares you with blocked accounts, arrest or penalties.",
    "Too good to be true": "Promises easy money, prizes or refunds.",
    "Secrecy": "Tells you not to tell anyone.",
    "Moves you to WhatsApp / Telegram": "Pulls you into a private chat app.",
    "Suspicious link": "Contains a link. Never open links from unknown senders.",
    "Tries to trick the AI": "Gives orders meant for an AI, or tests whether it is one.",
}


# ---------------------------------------------------------------------------- config
def load_config() -> dict | None:
    cfg = {}
    path = os.path.join(os.environ.get("SCAMBAITER_DATA", os.path.join(ROOT, "data")), "gmail.json")
    try:
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        pass
    user = os.environ.get("SCAMBAITER_GMAIL_USER") or cfg.get("user")
    pw = os.environ.get("SCAMBAITER_GMAIL_APP_PASSWORD") or cfg.get("app_password")
    if not user or not pw:
        return None
    allow = os.environ.get("SCAMBAITER_GMAIL_DECOY_ALLOW")
    allow = [a.strip().lower() for a in allow.split(",")] if allow else [a.lower() for a in cfg.get("decoy_allow", [])]
    return {"user": user.strip().lower(), "app_password": pw.replace(" ", ""), "decoy_allow": [a for a in allow if a],
            "poll_seconds": int(os.environ.get("SCAMBAITER_GMAIL_POLL", cfg.get("poll_seconds", 15))),
            "imap_host": cfg.get("imap_host", "imap.gmail.com"), "smtp_host": cfg.get("smtp_host", "smtp.gmail.com")}


# ---------------------------------------------------------------------------- transport
class GmailTransport:
    """IMAP over TLS to read unread mail, SMTP over TLS to reply."""

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def fetch_unseen(self) -> list[bytes]:
        out = []
        with imaplib.IMAP4_SSL(self.cfg["imap_host"], 993, timeout=30) as m:
            m.login(self.cfg["user"], self.cfg["app_password"])
            m.select("INBOX")
            typ, data = m.search(None, "UNSEEN")
            for num in (data[0].split() if typ == "OK" and data and data[0] else [])[:20]:
                typ, msg = m.fetch(num, "(RFC822)")   # fetching marks it as read
                if typ == "OK" and msg and isinstance(msg[0], tuple):
                    out.append(msg[0][1])
        return out

    def send(self, msg: EmailMessage) -> None:
        with smtplib.SMTP_SSL(self.cfg["smtp_host"], 465, timeout=30) as s:
            s.login(self.cfg["user"], self.cfg["app_password"])
            s.send_message(msg)


# ---------------------------------------------------------------------------- parsing
def _text_of(msg) -> str:
    part = msg.get_body(preferencelist=("plain", "html"))
    if part is None:
        return ""
    try:
        body = part.get_content()
    except (LookupError, ValueError):
        body = part.get_payload(decode=True).decode("utf-8", "replace")
    if part.get_content_type() == "text/html":
        body = re.sub(r"(?is)<(script|style).*?</\1>", " ", body)
        body = re.sub(r"(?i)<br\s*/?>|</p>|</div>", "\n", body)
        body = html.unescape(re.sub(r"<[^>]+>", " ", body))
    return re.sub(r"[ \t]+", " ", body).strip()


def strip_quoted(body: str) -> str:
    """Keep only the new part of a reply."""
    m = _QUOTE_START.search(body)
    if m:
        body = body[:m.start()]
    return "\n".join(l for l in body.splitlines() if not l.lstrip().startswith(">")).strip()


def parse(raw: bytes) -> dict:
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    sender = email.utils.parseaddr(str(msg.get("From", "")))[1].lower()
    subject = str(msg.get("Subject", "")).strip()
    body = _text_of(msg)
    refs = " ".join(str(msg.get(h, "")) for h in ("In-Reply-To", "References"))
    out = {"from": sender, "subject": subject, "message_id": str(msg.get("Message-ID", "")).strip(),
           "references": re.findall(r"<[^>]+>", refs), "body": body, "forward": None}
    fwd = _FWD.search(body)
    if fwd or re.match(r"(?i)^(fwd?|fw):", subject):
        inner = body[fwd.end():] if fwd else body
        orig_from = re.search(r"(?im)^\s*From:\s*(.+)$", inner)
        orig_subj = re.search(r"(?im)^\s*Subject:\s*(.+)$", inner)
        # the original text starts after the forwarded header block (first blank line after it)
        header_end = re.search(r"\n\s*\n", inner)
        text = inner[header_end.end():] if header_end and orig_from else inner
        addr = _ADDR.search(orig_from.group(1)) if orig_from else None
        out["forward"] = {"from": addr.group().lower() if addr else None,
                          "subject": orig_subj.group(1).strip() if orig_subj else re.sub(r"(?i)^(fwd?|fw):\s*", "", subject),
                          "text": text.strip()}
    return out


# ---------------------------------------------------------------------------- intake
class MailIntake:
    def __init__(self, service, cfg: dict | None, transport=None):
        self.service = service
        self.cfg = cfg
        self.transport = transport or (GmailTransport(cfg) if cfg else None)
        self.lock = threading.Lock()
        self.status = {"enabled": bool(cfg), "address": cfg["user"] if cfg else None,
                       "decoy_allow": cfg["decoy_allow"] if cfg else [], "last_poll": None, "last_error": None,
                       "received": 0, "replied": 0, "reports": 0, "decoy_threads": 0}

    # ------------------------------------------------------------ public
    def start(self) -> None:
        if not self.cfg:
            return
        def loop():
            while True:
                self.poll_once()
                time.sleep(max(5, self.cfg["poll_seconds"]))
        threading.Thread(target=loop, daemon=True, name="gmail-poller").start()
        log.info("Gmail intake on: %s (poll every %ss)", self.cfg["user"], self.cfg["poll_seconds"])

    def poll_once(self) -> int:
        if not self.transport:
            return 0
        with self.lock:
            try:
                raws = self.transport.fetch_unseen()
                self.status["last_error"] = None
            except Exception as e:  # noqa: BLE001
                self.status["last_error"] = f"{type(e).__name__}: {e}"
                log.warning("Gmail poll failed: %s", self.status["last_error"])
                raws = []
            self.status["last_poll"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        for raw in raws:
            try:
                self.handle(raw, send_replies=True)
            except Exception:  # noqa: BLE001
                log.exception("could not handle an email")
        return len(raws)

    def handle(self, raw: bytes, send_replies: bool = False, via: str = "gmail") -> dict:
        """One email -> a case. Returns what happened (used by the .eml upload too)."""
        p = parse(raw)
        own = self.cfg["user"] if self.cfg else None
        if own and p["from"] == own:
            return {"action": "ignored", "reason": "our own email"}
        self.status["received"] += 1
        S = self.service
        # 1. a reply in a decoy thread we started
        sid = S.find_email_thread(p["references"])
        if sid:
            text = strip_quoted(p["body"]) or p["subject"]
            turn = S.turn(sid, text)
            sent = self._reply_decoy(p, sid, turn.bot_reply.text) if send_replies else False
            S.audit_event("email", "email_reply_received", sid, f"from {p['from']}")
            return {"action": "decoy_continue", "session_id": sid, "reply": turn.bot_reply.text, "sent": sent}
        # 2. a forwarded scam: case + verdict to the person who forwarded it
        if p["forward"]:
            f = p["forward"]
            text = (f["subject"] + "\n" + f["text"]).strip() if f["subject"] else f["text"]
            meta = {"source": via, "mode": "report", "reporter": p["from"], "peer": f["from"],
                    "subject": f["subject"], "thread": [p["message_id"]]}
            s = S.ingest_report(text, meta, extra_emails=[f["from"]] if f["from"] else [])
            verdict = S.analysis(s.id)
            sent = self._reply_verdict(p, s, verdict) if send_replies else False
            self.status["reports"] += 1
            S.audit_event("email", "email_report_received", s.id, f"reported by {p['from']}")
            return {"action": "report", "session_id": s.id, "level": verdict.get("level"),
                    "flags": verdict.get("flags", []), "sent": sent}
        # 3. someone wrote to the decoy directly: a new decoy conversation
        allowed = bool(self.cfg) and ("*" in self.cfg["decoy_allow"] or p["from"] in self.cfg["decoy_allow"])
        text = (p["subject"] + "\n" + strip_quoted(p["body"])).strip()
        meta = {"source": via, "mode": "decoy" if allowed or not send_replies else "logged", "peer": p["from"], "subject": p["subject"],
                "thread": [p["message_id"]] if p["message_id"] else []}
        if allowed or not send_replies:
            s = S.create_session_from(text, meta, channel="simulator", extra_emails=[p["from"]])
            reply = next((m.text for m in reversed(s.messages) if m.role == "bot"), "")
            sent = self._reply_decoy(p, s.id, reply) if send_replies and allowed else False
            self.status["decoy_threads"] += 1
            S.audit_event("email", "email_decoy_started", s.id, f"from {p['from']}")
            return {"action": "decoy_start", "session_id": s.id, "reply": reply, "sent": sent}
        s = S.ingest_report(text, meta, extra_emails=[p["from"]])
        S.audit_event("email", "email_logged_no_reply", s.id, f"from {p['from']} (not on the decoy allow-list)")
        return {"action": "logged", "session_id": s.id, "sent": False}

    # ------------------------------------------------------------ replies
    def _send(self, msg: EmailMessage) -> bool:
        try:
            self.transport.send(msg)
            self.status["replied"] += 1
            return True
        except Exception as e:  # noqa: BLE001
            self.status["last_error"] = f"send failed: {type(e).__name__}: {e}"
            log.warning("Gmail send failed: %s", e)
            return False

    def _reply_decoy(self, p: dict, sid: str, text: str) -> bool:
        if not text:
            return False
        msg = EmailMessage()
        msg["From"] = self.cfg["user"]
        msg["To"] = p["from"]
        msg["Subject"] = p["subject"] if p["subject"].lower().startswith("re:") else "Re: " + (p["subject"] or "your message")
        mid = email.utils.make_msgid(domain="scambaiter.local")
        msg["Message-ID"] = mid
        if p["message_id"]:
            msg["In-Reply-To"] = p["message_id"]
            msg["References"] = " ".join(p["references"] + [p["message_id"]])
        msg.set_content(text)
        ok = self._send(msg)
        if ok:
            self.service.add_email_thread(sid, [p["message_id"], mid])
        return ok

    def _reply_verdict(self, p: dict, s, a: dict) -> bool:
        level = a.get("level", "LOW")
        head = {"HIGH": "Very likely a SCAM", "MEDIUM": "Likely a scam", "LOW": "No strong scam signs found"}[level]
        lines = [f"Scambaiter verdict: {head} ({level} risk)", f"Case #{s.id[2:].upper()}  [SIMULATION]", ""]
        if a.get("flags"):
            lines.append("Warning signs we found:")
            lines += [f"  - {f}: {WHY.get(f, '')}" for f in a["flags"]]
            lines.append("")
        if s.entities:
            lines.append("Identifiers the sender used (now on our evidence board):")
            lines += [f"  - {e.type.replace('_', ' ')}: {e.value}" for e in s.entities]
            lines.append("")
        if a.get("demanded"):
            lines += [f"They asked for Rs {a['demanded']}.", ""]
        lines += ["What to do:", "  - Do not reply, pay, click links or share any OTP / PIN.",
                  "  - Report it at https://cybercrime.gov.in or call 1930.",
                  "  - If you already paid, call 1930 immediately: the first hours matter.", "",
                  "Scambaiter checks messages automatically. It can be wrong: when in doubt, call the company on its official number."]
        msg = EmailMessage()
        msg["From"] = self.cfg["user"]
        msg["To"] = p["from"]
        msg["Subject"] = f"[Scambaiter: {level} RISK] " + re.sub(r"(?i)^(fwd?|fw):\s*", "", p["subject"])
        if p["message_id"]:
            msg["In-Reply-To"] = p["message_id"]
            msg["References"] = p["message_id"]
        msg.set_content("\n".join(lines))
        return self._send(msg)


# ---------------------------------------------------------------------------- setup CLI
def _setup() -> int:
    """python -m backend.mail setup   : save the Gmail login to data/gmail.json (gitignored)
       python -m backend.mail test    : check the login works (IMAP + SMTP), sends nothing"""
    import getpass
    import sys
    data = os.environ.get("SCAMBAITER_DATA", os.path.join(ROOT, "data"))
    path = os.path.join(data, "gmail.json")
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        cfg = load_config()
        if not cfg:
            print("Gmail is not set up. Run: python -m backend.mail setup")
            return 1
        try:
            with imaplib.IMAP4_SSL(cfg["imap_host"], 993, timeout=20) as m:
                m.login(cfg["user"], cfg["app_password"])
                m.select("INBOX")
                n = len((m.search(None, "UNSEEN")[1][0] or b"").split())
            with smtplib.SMTP_SSL(cfg["smtp_host"], 465, timeout=20) as s:
                s.login(cfg["user"], cfg["app_password"])
        except Exception as e:  # noqa: BLE001
            print(f"FAILED: {type(e).__name__}: {e}\nCheck the App Password and that IMAP is on (Gmail settings > Forwarding and POP/IMAP).")
            return 1
        print(f"OK: {cfg['user']} can read ({n} unread) and send. Decoy replies go to: {', '.join(cfg['decoy_allow']) or 'nobody'}")
        return 0
    print("Gmail for Scambaiter. Use a NEW Gmail account just for the demo, with 2-step verification on.")
    print("Create an App Password at https://myaccount.google.com/apppasswords (16 letters).\n")
    user = input("Gmail address: ").strip()
    pw = getpass.getpass("App Password (hidden): ").replace(" ", "")
    allow = input("Addresses the decoy may reply to (your team's, comma-separated): ").strip()
    os.makedirs(data, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"user": user, "app_password": pw,
                   "decoy_allow": [a.strip().lower() for a in allow.split(",") if a.strip()]}, f, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    print(f"\nSaved to {path} (not in git). Check it with: python -m backend.mail test")
    return 0


if __name__ == "__main__":
    raise SystemExit(_setup())
