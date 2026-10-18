"""
Scam analysis shared by the evidence report, the dashboard (via the backend) and the
"Is this a scam?" quick check: red flags, risk level, safety record and the money the
scammer asked for. One place, so every screen says the same thing.
"""
from __future__ import annotations

import re

from contracts.models import Session

# (name, pattern). Latin-script words sit inside \b...\b; Hindi (romanised) and Tamil words
# sit outside it, because \b does not work reliably on Tamil script.
RED_FLAGS: list[tuple[str, re.Pattern]] = [(name, re.compile(rx, re.I)) for name, rx in [
    ("Urgency", r"\b(urgent(ly)?|immediately|right now|today|hurry|fast|quick(ly)?|expire[sd]?|last (reminder|chance)|time is running"
                r"|within \d+ ?(min|minutes|hours?)|abhi|turant|jaldi|sirf aaj)\b|உடனே|இன்று|அவசர"),
    ("Asks for OTP / PIN", r"\b(otp|pin|cvv|password|passcode)\b"),
    ("Demands payment", r"\b(pay|payment|transfer|deposit|fee|charges?|send (money|rs|₹)|collect request"
                        r"|(accept|approve) (the )?(collect )?request|scan (the )?qr|bhejo|bhej do|anuppunga)\b|₹|\brs\.? ?\d|அனுப்ப|செலுத்த"),
    ("Fake authority", r"\b(rbi|police|cbi|cyber ?cell|customs|income tax|trai|court|government|ministry"
                       r"|bank (official|manager|head office)|kyc (team|department)|sbi|hdfc|icici|amazon|flipkart"
                       r"|electricity board|paytm|phonepe|gpay|google pay)\b|காவல்|வங்கி"),
    ("Threat", r"\b(block(ed)?|suspend(ed)?|arrest|legal action|penalty|freeze|frozen|disconnect(ed)?|fir|warrant"
               r"|money laundering|case (is )?(registered|filed)|restrict(ed|ion)?|band ho)\b|முடக்க|கைது"),
    ("Too good to be true", r"\b(won|winner|lottery|prize|reward|cashback|double|guaranteed|profit|returns?"
                            r"|loan (is )?approved|earn(ings)?|bonus|refund|kamao|ghar baithe)\b|பரிசு"),
    ("Secrecy", r"\b(do not (tell|inform|share with)|don'?t tell|keep (it|this) (secret|confidential)"
                r"|stay on (the|this) call|kisi ko mat)\b|யாரிடமும் சொல்ல"),
    ("Moves you to WhatsApp / Telegram", r"\b(whatsapp|telegram|t\.me|wa\.me|signal app)\b"),
    # prompt injection: text written to take over an AI decoy or assistant, not a person
    ("Tries to trick the AI",
     r"\b(ignore|forget|disregard|override)\b.{0,30}\b(instructions?|rules|prompts?|guidelines|programming|above)\b"
     r"|\bsystem prompt\b|\bdeveloper mode\b|\bjailbreak\b"
     r"|\b(you are|you're|are you) (an? )?(ai|a\.i\.|bot|chat ?gpt|language model|llm|assistant)\b"
     r"|\b(act|behave|respond) as (an? )?(ai|assistant|admin|developer|system)\b"
     r"|\brepeat (after me|your instructions|the (text|words) above)\b"
     r"|\b(print|reveal|show|tell me) (your|the) (prompt|instructions|rules|system)\b"
     r"|<\s*/?\s*(system|assistant|im_start|im_end)\s*>|\[/?INST\]"),
]]
INJECTION = RED_FLAGS[-1][1]

_OTP = RED_FLAGS[1][1]
_PAY = RED_FLAGS[2][1]
_DIGITS4 = re.compile(r"\d(?:[\s-]?\d){3,}")                      # an OTP, PIN or account number
_PAID = re.compile(r"\bi(?: have|'ve)? (?:sent|paid|transferred)\b", re.I)

# money the scammer asks for: an amount close to a "pay / send / fee" word
_DEMAND = re.compile(r"\b(pay|transfer|deposit|send|fee|charges?|collect|bhejo|bhej|anuppunga)\b|அனுப்ப|செலுத்த", re.I)
_AMOUNT = re.compile(r"(?:₹|\brs\.?|\binr|\brupees?)\s?(\d[\d,]*(?:\.\d+)?)|\b(\d[\d,]*)\s?(?:rs\b|rupees\b|/-)", re.I)


def level_for(flags: list[str]) -> str:
    return "HIGH" if len(flags) >= 4 else "MEDIUM" if len(flags) >= 2 else "LOW"


def red_flags(text: str, has_link: bool = False) -> list[str]:
    flags = [name for name, rx in RED_FLAGS if rx.search(text)]
    if has_link:
        flags.append("Suspicious link")
    return flags


def demanded_amounts(text: str) -> set[int]:
    """Rupee amounts mentioned near a payment demand ('pay Rs 10', 'fee ₹499').
    Amounts that are only offers ('earn ₹3000 per day') are not counted."""
    found: set[int] = set()
    for d in _DEMAND.finditer(text):
        window = text[max(0, d.start() - 30):d.end() + 50]
        for a in _AMOUNT.finditer(window):
            raw = (a.group(1) or a.group(2) or "").replace(",", "")
            try:
                value = int(float(raw))
            except ValueError:
                continue
            if 0 < value < 10_000_000:
                found.add(value)
    return found


def analyse_session(session: Session) -> dict:
    scam = [m.text for m in session.messages if m.role == "scammer"]
    bot = [m.text for m in session.messages if m.role == "bot"]
    flags = red_flags("\n".join(scam), any(e.type == "url" for e in session.entities))
    amounts: set[int] = set()
    for t in scam:
        amounts |= demanded_amounts(t)
    return {
        "flags": flags, "level": level_for(flags),
        "otp_asked": sum(bool(_OTP.search(t)) for t in scam),
        "pay_asked": sum(bool(_PAY.search(t)) for t in scam),
        "shared": sum(bool(_DIGITS4.search(t)) for t in bot),
        "paid": sum(bool(_PAID.search(t)) for t in bot),
        "demanded": sum(amounts),
    }
