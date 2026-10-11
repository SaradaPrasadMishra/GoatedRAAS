"""
SHARED NORMALISATION  (contracts/normalize.py)
==============================================
Campaign linking only works if two sessions that mention the same UPI ID,
phone or link produce the SAME string. Everyone imports these functions;
nobody writes their own. Standard library only.
"""
from __future__ import annotations

import re
import unicodedata
from urllib.parse import urlsplit

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"), None)


def clean_text(s: str) -> str:
    """Unicode-normalise and strip zero-width chars scammers use to dodge filters."""
    return unicodedata.normalize("NFKC", s).translate(_ZERO_WIDTH)


def norm_upi(raw: str) -> str:
    return clean_text(raw).strip().strip(".,;:!?)(").lower()


def norm_phone(raw: str) -> str:
    """Indian numbers -> '+91XXXXXXXXXX'. Anything else -> '+' + digits."""
    digits = re.sub(r"\D", "", clean_text(raw))
    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    elif len(digits) == 11 and digits.startswith("0"):
        digits = digits[1:]
    if len(digits) == 10 and digits[0] in "6789":
        return "+91" + digits
    return "+" + digits


def norm_url(raw: str) -> str:
    """'HTTPS://www.SBI-kyc.in/Verify/?a=1' -> 'sbi-kyc.in/Verify'. Query strings dropped."""
    s = clean_text(raw).strip().strip(".,;:!?)(\"'")
    if "://" not in s:
        s = "http://" + s
    parts = urlsplit(s)
    host = (parts.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    path = parts.path.rstrip("/")
    return host + path


def norm_bank_account(raw: str) -> str:
    return re.sub(r"\D", "", clean_text(raw))


def norm_ifsc(raw: str) -> str:
    return clean_text(raw).strip().upper()


def norm_email(raw: str) -> str:
    return clean_text(raw).strip().strip(".,;:!?)(").lower()


def norm_crypto(raw: str) -> str:
    s = clean_text(raw).strip()
    return s.lower() if s.lower().startswith("0x") else s


NORMALISERS = {
    "upi_id": norm_upi,
    "phone": norm_phone,
    "url": norm_url,
    "bank_account": norm_bank_account,
    "ifsc": norm_ifsc,
    "email": norm_email,
    "crypto_wallet": norm_crypto,
}


def normalise(entity_type: str, raw: str) -> str:
    return NORMALISERS[entity_type](raw)


def node_id(entity_type: str, value: str) -> str:
    """Graph node id for an entity. Use this everywhere."""
    return f"{entity_type}:{value}"
