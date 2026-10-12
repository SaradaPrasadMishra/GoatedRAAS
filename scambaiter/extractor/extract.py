import re
from typing import List, Tuple
from contracts.models import Entity, ScamType
from contracts.normalize import normalise, clean_text

# Keywords for scam classification: (keyword, weight). Matched as whole words / phrases,
# so "pan" does not fire inside "company". English + Hinglish + a few Tamil/Hindi words.
SCAM_KEYWORDS = {
    "kyc_update": [("kyc", 3), ("re-kyc", 3), ("pan card", 2), ("aadhaar", 2), ("aadhar", 2), ("account blocked", 3),
                   ("account will be blocked", 3), ("blocked", 1), ("suspended", 1), ("expired", 1), ("verify your account", 2),
                   ("update now", 1), ("revalidate", 2), ("முடக்க", 3), ("புதுப்பி", 2), ("expire ho", 2), ("band ho", 2)],
    "refund_collect": [("refund", 3), ("collect request", 3), ("accept the request", 2), ("cashback", 2), ("return of", 1),
                       ("receive amount", 2), ("money back", 2), ("reversal", 2), ("upi pin to receive", 3)],
    "job_task": [("part time", 3), ("part-time", 3), ("work from home", 3), ("task", 2), ("rating", 2), ("like videos", 3),
                 ("youtube", 2), ("per day", 1), ("daily income", 2), ("job", 2), ("salary", 1), ("hr", 1), ("வேலை", 3), ("naukri", 2)],
    "lottery_prize": [("lottery", 3), ("prize", 3), ("winner", 3), ("won", 2), ("kbc", 3), ("lucky draw", 3), ("lucky", 2),
                      ("claim", 1), ("congratulations", 2), ("வாழ்த்து", 2), ("ticket", 1), ("jackpot", 3)],
    "digital_arrest": [("fir", 3), ("police", 3), ("cbi", 3), ("customs", 3), ("seized", 3), ("arrest", 3), ("warrant", 3),
                       ("case no", 2), ("case", 1), ("inquiry", 2), ("enquiry", 2), ("notice", 1), ("officer", 1), ("court", 3),
                       ("narcotics", 3), ("video verification", 3), ("cyber crime", 2), ("legal action", 2)],
    "investment": [("investment", 3), ("invest", 3), ("crypto", 3), ("usdt", 3), ("bitcoin", 3), ("trading", 3), ("stock", 2),
                   ("returns", 2), ("double", 2), ("doubling", 3), ("guaranteed", 2), ("portfolio", 3), ("profit", 2),
                   ("signals", 2), ("ipo", 2), ("ghante mein double", 3), ("allocation", 1)],
    "loan_app": [("loan", 3), ("instant loan", 3), ("credit", 2), ("pre-approved", 3), ("processing fee", 3), ("emi", 2),
                 ("borrow", 2), ("cibil", 2), ("disbursal", 3), ("கடன்", 3), ("karz", 2)],
}
_KW_RE = {t: [(re.compile(r"(?<![\w])" + re.escape(k) + r"(?![\w])"), w) for k, w in kws] for t, kws in SCAM_KEYWORDS.items()}

def _get_raw(original: str, clean_match: str) -> str:
    # Try exact match first
    if clean_match in original:
        return clean_match
    # Try zero-width regex
    pattern = r"[\u200b\u200c\u200d\ufeff]*".join(re.escape(c) for c in clean_match)
    match = re.search(pattern, original)
    return match.group(0) if match else clean_match

def extract_entities(text: str, message_id: str) -> list[Entity]:
    cleaned = clean_text(text)
    entities = []
    reserved_spans: List[Tuple[int, int]] = []
    
    def add_entity(e_type: str, match_obj, conf: float = 0.95):
        start, end = match_obj.span()
        for rs, re_end in reserved_spans:
            if not (end <= rs or start >= re_end):
                return
        reserved_spans.append((start, end))
        val = normalise(e_type, match_obj.group())
        raw = _get_raw(text, match_obj.group())
        entities.append(Entity(
            type=e_type, value=val, raw=raw, message_id=message_id, confidence=conf
        ))

    # 1. Email (has dot after @)
    for m in re.finditer(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", cleaned):
        add_entity("email", m)

    # 2. UPI ID (no dot after @)
    for m in re.finditer(r"[a-zA-Z0-9.\-_]+@[a-zA-Z]+", cleaned):
        if "." not in m.group().split("@")[1]:
            add_entity("upi_id", m)

    # 2b. Crypto (before URL/phone/IFSC, so digits or letters inside a wallet are never read as those)
    for m in re.finditer(r"\b(?:0x[a-fA-F0-9]{40}|bc1[a-zA-HJ-NP-Z0-9]{25,60}|T[1-9A-HJ-NP-Za-km-z]{33})\b", cleaned):
        add_entity("crypto_wallet", m)

    # 3. URL
    url_pattern = r"(?:https?://)?(?:www\.)?(?:[a-zA-Z0-9-]+\.)+(?:in|com|app|xyz|online|info|net|org|top|site|live|ly)(?:/[^\s]*)?|(?:https?://)?(?:bit\.ly|tinyurl\.com|t\.me|wa\.me)/[^\s]+"
    for m in re.finditer(url_pattern, cleaned, re.IGNORECASE):
        # Strip trailing punctuation
        m_str = m.group().rstrip('.,;:!?)("\'')
        conf = 0.95 if m_str.startswith("http") else 0.8
        # Make a fake match object for the stripped string to keep bounds accurate
        stripped_len = len(m_str)
        class FakeMatch:
            def span(self): return m.start(), m.start() + stripped_len
            def group(self): return m_str
        add_entity("url", FakeMatch(), conf)

    # 4. Phone (avoiding matches right before @upi)
    phone_pattern = r"(?<!\d)(?:\+?91[\-\s]?)?(?:0)?(?:91[\-\s]?)?[6-9]\d{4}[\-\s]?\d{5}(?!\s*@upi)"
    for m in re.finditer(phone_pattern, cleaned):
        add_entity("phone", m)

    # 6. IFSC (whole word only)
    for m in re.finditer(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", cleaned, re.IGNORECASE):
        add_entity("ifsc", m)

    # 7. Bank Account (9-18 digits, checking context)
    for m in re.finditer(r"(?<!\d)\d{9,18}(?!\d)", cleaned):
        start = max(0, m.start() - 20)
        context = cleaned[start:m.start()].lower()
        has_kw = any(k in context for k in ["a/c", "account", "acc no", "खाता"])
        conf = 0.85 if has_kw else 0.6
        add_entity("bank_account", m, conf)

    # Deduplicate by (type, value)
    seen = set()
    deduped = []
    for e in entities:
        if (e.type, e.value) not in seen:
            seen.add((e.type, e.value))
            deduped.append(e)
            
    return deduped

def classify_scam(text: str) -> ScamType:
    cleaned = clean_text(text).lower()
    scores = {t: sum(w for rx, w in pats if rx.search(cleaned)) for t, pats in _KW_RE.items()}
    best_type = max(scores, key=scores.get)
    if scores[best_type] > 0:
        return best_type
    return "other" if extract_entities(text, "m_classify") else "unknown"
