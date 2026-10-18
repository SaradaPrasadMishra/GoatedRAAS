"""
Security layer: accounts and roles, API keys, rate limits, a tamper-evident audit log,
the evidence seal (an HMAC hash chain over every message), encryption at rest, PII masking
and the prompt-injection detector. Standard library, plus `cryptography` for AES-GCM and
Ed25519 when it is installed (it is in requirements.txt).

Secrets live in data/ (gitignored), never in the repo:
    data/secrets.json   seal key, data key, signing key, the local intake key
    data/users.json     PBKDF2-SHA256 password hashes, roles
    data/api_keys.json  SHA-256 hashes of API keys, scopes, revoked flag

Command line (run from scambaiter/):
    python -m backend.security passwd admin            set a password
    python -m backend.security keys                    list API keys
    python -m backend.security newkey "Bank X" lookup  create an API key (shown once)
    python -m backend.security verify                  check every case seal + the audit log
    python -m backend.security tamper s_ab12cd34       DEMO: edit a message like a dishonest insider would
    python -m backend.security verify-alert alert.json check a signed bank alert
    python -m backend.security make-cert               self-signed HTTPS certificate in data/tls/
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone

log = logging.getLogger("scambaiter")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.environ.get("SCAMBAITER_DATA", os.path.join(ROOT, "data"))

ROLES = ("admin", "analyst")                       # people
SCOPES = ("intake", "lookup")                      # API keys: intake = send scams in, lookup = public API
SESSION_HOURS = 8
PBKDF2_ROUNDS = 310_000                            # OWASP 2023 guidance for PBKDF2-SHA256

try:
    from cryptography.exceptions import InvalidSignature, InvalidTag
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import serialization
    HAVE_CRYPTO = True
except Exception:  # noqa: BLE001
    HAVE_CRYPTO = False


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_private(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)


def _read(path: str, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


# ============================================================================ keys
class Keys:
    """Server secrets, created on first run. SCAMBAITER_DATA_KEY (base64, 32 bytes) overrides the
    data key so it can come from a vault instead of the disk."""

    def __init__(self, data_dir: str = DATA):
        self.path = os.path.join(data_dir, "secrets.json")
        s = _read(self.path, {})
        changed = False
        for name, make in (("seal_key", lambda: secrets.token_hex(32)),
                           ("data_key", lambda: base64.b64encode(secrets.token_bytes(32)).decode()),
                           ("sign_key", lambda: secrets.token_hex(32)),
                           ("intake_key", lambda: "sbk_phone_" + secrets.token_urlsafe(24)),
                           ("local_key", lambda: "sbk_local_" + secrets.token_urlsafe(24))):
            if not s.get(name):
                s[name] = make()
                changed = True
        if changed:
            _write_private(self.path, s)
        self.seal = bytes.fromhex(s["seal_key"])
        env_key = os.environ.get("SCAMBAITER_DATA_KEY")
        self.data = base64.b64decode(env_key) if env_key else base64.b64decode(s["data_key"])
        self.intake_key = s["intake_key"]   # the scammer's phone page (intake only)
        self.local_key = s["local_key"]     # tools on this laptop (simulator, evaluate): analyst
        self._sign_seed = bytes.fromhex(s["sign_key"])

    # ---------------------------------------------------------------- HMAC
    def mac(self, *parts: str) -> str:
        return hmac.new(self.seal, "\x1f".join(parts).encode("utf-8"), hashlib.sha256).hexdigest()

    # ---------------------------------------------------------------- encryption at rest
    def encrypt(self, plain: str, aad: str) -> str:
        """AES-256-GCM. The row id is bound in as associated data, so rows cannot be swapped."""
        if not HAVE_CRYPTO:
            return plain
        nonce = secrets.token_bytes(12)
        ct = AESGCM(self.data).encrypt(nonce, plain.encode("utf-8"), aad.encode("utf-8"))
        return "gcm1:" + base64.b64encode(nonce + ct).decode()

    def decrypt(self, stored: str, aad: str) -> str:
        if not stored.startswith("gcm1:"):
            return stored  # written before encryption was on; re-encrypted on the next save
        if not HAVE_CRYPTO:
            raise RuntimeError("database is encrypted but the 'cryptography' package is not installed")
        raw = base64.b64decode(stored[5:])
        try:
            return AESGCM(self.data).decrypt(raw[:12], raw[12:], aad.encode("utf-8")).decode("utf-8")
        except InvalidTag as e:
            raise ValueError(f"row {aad} failed decryption: wrong key or the ciphertext was modified") from e

    # ---------------------------------------------------------------- signatures (bank alerts)
    def sign(self, payload: bytes) -> dict:
        if HAVE_CRYPTO:
            key = Ed25519PrivateKey.from_private_bytes(self._sign_seed)
            return {"alg": "Ed25519", "key_id": self.key_id(), "value": base64.b64encode(key.sign(payload)).decode()}
        return {"alg": "HMAC-SHA256", "key_id": "local",
                "value": base64.b64encode(hmac.new(self.seal, payload, hashlib.sha256).digest()).decode()}

    def public_key(self) -> dict:
        if not HAVE_CRYPTO:
            return {"alg": "HMAC-SHA256", "note": "install 'cryptography' for Ed25519 public-key signatures"}
        pub = Ed25519PrivateKey.from_private_bytes(self._sign_seed).public_key()
        raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        return {"alg": "Ed25519", "key_id": self.key_id(), "public_key_b64": base64.b64encode(raw).decode(), "pem": pem}

    def key_id(self) -> str:
        if not HAVE_CRYPTO:
            return "local"
        pub = Ed25519PrivateKey.from_private_bytes(self._sign_seed).public_key()
        raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return "sb-" + hashlib.sha256(raw).hexdigest()[:16]


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify_signed(doc: dict, public_key_b64: str | None = None, keys: Keys | None = None) -> bool:
    sig = doc.get("signature") or {}
    body = canonical({k: v for k, v in doc.items() if k != "signature"})
    value = base64.b64decode(sig.get("value", ""))
    if sig.get("alg") == "Ed25519" and HAVE_CRYPTO:
        pub_raw = base64.b64decode(public_key_b64) if public_key_b64 else \
            base64.b64decode((keys or Keys()).public_key()["public_key_b64"])
        try:
            Ed25519PublicKey.from_public_bytes(pub_raw).verify(value, body)
            return True
        except InvalidSignature:
            return False
    if sig.get("alg") == "HMAC-SHA256":
        k = keys or Keys()
        return hmac.compare_digest(value, hmac.new(k.seal, body, hashlib.sha256).digest())
    return False


# ============================================================================ evidence seal
def genesis(keys: Keys, session_id: str) -> str:
    return keys.mac("genesis", session_id)


def seal_message(keys: Keys, prev: str, m) -> str:
    """Hash-chain link for one message: changing its text, role, time or order breaks every later link."""
    text_hash = hashlib.sha256(m.text.encode("utf-8")).hexdigest()
    return keys.mac(prev, m.session_id, m.id, m.role, m.ts, text_hash)


# ============================================================================ accounts
def _hash_password(password: str, salt: bytes | None = None, rounds: int = PBKDF2_ROUNDS) -> dict:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return {"salt": salt.hex(), "hash": dk.hex(), "rounds": rounds, "alg": "pbkdf2-sha256"}


def _check_password(password: str, rec: dict) -> bool:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(rec["salt"]), int(rec["rounds"]))
    return hmac.compare_digest(dk.hex(), rec["hash"])


class Accounts:
    def __init__(self, data_dir: str = DATA):
        self.path = os.path.join(data_dir, "users.json")
        self.lock = threading.Lock()
        self.users: dict = _read(self.path, {})
        self.created: dict[str, str] = {}   # passwords made on this start, printed once
        for user, role, env in (("admin", "admin", "SCAMBAITER_ADMIN_PASSWORD"),
                                ("analyst", "analyst", "SCAMBAITER_ANALYST_PASSWORD")):
            pw = os.environ.get(env)
            if user not in self.users:
                pw = pw or secrets.token_urlsafe(9)
                self.users[user] = {"role": role, **_hash_password(pw), "created": _now()}
                if not os.environ.get(env):
                    self.created[user] = pw
            elif pw and not _check_password(pw, self.users[user]):
                self.users[user].update(_hash_password(pw))
        _write_private(self.path, self.users)
        if self.created:
            with open(os.path.join(data_dir, "FIRST_LOGIN.txt"), "w", encoding="utf-8") as f:
                f.write("Scambaiter first-run passwords (change them: python -m backend.security passwd admin)\n")
                for u, p in self.created.items():
                    f.write(f"{u}: {p}\n")
        # login tokens live in memory only: a restart logs everyone out
        self.tokens: dict[str, dict] = {}

    def set_password(self, user: str, password: str, role: str | None = None) -> None:
        if len(password) < 8:
            raise ValueError("password must be at least 8 characters")
        with self.lock:
            rec = self.users.get(user, {"role": role or "analyst", "created": _now()})
            if role:
                rec["role"] = role
            rec.update(_hash_password(password))
            self.users[user] = rec
            _write_private(self.path, self.users)

    def login(self, user: str, password: str) -> dict | None:
        rec = self.users.get(user)
        if rec is None:
            _hash_password(password)  # same work either way, so timing doesn't reveal valid usernames
            return None
        if not _check_password(password, rec):
            return None
        token = secrets.token_urlsafe(32)
        info = {"user": user, "role": rec["role"], "expires": time.time() + SESSION_HOURS * 3600}
        with self.lock:
            self.tokens[hashlib.sha256(token.encode()).hexdigest()] = info
        return {"token": token, **info}

    def resolve(self, token: str | None) -> dict | None:
        if not token:
            return None
        key = hashlib.sha256(token.encode()).hexdigest()
        with self.lock:
            info = self.tokens.get(key)
            if info and info["expires"] < time.time():
                self.tokens.pop(key, None)
                return None
            return info

    def logout(self, token: str | None) -> None:
        if token:
            with self.lock:
                self.tokens.pop(hashlib.sha256(token.encode()).hexdigest(), None)


# ============================================================================ API keys
class ApiKeys:
    """Keys look like sbk_<id>_<secret>. Only a SHA-256 of the key is stored."""

    def __init__(self, keys: Keys, data_dir: str = DATA):
        self.path = os.path.join(data_dir, "api_keys.json")
        self.lock = threading.Lock()
        self.items: list[dict] = _read(self.path, [])
        self.phone, self.local = keys.intake_key, keys.local_key

    def _save(self) -> None:
        _write_private(self.path, self.items)

    def create(self, name: str, scope: str) -> dict:
        if scope not in SCOPES:
            raise ValueError(f"scope must be one of {', '.join(SCOPES)}")
        name = (name or "").strip()[:60]
        if not name:
            raise ValueError("name must not be empty")
        kid = secrets.token_hex(4)
        key = f"sbk_{kid}_{secrets.token_urlsafe(24)}"
        rec = {"id": kid, "name": name, "scope": scope, "hash": hashlib.sha256(key.encode()).hexdigest(),
               "created": _now(), "revoked": False, "last_used": None, "uses": 0}
        with self.lock:
            self.items.append(rec)
            self._save()
        return {**self.public(rec), "key": key}

    def revoke(self, kid: str) -> dict:
        with self.lock:
            for rec in self.items:
                if rec["id"] == kid:
                    rec["revoked"] = True
                    self._save()
                    return self.public(rec)
        raise KeyError(kid)

    def resolve(self, key: str | None) -> dict | None:
        if not key:
            return None
        if hmac.compare_digest(key, self.phone):
            return {"id": "phone", "name": "scammer phone page", "scope": "intake"}
        if hmac.compare_digest(key, self.local):
            return {"id": "local", "name": "tools on this laptop", "scope": "analyst"}
        h = hashlib.sha256(key.encode()).hexdigest()
        with self.lock:
            for rec in self.items:
                if hmac.compare_digest(rec["hash"], h) and not rec["revoked"]:
                    rec["last_used"] = _now()
                    rec["uses"] = rec.get("uses", 0) + 1
                    return rec
        return None

    def flush(self) -> None:
        with self.lock:
            self._save()

    @staticmethod
    def public(rec: dict) -> dict:
        return {k: rec.get(k) for k in ("id", "name", "scope", "created", "revoked", "last_used", "uses")}

    def list(self) -> list[dict]:
        with self.lock:
            return [self.public(r) for r in self.items]


# ============================================================================ rate limits
class RateLimiter:
    """Sliding window per (bucket, client)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.hits: dict[tuple[str, str], deque] = {}

    def allow(self, bucket: str, client: str, limit: int, window: float = 60.0) -> tuple[bool, int]:
        now = time.monotonic()
        with self.lock:
            q = self.hits.setdefault((bucket, client), deque())
            while q and q[0] <= now - window:
                q.popleft()
            if len(q) >= limit:
                return False, int(window - (now - q[0])) + 1
            q.append(now)
            return True, 0


class LoginGuard:
    """5 wrong passwords from one address locks logins from it for 5 minutes."""
    MAX, LOCK_S = 5, 300

    def __init__(self):
        self.lock = threading.Lock()
        self.fails: dict[str, list[float]] = {}

    def locked(self, ip: str) -> int:
        with self.lock:
            f = [t for t in self.fails.get(ip, []) if t > time.time() - self.LOCK_S]
            self.fails[ip] = f
            return int(self.LOCK_S - (time.time() - f[0])) + 1 if len(f) >= self.MAX else 0

    def failed(self, ip: str) -> None:
        with self.lock:
            self.fails.setdefault(ip, []).append(time.time())

    def ok(self, ip: str) -> None:
        with self.lock:
            self.fails.pop(ip, None)


# ============================================================================ audit log
class Audit:
    """Append-only, hash-chained log: who did what, when, from where. Editing or deleting any
    row breaks the chain from that row on, and /api/admin/audit shows where."""

    def __init__(self, keys: Keys, db_path: str):
        self.keys = keys
        self.lock = threading.Lock()
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, ts TEXT, actor TEXT, role TEXT,"
                        " ip TEXT, action TEXT, target TEXT, detail TEXT, prev TEXT, hash TEXT)")
        self.db.commit()

    def record(self, actor: str, role: str, ip: str, action: str, target: str = "", detail: str = "") -> None:
        with self.lock:
            row = self.db.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            seq, prev = (row[0] + 1, row[1]) if row else (1, self.keys.mac("audit-genesis"))
            ts = _now()
            fields = [str(seq), ts, actor, role, ip, action, target, detail[:500]]
            h = self.keys.mac(prev, *fields)
            self.db.execute("INSERT INTO audit VALUES (?,?,?,?,?,?,?,?,?,?)", (seq, ts, actor, role, ip, action,
                                                                             target, detail[:500], prev, h))
            self.db.commit()

    def entries(self, limit: int = 200) -> list[dict]:
        with self.lock:
            rows = self.db.execute("SELECT seq, ts, actor, role, ip, action, target, detail FROM audit "
                                   "ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
        cols = ("seq", "ts", "actor", "role", "ip", "action", "target", "detail")
        return [dict(zip(cols, r)) for r in rows]

    def verify(self) -> dict:
        with self.lock:
            rows = self.db.execute("SELECT seq, ts, actor, role, ip, action, target, detail, prev, hash "
                                   "FROM audit ORDER BY seq").fetchall()
        prev = self.keys.mac("audit-genesis")
        for i, r in enumerate(rows):
            seq = r[0]
            if seq != i + 1 or r[8] != prev or r[9] != self.keys.mac(prev, *[str(x) for x in r[:8]]):
                return {"ok": False, "entries": len(rows), "broken_at": seq}
            prev = r[9]
        return {"ok": True, "entries": len(rows), "broken_at": None, "head": prev[:16]}


# ============================================================================ PII masking
_CARD = re.compile(r"(?i)\b(card|debit|credit|visa|master ?card|rupay)\b\D{0,25}(\d(?:[ -]?\d){12,18})\b")
_PAN = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
_AADHAAR = re.compile(r"(?i)(aadh?aar|uidai|uid)\D{0,25}(\d{4}[ -]?\d{4}[ -]?\d{4})")


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def mask_text(text: str) -> str:
    """Hide a victim's card, Aadhaar and PAN numbers that show up in a forwarded message.
    Scammer identifiers (UPI IDs, phones, mule accounts) are evidence and stay visible."""
    def card(m):
        d = re.sub(r"\D", "", m.group(2))
        if 13 <= len(d) <= 19 and _luhn(d):
            return m.group()[:m.start(2) - m.start()] + "[card ••••" + d[-4:] + "]"
        return m.group()
    text = _CARD.sub(card, text)
    text = _AADHAAR.sub(lambda m: m.group(1) + " [Aadhaar ••••" + re.sub(r"\D", "", m.group(2))[-4:] + "]", text)
    return _PAN.sub(lambda m: f"[PAN {m.group()[:2]}•••••{m.group()[-1]}]", text)


def mask_contact(value: str | None) -> str | None:
    """Reporter details (victim PII): 'priya.k@gmail.com' -> 'p••••k@gmail.com', '+919876543210' -> '+91••••••3210'."""
    if not value:
        return value
    if "@" in value:
        name, _, domain = value.partition("@")
        return (name[0] + "••••" + (name[-1] if len(name) > 1 else "")) + "@" + domain
    digits = re.sub(r"\D", "", value)
    return (value[:3] if value.startswith("+") else "") + "••••••" + digits[-4:]


# ============================================================================ prompt injection
try:
    from report.analysis import INJECTION   # one pattern, shared with the red flags
except Exception:  # noqa: BLE001
    INJECTION = re.compile(r"\bignore\b.{0,30}\binstructions?\b|\bsystem prompt\b", re.I)


def injection_attempt(text: str) -> bool:
    return bool(INJECTION.search(text or ""))


# ============================================================================ HTTPS
def make_cert(out_dir: str) -> str:
    """Self-signed certificate for this laptop (browsers will warn once; production uses a real CA)."""
    if not HAVE_CRYPTO:
        return "install 'cryptography' first"
    import datetime as dt
    import ipaddress
    import socket
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Scambaiter local")])
    alt = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        alt.append(x509.IPAddress(ipaddress.ip_address(s.getsockname()[0])))
        s.close()
    except OSError:
        pass
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=365)).add_extension(x509.SubjectAlternativeName(alt), False)
            .sign(key, hashes.SHA256()))
    os.makedirs(out_dir, exist_ok=True)
    cert_path, key_path = os.path.join(out_dir, "cert.pem"), os.path.join(out_dir, "key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    return f"wrote {cert_path} and {key_path}\nstart: python -m backend.main --tls-cert {cert_path} --tls-key {key_path}"


# ============================================================================ CLI
def _cli(argv: list[str]) -> int:
    import getpass
    if not argv:
        print(__doc__)
        return 2
    cmd, args = argv[0], argv[1:]
    if cmd == "passwd" and args:
        pw = getpass.getpass(f"New password for {args[0]}: ")
        Accounts().set_password(args[0], pw, args[1] if len(args) > 1 else None)
        print("saved")
    elif cmd == "keys":
        for k in ApiKeys(Keys()).list():
            print(f"{k['id']:10} {k['scope']:7} {'REVOKED' if k['revoked'] else 'active ':7} {k['name']}")
    elif cmd == "newkey" and len(args) == 2:
        k = ApiKeys(Keys()).create(args[0], args[1])
        print(f"API key for {k['name']} ({k['scope']}), shown only once:\n  {k['key']}")
    elif cmd in ("verify", "tamper"):
        from backend.store import Store
        store = Store()
        if cmd == "tamper":
            sid = args[0] if args else next(iter(store.sessions), None)
            if not sid:
                print("no cases to tamper with")
                return 1
            print(store.tamper_for_demo(sid))
            return 0
        bad = 0
        for sid in store.sessions:
            r = store.verify(sid)
            bad += not r["ok"]
            print(f"{sid}  {'SEALED  ' if r['ok'] else 'TAMPERED'}  {r['messages']} messages  {r.get('reason') or ''}")
        a = Audit(store.keys, store.path).verify()
        print(f"audit log: {'intact' if a['ok'] else 'BROKEN at entry ' + str(a['broken_at'])} ({a['entries']} entries)")
        return 1 if bad or not a["ok"] else 0
    elif cmd == "make-cert":
        print(make_cert(os.path.join(DATA, "tls")))
    elif cmd == "verify-alert" and args:
        doc = _read(args[0], {})
        good = verify_signed(doc, args[1] if len(args) > 1 else None)
        print("signature VALID" if good else "signature INVALID")
        return 0 if good else 1
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
