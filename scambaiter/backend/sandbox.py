"""
Link detonation sandbox: open a scam link safely and record what the page does.

The decoy never opens links. An analyst (or auto-mode) sends a captured link here instead. The sandbox
fetches it the way a phone browser would, without running JavaScript, submitting forms or saving
downloads, and reports: the redirect chain, the final address and server, whether it asks for
passwords / OTP / card / UPI PIN, which brand it pretends to be, APK downloads, and any UPI IDs,
phone numbers or accounts printed on the page (they are added to the case and can link gangs).

Modes (SCAMBAITER_SANDBOX):
    demo  (default)  every link is served by a built-in fake scam site on 127.0.0.1. Nothing leaves the
                     laptop; results are labelled SIMULATION. Use this for demos and tests.
    live             really fetches the link. Run it on an isolated machine or VM, and send its traffic
                     through a separate egress (SCAMBAITER_SANDBOX_PROXY=http://host:port) so the scam
                     site can't see or block your organisation's network.
    off              disabled.

Guards in live mode: only http/https on ports 80/443, the hostname is resolved first and private,
loopback, link-local and reserved addresses are refused (no access to the local network), the
connection is pinned to that checked address, at most 5 redirects (each re-checked), 10 s timeout,
2 MB cap, no cookies, nothing written to disk.
"""
from __future__ import annotations

import hashlib
import html
import http.client
import ipaddress
import os
import re
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urljoin, urlsplit

MAX_BYTES = 2 * 1024 * 1024
TIMEOUT = 10.0
MAX_REDIRECTS = 5
UA = ("Mozilla/5.0 (Linux; Android 13; SM-A145F) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/124.0 Mobile Safari/537.36")

# brand -> its real registrable domains (a page naming the brand on any other domain is impersonation)
BRANDS = {
    "SBI": (r"\bsbi\b|state bank|yono", ("sbi.co.in", "onlinesbi.sbi", "sbi.bank.in", "yonosbi.com")),
    "HDFC Bank": (r"\bhdfc\b", ("hdfcbank.com", "hdfc.bank.in")),
    "ICICI Bank": (r"\bicici\b", ("icicibank.com", "icici.bank.in")),
    "Axis Bank": (r"\baxis bank\b", ("axisbank.com", "axis.bank.in")),
    "Kotak": (r"\bkotak\b", ("kotak.com",)),
    "Paytm": (r"\bpaytm\b", ("paytm.com", "paytmbank.com")),
    "PhonePe": (r"\bphone ?pe\b", ("phonepe.com",)),
    "Google Pay": (r"\bgoogle ?pay\b|\bgpay\b", ("google.com", "pay.google.com")),
    "Amazon": (r"\bamazon\b", ("amazon.in", "amazon.com")),
    "Flipkart": (r"\bflipkart\b", ("flipkart.com",)),
    "Income Tax Dept": (r"income ?tax", ("incometax.gov.in",)),
    "RBI": (r"\brbi\b|reserve bank", ("rbi.org.in",)),
    "India Post": (r"india ?post", ("indiapost.gov.in",)),
    "Electricity board": (r"electricity|bescom|tneb|tangedco|msedcl", ()),
    "KBC / lottery": (r"\bkbc\b|kaun banega|lucky draw|lottery", ()),
    "Police / CBI": (r"\bcbi\b|cyber ?cell|police|customs|narcotics", ("gov.in", "nic.in")),
}
_CRED = [("password", r"type\s*=\s*[\"']?password|\bpassword\b|\bpasscode\b"),
         ("OTP", r"\botp\b|one[- ]time password"),
         ("card number / CVV", r"\bcvv\b|card ?number|expiry|\bdebit card\b|\bcredit card\b"),
         ("UPI PIN / MPIN", r"upi ?pin|\bmpin\b|\btpin\b"),
         ("Aadhaar / PAN", r"aadh?aar|\bpan (card|number)\b")]
_SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "t.ly", "shorturl.at")


def mode() -> str:
    m = os.environ.get("SCAMBAITER_SANDBOX", "demo").lower()
    return m if m in ("demo", "live", "off") else "demo"


def _registrable(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "gov", "nic", "org", "net", "ac", "bank") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _normalise_url(url: str) -> str:
    url = (url or "").strip()
    if not re.match(r"(?i)^[a-z][a-z0-9+.-]*://", url):
        url = "http://" + url
    return url


class Blocked(Exception):
    pass


def _check_target(url: str, allow: set[str]) -> tuple[str, str, int, str]:
    """-> (scheme, host, port, ip). Refuses anything that could reach our own network."""
    p = urlsplit(url)
    scheme = (p.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise Blocked(f"scheme {scheme or '?'} is not allowed")
    host = (p.hostname or "").lower()
    if not host:
        raise Blocked("no host")
    port = p.port or (443 if scheme == "https" else 80)
    if p.username or p.password:
        raise Blocked("credentials in the link")
    if f"{host}:{port}" in allow:
        return scheme, host, port, socket.gethostbyname(host)
    if port not in (80, 443):
        raise Blocked(f"port {port} is not allowed")
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise Blocked(f"domain does not resolve ({e.strerror or e})") from e
    ips = [i[4][0] for i in infos]
    for ip in ips:
        a = ipaddress.ip_address(ip.split("%")[0])
        if a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified:
            raise Blocked(f"{host} points to an internal address ({ip})")
    return scheme, host, port, ips[0]


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, ip, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, ip, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _fetch_once(url: str, allow: set[str], proxy: str | None) -> dict:
    scheme, host, port, ip = _check_target(url, allow)
    p = urlsplit(url)
    path = (p.path or "/") + (f"?{p.query}" if p.query else "")
    tls_ok = None
    if proxy:
        pp = urlsplit(proxy)
        if scheme == "https":
            conn = http.client.HTTPSConnection(pp.hostname, pp.port or 8080, timeout=TIMEOUT,
                                               context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(pp.hostname, pp.port or 8080, timeout=TIMEOUT)
        conn.set_tunnel(host, port)
    elif scheme == "https":
        conn = _PinnedHTTPS(host, port, ip, TIMEOUT, ssl.create_default_context())
    else:
        conn = _PinnedHTTP(host, port, ip, TIMEOUT)
    try:
        conn.request("GET", path, headers={"Host": host if port in (80, 443) else f"{host}:{port}", "User-Agent": UA,
                                           "Accept": "text/html,*/*;q=0.8", "Accept-Language": "en-IN,en;q=0.8",
                                           "Connection": "close"})
        r = conn.getresponse()
        tls_ok = scheme == "https"
        body, total = b"", 0
        hasher = hashlib.sha256()
        while True:
            chunk = r.read(65536)
            if not chunk:
                break
            total += len(chunk)
            hasher.update(chunk)
            if len(body) < MAX_BYTES:
                body += chunk[:MAX_BYTES - len(body)]
            if total > 8 * MAX_BYTES:
                break     # stop reading huge downloads; the hash covers what we read
        return {"url": url, "status": r.status, "ip": ip, "server": r.getheader("Server") or "",
                "location": r.getheader("Location"), "type": (r.getheader("Content-Type") or "").split(";")[0].lower(),
                "disposition": r.getheader("Content-Disposition") or "", "bytes": total,
                "sha256": hasher.hexdigest(), "body": body, "tls": tls_ok}
    except ssl.SSLError as e:
        raise Blocked(f"TLS certificate problem: {e.reason or e}") from e
    finally:
        conn.close()


def fetch(url: str, allow: set[str] | None = None, proxy: str | None = None) -> dict:
    allow = allow or set()
    chain, cur = [], _normalise_url(url)
    for _ in range(MAX_REDIRECTS + 1):
        hop = _fetch_once(cur, allow, proxy)
        chain.append({k: hop[k] for k in ("url", "status", "ip", "server")})
        if hop["status"] in (301, 302, 303, 307, 308) and hop["location"]:
            cur = urljoin(cur, hop["location"])
            continue
        hop["chain"] = chain
        return hop
    raise Blocked(f"more than {MAX_REDIRECTS} redirects")


# ---------------------------------------------------------------------------- analysis
def _text(body: bytes) -> str:
    t = body.decode("utf-8", "replace")
    t = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", t)
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", t))).strip()


def analyse(url: str, hop: dict, extract=None) -> dict:
    """Findings and a verdict for one fetched page. `extract(text)` returns identifier (type, value) pairs."""
    findings: list[dict] = []
    add = lambda sev, what: findings.append({"severity": sev, "finding": what})  # noqa: E731
    first_host = (urlsplit(_normalise_url(url)).hostname or "").lower()
    final_host = (urlsplit(hop["chain"][-1]["url"]).hostname or "").lower()
    raw = hop["body"].decode("utf-8", "replace")
    page = _text(hop["body"]) if "html" in hop["type"] or raw.lstrip().startswith("<") else ""
    title = html.unescape(re.sub(r"\s+", " ", (re.search(r"(?is)<title[^>]*>(.*?)</title>", raw) or [None, ""])[1])).strip()[:120]
    hay = (title + " " + page).lower()

    is_apk = (hop["type"] in ("application/vnd.android.package-archive", "application/octet-stream")
              and re.search(r"\.(apk|exe|scr|bat)\b", hop["chain"][-1]["url"] + hop["disposition"], re.I)) \
        or hop["type"] == "application/vnd.android.package-archive"
    if is_apk:
        add("high", f"Downloads an app installer ({hop['bytes']:,} bytes, sha256 {hop['sha256'][:16]}…): "
                    "fake apps steal OTPs and take over phones")
    forms = re.findall(r"(?is)<form\b[^>]*>.*?</form>", raw)
    if not is_apk and re.search(r"(?i)href\s*=\s*[\"']?[^\"' >]+\.apk\b", raw):
        add("high", "Pushes you to install an app (.apk) from outside the Play Store")
    form_text = " ".join(forms).lower()
    asked = [name for name, rx in _CRED if re.search(rx, form_text, re.I)] if forms else []
    if asked:
        add("high", "Form asks for " + ", ".join(asked))
    brands = [b for b, (rx, _) in BRANDS.items() if re.search(rx, hay, re.I)]
    reg = _registrable(final_host)
    fakes = [b for b in brands if BRANDS[b][1] and not any(reg == d or final_host.endswith("." + d) for d in BRANDS[b][1])]
    fakes += [b for b in brands if not BRANDS[b][1]]
    if fakes:
        add("high" if asked or is_apk else "medium", f"Pretends to be {', '.join(fakes)} on {reg}, not an official domain")
    if "xn--" in first_host or "xn--" in final_host:
        add("medium", "Look-alike domain written in another script (punycode)")
    tokens = re.split(r"[-.]", first_host)
    if any(re.fullmatch(r"sbi|hdfc|icici|axis|paytm|phonepe|gpay|amazon|flipkart|kyc|rbi|npci|yono", t) for t in tokens) \
            and _registrable(first_host) not in [d for _, (_, ds) in BRANDS.items() for d in ds]:
        add("medium", f"Domain {first_host} borrows a bank or app name")
    hosts = [(urlsplit(h["url"]).hostname or "").lower() for h in hop["chain"]]
    if len({_registrable(h) for h in hosts}) > 1:
        add("medium", "Redirects through " + " → ".join(dict.fromkeys(hosts)))
    if any(h in _SHORTENERS for h in hosts):
        add("low", "Hidden behind a link shortener")
    if re.search(r"(?i)http-equiv=[\"']?refresh|location\.(href|replace)|window\.location", raw):
        add("low", "Uses a script or meta refresh to send you elsewhere")
    for f in forms:
        action = (re.search(r"(?i)action\s*=\s*[\"']?([^\"' >]+)", f) or [None, ""])[1]
        if action.startswith("http"):
            ah = (urlsplit(action).hostname or "").lower()
            if ah and _registrable(ah) != _registrable(final_host):
                add("medium", f"Form sends what you type to another site: {ah}")
            elif action.startswith("http://"):
                add("medium", "Form sends what you type without encryption (http)")
    if hop["chain"][-1]["url"].startswith("http://") and asked:
        add("medium", "Asks for secrets over an unencrypted (http) page")
    if re.search(r"(?i)\b(within \d+ (minutes|hours)|expire[sd]? today|account will be (blocked|suspended)|last chance)\b", hay):
        add("low", "Urgent countdown or threat on the page")
    ids = []
    if extract and page:
        try:
            ids = [(t, v) for t, v in extract(page[:20000]) if not (t == "url" and _registrable(v.split("/")[0]) == reg)]
        except Exception:  # noqa: BLE001
            ids = []
    if any(t in ("upi_id", "bank_account", "phone", "crypto_wallet") for t, _ in ids):
        add("medium", "Shows payment details: " + ", ".join(v for t, v in ids if t in ("upi_id", "bank_account", "phone", "crypto_wallet"))[:200])
    findings.sort(key=lambda f: ("high", "medium", "low").index(f["severity"]))
    sev = [f["severity"] for f in findings]
    verdict = "MALICIOUS" if "high" in sev else "SUSPICIOUS" if "medium" in sev else "NO SIGNS FOUND"
    return {"verdict": verdict, "title": title, "final_url": hop["chain"][-1]["url"], "status": hop["status"],
            "server": hop["chain"][-1]["server"], "ip": hop["chain"][-1]["ip"], "content_type": hop["type"],
            "bytes": hop["bytes"], "sha256": hop["sha256"], "chain": hop["chain"], "findings": findings,
            "identifiers": [{"type": t, "value": v} for t, v in ids], "brands": fakes}


# ---------------------------------------------------------------------------- the sandbox
class Sandbox:
    def __init__(self, extract=None):
        self.extract = extract          # text -> [(type, value)] (the case extractor)
        self.mode = mode()
        self.proxy = os.environ.get("SCAMBAITER_SANDBOX_PROXY") or None
        self.allow = {a.strip().lower() for a in os.environ.get("SCAMBAITER_SANDBOX_ALLOW", "").split(",") if a.strip()}
        self._demo: DemoSite | None = None
        self.lock = threading.Lock()

    def status(self) -> dict:
        return {"mode": self.mode, "egress": "separate proxy" if self.proxy else
                ("none: demo site on this laptop" if self.mode == "demo" else "this machine's network"),
                "javascript": "never run", "forms": "never submitted", "downloads": "hashed, never saved"}

    def detonate(self, url: str) -> dict:
        if self.mode == "off":
            raise ValueError("the link sandbox is off (SCAMBAITER_SANDBOX=off)")
        url = _normalise_url(url)[:2000]
        started = time.time()
        target, allow = url, self.allow
        if self.mode == "demo":
            with self.lock:
                if self._demo is None:
                    self._demo = DemoSite()
            p = urlsplit(url)
            target = f"http://127.0.0.1:{self._demo.port}/go/{p.hostname or 'unknown'}{p.path or '/'}"
            allow = {f"127.0.0.1:{self._demo.port}"}
        base = {"url": url, "mode": self.mode, "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "simulation": self.mode == "demo"}
        try:
            hop = fetch(target, allow, None if self.mode == "demo" else self.proxy)
        except Blocked as e:
            return {**base, "verdict": "BLOCKED", "reason": str(e), "findings": [], "identifiers": [], "chain": []}
        except (OSError, http.client.HTTPException) as e:
            return {**base, "verdict": "UNREACHABLE", "reason": f"{type(e).__name__}: {e}"[:200],
                    "findings": [{"severity": "low", "finding": "Site did not answer: often already taken down"}],
                    "identifiers": [], "chain": []}
        if self.mode == "demo":   # show the scam's own addresses, not the local demo server
            first = urlsplit(url).hostname or "unknown"
            for h in hop["chain"]:
                path = urlsplit(h["url"]).path
                m = re.match(r"^/(?:go|site)/([^/]+)(/.*)?$", path)
                h["url"] = f"https://{m.group(1)}{m.group(2) or '/'}" if m else f"https://{first}{path}"
                h["ip"] = "203.0.113." + str(sum(map(ord, h["url"])) % 250 + 1)   # TEST-NET documentation range
                h["server"] = "nginx (demo site)"
        result = {**base, **analyse(url, hop, self.extract)}
        result["seconds"] = round(time.time() - started, 2)
        return result


# ---------------------------------------------------------------------------- demo scam site
_PAGES = {
    "bank": ("SBI YONO - KYC Update", "State Bank of India", "Your YONO account will be blocked today. Complete KYC within 30 minutes.",
             ["User ID", "Password", "Registered mobile", "OTP"], "Pay Rs 10 verification fee to sbi.verify.desk@ybl or call 8001234567.",
             "/download/SBI-KYC-Update.apk"),
    "job": ("Amazon Work From Home - Task Portal", "Amazon Jobs", "Earn Rs 3000 daily. Last chance: only 5 seats left today.",
            ["Full name", "Mobile", "UPI ID"], "Pay joining fee Rs 499 to tasks.payout.hr@okicici. Telegram support: t.me/amzn_task_hr",
            None),
    "power": ("Electricity Bill Payment - Disconnection Notice", "Electricity Board", "Your power will be disconnected tonight.",
              ["Consumer number", "Debit card number", "CVV", "Expiry"], "Call officer 7012345678 or pay to ebill.desk@paytm.", None),
    "police": ("Cyber Crime Cell - Case Verification", "CBI Cyber Cell", "A case is registered against you. Do not tell anyone.",
               ["Aadhaar number", "PAN card number", "Bank account"], "Transfer security deposit to account 50100234567890 IFSC HDFC0001234.",
               None),
    "prize": ("KBC Lucky Draw Winner", "KBC Lottery", "You won Rs 25 lakh! Claim within 24 hours.",
              ["Name", "Mobile", "UPI PIN"], "Pay processing fee Rs 5000 to kbc.prize.office@ybl.", None),
}


def _kind(host: str) -> str:
    h = host.lower()
    for kind, rx in (("job", r"job|task|work|amzn|amazon|hr"), ("power", r"bill|power|electric|eb-"),
                     ("police", r"cbi|police|cyber|court|customs"), ("prize", r"kbc|prize|lottery|lucky|win")):
        if re.search(rx, h):
            return kind
    return "bank"


class _DemoHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", ctype="text/html; charset=utf-8", headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "nginx")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        m = re.match(r"^/go/([^/]+)(/.*)?$", self.path)
        if m:   # first hop: a tracking redirect, like real kits use
            if (m.group(2) or "").lower().endswith(".apk"):
                return self._send(302, headers={"Location": "/download/update.apk"})
            return self._send(302, headers={"Location": f"/site/{m.group(1)}/login"})
        m = re.match(r"^/site/([^/]+)/", self.path)
        if self.path.startswith("/download/"):
            return self._send(200, b"PK\x03\x04 DEMO APK (simulation, not a real app) " + b"\0" * 2048,
                              "application/vnd.android.package-archive",
                              {"Content-Disposition": 'attachment; filename="update.apk"'})
        if not m:
            return self._send(404, b"not found")
        title, brand, urgent, fields, pay, apk = _PAGES[_kind(m.group(1))]
        inputs = "".join(f'<label>{f}<input name="f{i}" type="{"password" if "Password" in f or "PIN" in f or "OTP" in f else "text"}"></label>'
                         for i, f in enumerate(fields))
        page = f"""<!doctype html><html><head><title>{title}</title><meta name="viewport" content="width=device-width">
<script>setTimeout(function(){{window.location.href='/site/{m.group(1)}/thanks'}},90000)</script></head>
<body><h1>{brand}</h1><p><b>{urgent}</b></p>
<form method="post" action="https://collect-{m.group(1).split('.')[0][:24]}.top/submit.php">{inputs}<button>Verify now</button></form>
<p>{pay}</p>{f'<a href="{apk}">Download the official app</a>' if apk else ''}
<p>SIMULATION: synthetic scam page served by the Scambaiter demo sandbox.</p></body></html>"""
        self._send(200, page.encode())


class DemoSite:
    """A fake scam site on 127.0.0.1 (random port) for demos and tests."""

    def __init__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _DemoHandler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True, name="sandbox-demo-site").start()
