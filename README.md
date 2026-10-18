# Scambaiter

**An AI that talks to scammers so real people don't have to.**

Forward a scam message (fake KYC, refund "collect request", part-time job task, lottery,
"digital arrest", crypto doubling, instant loan). A local AI replies as a slow, confused,
gullible person and keeps the scammer talking. Every turn it pulls out the scammer's
**UPI IDs, phone numbers, links, bank accounts, IFSC codes, emails and crypto wallets**,
links sessions that reuse them into **gangs**, shows everything on a live dashboard, and
produces an **evidence report** a victim can file at cybercrime.gov.in or quote when calling 1930.

Built for Mission'26 (VIT Chennai SCOPE + BIS, FinTech theme). Runs fully offline:
the only LLM is a local open-weight model through Ollama. **Simulation only:** no real
payments, no real people, and the bot never shares an OTP, PIN or account number.

## Run it (Windows)

One-time setup (Python 3.10+, Git and [Ollama](https://ollama.com) installed):
```
git clone https://github.com/SaradaPrasadMishra/GoatedRAAS.git
cd GoatedRAAS\scambaiter
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
ollama pull qwen2.5:7b
```
On a laptop with less than 16 GB RAM use `qwen2.5:1.5b` and `set OLLAMA_MODEL=qwen2.5:1.5b`.

Start the backend (terminal 1), or double-click `run_demo.bat`:
```
cd GoatedRAAS\scambaiter
.venv\Scripts\activate
set OLLAMA_KEEP_ALIVE=30m
python -m backend.main --lan --reset
```
The banner should say `extractor real`, `campaigns real`, `report real`, `bot Ollama qwen2.5:7b`,
`security login on · encryption AES-256-GCM`. Open **http://localhost:8000**, sign in, press F11.

**Sign in:** the first start creates `admin` and `analyst` with random passwords, printed in the
backend window and saved in `scambaiter/data/FIRST_LOGIN.txt`. Change one with
`python -m backend.security passwd admin`. `--lan` lets the scammer's phone join: the banner prints a
phone link ending in `#k=…` that pairs it (without `--lan` the backend only listens on this laptop).

Play the stage demo (terminal 2): three linked scams arrive 4 s apart.
```
cd GoatedRAAS\scambaiter
.venv\Scripts\activate
python -m simulator.run --live
```

### Is the AI really talking?
- The backend banner must say `bot Ollama qwen2.5:7b`, and the dashboard badge must say **AI live**.
  If it says **AI off · canned replies**, the decoy is using about 20 pre-written fallback lines:
  start the Ollama app, run `ollama pull qwen2.5:7b` (or set `OLLAMA_MODEL` to the model you pulled),
  and restart the backend. The backend console names the missing model.
- The scammer side of `--live` is written by the local model when Ollama is running (each line is
  tagged `[AI]` in terminal 2) and falls back to P4's scripts otherwise (`[script]`). Planted phone
  numbers and UPI IDs are still revealed on their scheduled turns so the demo always captures them.
- For a fully unscripted run, type your own scam into the intake slip and keep typing the scammer's
  lines in the chat box: everything the decoy says comes from the model.

### Handy on stage
- **Sample scams:** one-click KYC, digital arrest, job task and two Hinglish scams on the intake slip.
- **Just check: is this a scam?** gives a verdict and the red flags without starting a decoy.
- **Gang dossier:** click a gang on the evidence board; export its identifiers as CSV for a bank or I4C.
- **Backup replay:** in rehearsal, open a good live-AI case and click *save for replay*; on stage press **Shift+R**
  to replay it (labelled REPLAY). Recordings stay on the laptop in `scambaiter/data/replays/`.

### Security and real-world integration
Login with admin/analyst roles, API keys, rate limits, encryption at rest, a tamper-evident seal on every
message, a hash-chained audit log, PII masking, a prompt-injection guard, a Gmail inbox, an SMS-gateway
webhook, an NCRP-ready complaint, signed mule-account alerts for banks, and a public lookup API.
Threat model, how-to and judge demo: **[scambaiter/SECURITY.md](scambaiter/SECURITY.md)**.
- **Gmail:** run `setup_gmail.bat` once (a demo Gmail with an App Password). Forward a scam email to it to
  get a verdict email back; write to it from a teammate's address and the decoy replies in the thread.
- **No internet?** Drop a scam email saved as `.eml` on the intake slip: same path, no Gmail needed.
- **Link sandbox:** a captured link shows **check in sandbox ▶**: the verdict, what the page asks for, and the
  payment details on it (added to the case). Demo mode uses a built-in fake scam site, so it works offline.
- **SECURITY** button (admin): audit log, API keys, integrations, the phone link.

## Check it
```
python tools/check_contract.py all        # backend running; expect 62 passed, 0 failed
python -m unittest backend.test_security  # 22 security, Gmail/SMS and sandbox tests
python -m backend.security verify         # every case seal + the audit log
python -m simulator.run --scripts 35 --turns 6
python -m simulator.evaluate --md         # writes pitch/metrics.md
```

## What's inside (`scambaiter/`)
| Folder | Owner | What it does |
|---|---|---|
| `backend/` | P1 | HTTP API, local-LLM bot with safety filter, encrypted SQLite storage, security layer, Gmail/SMS intake, NCRP and bank-alert exports |
| `extractor/` | P2 | Identifier extraction, scam-type classifier, gang linking |
| `dashboard/`, `report/` | P3 | Live dashboard and printable evidence report |
| `simulator/`, `pitch/` | P4 | 35 scripted scams, live demo driver, metrics, pitch notes |
| `contracts/`, `tools/` | P1 | Shared data models, contract checker, mock server |

More detail: `scambaiter/CONTEXT.md`, `scambaiter/API_CONTRACT.md`, `scambaiter/backend/README.md`.
