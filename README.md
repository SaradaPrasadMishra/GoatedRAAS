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

Start the backend (terminal 1):
```
cd GoatedRAAS\scambaiter
.venv\Scripts\activate
set OLLAMA_KEEP_ALIVE=30m
python -m backend.main --reset
```
The banner should say `extractor real`, `campaigns real`, `report real`, `bot Ollama qwen2.5:7b`.
Open **http://localhost:8000** and press F11.

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

## Check it
```
python tools/check_contract.py all        # backend running; expect 62 passed, 0 failed
python -m simulator.run --scripts 35 --turns 6
python -m simulator.evaluate --md         # writes pitch/metrics.md
```

## What's inside (`scambaiter/`)
| Folder | Owner | What it does |
|---|---|---|
| `backend/` | P1 | HTTP API, local-LLM bot with safety filter, SQLite storage |
| `extractor/` | P2 | Identifier extraction, scam-type classifier, gang linking |
| `dashboard/`, `report/` | P3 | Live dashboard and printable evidence report |
| `simulator/`, `pitch/` | P4 | 35 scripted scams, live demo driver, metrics, pitch notes |
| `contracts/`, `tools/` | P1 | Shared data models, contract checker, mock server |

More detail: `scambaiter/CONTEXT.md`, `scambaiter/API_CONTRACT.md`, `scambaiter/backend/README.md`.
