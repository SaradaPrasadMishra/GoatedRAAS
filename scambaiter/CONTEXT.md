# CONTEXT.md — paste or attach this in EVERY AI chat, every time

## The project
**Scambaiter** — an AI that talks to scammers so real people don't have to.
A user forwards a scam message (fake KYC, fake refund "collect request", part-time job task,
lottery, "digital arrest", crypto doubling, instant loan). The bot replies as a slow, confused,
gullible person and keeps the scammer talking. Every turn it pulls out the scammer's
**UPI IDs, phone numbers, links, bank accounts, IFSC codes, emails and crypto wallets**.
It links sessions that reuse the same identifiers into **campaigns** (one gang, many messages),
shows it all on a live dashboard with a network graph, and produces an **evidence report**
a victim can file at cybercrime.gov.in or quote when calling 1930.

Hackathon: Mission'26, VIT Chennai SCOPE + Bureau of Indian Standards, 8 hours, FinTech theme.
**Strict open-source mandate**: no ChatGPT/Gemini/Claude APIs inside the product. The only LLM
is a local open-weight model through **Ollama** (default `qwen2.5:7b`, small-laptop fallback
`qwen2.5:1.5b`; both Apache-2.0). Everything else is MIT/BSD/Apache Python or JS.

## Team and ownership (nobody edits another person's folder)
| Person | AI they use | Owns | Must expose |
|---|---|---|---|
| P1 Tech lead | Claude Pro | `backend/`, `contracts/`, `tools/`, merges to `main` | FastAPI on :8000, `backend/bot.py` |
| P2 Extractor | Gemini | `extractor/` | `extract_entities`, `classify_scam`, `build_graph` |
| P3 Dashboard | Gemini | `dashboard/`, `report/` | `dashboard/index.html`, `render_report` |
| P4 Simulator | ChatGPT Go | `simulator/`, `pitch/` | `simulator/scripts.json`, `run.py`, `evaluate.py` |

## Repo layout
```
scambaiter/
  CONTEXT.md  API_CONTRACT.md  requirements.txt
  contracts/  models.py  normalize.py  sample_data/*.json     <- FROZEN, tech lead only
  tools/      check_contract.py  mock_server.py               <- FROZEN, tech lead only
  backend/    main.py  store.py  bot.py                       <- P1
  extractor/  extract.py  campaigns.py                        <- P2
  report/     render.py                                       <- P3
  dashboard/  index.html  app.js  style.css  vendor/          <- P3
  simulator/  scripts.json  run.py  evaluate.py  last_eval.json  <- P4
  pitch/      demo_script.md  slides.md                       <- P4
```
Every Python folder has an empty `__init__.py`. Run everything **from the repo root**
(`python -m backend.main`, `python tools/check_contract.py ...`). Python 3.10+.

## The function contracts (exact signatures)
```python
# extractor/extract.py  (P2)
def extract_entities(text: str, message_id: str) -> list[Entity]: ...
def classify_scam(text: str) -> ScamType: ...           # one message or a whole conversation joined by "\n"

# extractor/campaigns.py  (P2)
def build_graph(sessions: list[Session]) -> Graph: ...

# report/render.py  (P3)
def render_report(session: Session, graph: Graph) -> str: ...   # full standalone HTML document

# backend/bot.py  (P1)
PERSONAS: dict[str, str]                                 # key -> system-prompt text
def generate_reply(session: Session, persona: str) -> str: ...
```
Types come from `contracts/models.py`. Normalise every entity value with `contracts/normalize.py`.
The HTTP API is in `API_CONTRACT.md`.

## Rules everyone follows
1. **Never change `contracts/` or `tools/`.** Need a change? Ask P1, who edits it and re-shares.
2. **Build against sample data and the mock server**, not against each other.
   `python tools/mock_server.py` serves the whole API with fake data on :8000.
3. **Done = the checker passes**: `python tools/check_contract.py <your part>`.
4. **Safety, non-negotiable:** the bot never sends money, never shares a real OTP/PIN/account
   number (it never outputs 4+ digit runs), never opens scammer links, and the demo talks only
   to our own simulator. Every screen and report shows a **SIMULATION** badge.
5. No cloud APIs, no API keys, no telemetry. Must run with Wi-Fi off once installed.
6. Commit to your own branch (`p2-extractor`, `p3-dashboard`, `p4-simulator`); P1 merges.
