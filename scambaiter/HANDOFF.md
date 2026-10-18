# HANDOFF.md — read this first (for Claude Code)

You are picking up the **Scambaiter** hackathon project (Mission'26, VIT Chennai SCOPE + BIS,
FinTech theme, 8-hour build, demo today). Read `CONTEXT.md` and `API_CONTRACT.md` next.
The person you're working with owns **presentation**: dashboard look, evidence report, demo
flow, slides, and overall polish. A teammate (P1) is building `backend/` separately right now.

## State of each part (all verified against `tools/check_contract.py`)
| Part | Folder | Status |
|---|---|---|
| Contract, checker, mock server | `contracts/`, `tools/` | Frozen. Do not edit. |
| Extractor + campaign linking (P2) | `extractor/` | Done. 14/14 + 10/10 checks, 34/34 in `python -m extractor.tests_extra`. Crypto-vs-IFSC bug fixed; classifier rewritten with weighted whole-word keywords. |
| Dashboard + evidence report (P3) | `dashboard/`, `report/` | Done. 7/7 + 8/8. "The Trap" design: red/black/paper, preloader, caution-tape SIMULATION strip, word-by-word scammer line with CAPTURED stamps, evidence board with red string, branded A4 report. |
| Simulator + metrics + pitch (P4) | `simulator/`, `pitch/` | Done. 6/6 (+ last_eval check once generated). 35 scripts, 7 campaigns. Filler lines diversified. |
| Backend + bot (P1) | `backend/` | Done (merged). Stdlib HTTP server + Ollama bot with safety filter and fallback replies. `check_contract.py all` 62/62 against the running backend. P1 still owns `backend/`. |

Measured with all 35 simulator scripts through the real extractor (test backend, not P1's):
entity F1 1.00, campaign purity 1.00, campaign recall 7/7, scam-type accuracy 1.00
(keywords were tuned on these scripts, so expect lower on live-typed messages).
Re-measure with P1's real backend before putting numbers on slides.

## Security layer (added after judges' feedback)
See `SECURITY.md`. The dashboard needs a login (passwords in `data/FIRST_LOGIN.txt` on first run);
local scripts (simulator, checker) are trusted from 127.0.0.1 without a key. Cases are encrypted
(AES-256-GCM) and every message is sealed in an HMAC hash chain; `python -m backend.security verify`
checks them. `python -m unittest backend.test_security` runs 18 tests. Gmail: `setup_gmail.bat`.
The phone page needs the link with `#k=…` printed by `python -m backend.main --lan`.

## Rules
1. Never edit `contracts/` or `tools/`.
2. Keep every element id used in `dashboard/app.js`, the `API_BASE` constant, and the
   SIMULATION badge — the checker greps for them.
3. Must work with Wi-Fi off: no CDNs, no web fonts. Fonts in use ship with Windows
   (Bahnschrift, Cascadia Mono / Consolas). Cytoscape is vendored in `dashboard/vendor/`.
4. Escape all scammer text before inserting into HTML (it is untrusted).
5. The demo laptop is 1366×768 or larger, shown on a projector — big, high-contrast, readable.
6. Every screen and report keeps the **SIMULATION** label. No real payments, no real people.
7. After any change run:
   ```
   python tools/check_contract.py dashboard
   python tools/check_contract.py report
   python tools/check_contract.py extractor
   python tools/check_contract.py graph
   python tools/check_contract.py simulator
   ```

## How to see the dashboard without the real backend
```
python tools/mock_server.py            # terminal 1, serves fake data on :8000
start dashboard\index.html             # Windows; it auto-uses http://localhost:8000 on file://
```
The mock returns fixed sample data, so new sessions won't appear in the graph — that's the mock,
not a bug. With P1's backend: `python -m backend.main`, then open http://localhost:8000 .

Live demo traffic (once a backend is running):
```
python -m simulator.run --live          # 3 scripts from one campaign, 4 s pacing
python -m simulator.evaluate --md       # writes simulator/last_eval.json + pitch/metrics.md
```

## Open presentation tasks (suggested order)
1. **Evidence report** (`report/render.py`): give it the same brand (header band, logo mark,
   SIMULATION watermark) while staying printable on white A4.
2. **Demo script** (`pitch/demo_script.md`): button labels are now **Engage Decoy**, **Transmit**,
   **Evidence Report**, **Terminate**; remove the line "The mock extractor is intentionally dumb…";
   fill the `[VERIFY: source]` statistic from a real source (e.g. I4C / NCRB) or drop it.
3. **Slides** (`pitch/slides.md`): turn into a deck; results slide uses real numbers from
   `pitch/metrics.md` generated against P1's backend.
4. Optional dashboard polish: idle "attract mode" before the first session, a "time wasted"
   ticker that counts up live while a session is active, a full-screen toggle (F11 also works).
5. Rehearse with P1's backend + `--live` at least twice; time it to 3 minutes.
