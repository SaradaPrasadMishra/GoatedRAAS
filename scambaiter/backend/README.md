# backend/ — Scambaiter API + bot (P1)

Python standard-library HTTP server (no FastAPI/uvicorn needed). Implements every
route in `API_CONTRACT.md` and serves the dashboard at `/`.

| File | What it does |
|---|---|
| `main.py` | HTTP routes, CORS, static dashboard, startup banner |
| `service.py` | Turn pipeline, graph cache, stats, report. Loads `extractor/` and `report/`, falls back to `stubs.py` if they fail |
| `bot.py` | Personas, Ollama call, safety filter (no 4+ digit runs, no OTP/PIN handover, no "as an AI"), canned fallback replies |
| `store.py` | Sessions in memory + `data/scambaiter.sqlite` (survives restarts) |
| `stubs.py` | Minimal stand-ins used only if a teammate module is missing |

## Run (Windows, from `GoatedRAAS\scambaiter`, venv on)
```
set OLLAMA_KEEP_ALIVE=30m
python -m backend.main
```
Open http://localhost:8000 . The banner must say `extractor real`, `campaigns real`,
`report real`, and `bot Ollama qwen2.5:7b`.

Options:
```
python -m backend.main --reset          # wipe saved sessions (do this before going on stage)
python -m backend.main --port 8080
set OLLAMA_MODEL=qwen2.5:1.5b           # smaller/faster model
set SCAMBAITER_LLM=fallback             # no LLM, canned replies only
```
Reset while running: `curl -X POST http://localhost:8000/api/admin/reset`

## Test
```
python tools/check_contract.py all                       # backend must be running; expect 61/61 PASS
python -m simulator.run --scripts 35 --turns 6           # 35 scripted scams through the real pipeline
python -m simulator.evaluate --md                        # metrics -> pitch/metrics.md
python -m simulator.run --live                           # stage demo: 3 linked scams, 4 s pacing
```
