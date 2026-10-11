# API_CONTRACT.md — HTTP API (backend on http://localhost:8000)

All bodies are JSON shaped exactly like the classes in `contracts/models.py`.
CORS is open (`*`). Example responses live in `contracts/sample_data/`.
The mock server (`python tools/mock_server.py`) implements every route below.

| Method | Path | Request body | Response | Sample file |
|---|---|---|---|---|
| GET  | `/api/health` | – | `Health` | – |
| POST | `/api/sessions` | `CreateSessionRequest` | `Session` | `sessions.json[0]` |
| POST | `/api/sessions/{id}/messages` | `ScammerMessageRequest` | `TurnResponse` | `turn_response.json` |
| POST | `/api/sessions/{id}/close` | `{}` | `Session` (status `closed`) | – |
| GET  | `/api/sessions` | – | `list[SessionSummary]`, newest first | `session_summaries.json` |
| GET  | `/api/sessions/{id}` | – | `Session` | `sessions.json` |
| GET  | `/api/sessions/{id}/report` | – | `text/html` evidence report | – |
| GET  | `/api/graph` | – | `Graph` (all sessions) | `graph.json` |
| GET  | `/api/stats` | – | `Stats` | `stats.json` |
| GET  | `/` | – | serves `dashboard/index.html` (and `/dashboard/*` static files) | – |

## What one turn does (POST /api/sessions/{id}/messages)
1. Save the scammer `Message`.
2. `extract_entities(text, message_id)` → keep only entities whose `(type, value)` is new for this session → `new_entities`.
3. `classify_scam("\n".join(all scammer texts))` → update `session.scam_type`.
4. `generate_reply(session, session.persona)` → save as the bot `Message`.
5. Update `time_wasted_seconds` = last ts − first ts.
6. Return `TurnResponse`.

`POST /api/sessions` with `first_message` runs one turn immediately, so the returned
session already has 2 messages.

## Errors
Unknown session id → HTTP 404 `{"detail": "session not found"}`.
LLM down → still HTTP 200; `generate_reply` falls back to canned persona lines and
`/api/health` reports `"llm": "fallback"`.

## Polling
The dashboard polls `/api/sessions`, `/api/graph`, `/api/stats` every 2 s. No websockets.
