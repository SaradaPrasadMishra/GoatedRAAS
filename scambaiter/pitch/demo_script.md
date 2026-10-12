# Scambaiter — timed 3-minute demo script

> **Before the room:** start the backend and dashboard; keep the terminal ready. Run `python -m simulator.run --live` only when the dashboard is visible. Use synthetic messages only. Every screen/session must retain its **SIMULATION** badge.

## 0:00–0:20 — Hook

**Say:** “Imagine receiving this message: *‘URGENT: KYC pending. Account services may pause today. Verify at verify-kyc-river.in/update.’* A person who is worried about losing access may click quickly, reply, or send money. The point is not that every suspicious message is identical; it is that one message can be part of a larger operation.”

**Victim story:** “Picture a fictional customer who receives a fake KYC message, then a second message from a different number. They may look unrelated until an identifier connects them.” This is a synthetic example, not a real victim case.

## 0:20–0:45 — Problem and why it matters

**Say:** “Indian cyber-fraud reporting channels exist, but people still have to recognise a scam, preserve evidence, and act quickly. We will not quote an unverified loss figure: add a verified government or other authoritative statistic here only after checking its source and year. **[VERIFY: source — current official Indian cybercrime/fraud-loss statistic, publication date, and definition]**. We are demonstrating a workflow, not claiming a measured reduction in fraud.”

## 0:45–1:10 — Show the product

1. Open the local dashboard at `http://localhost:8000`.
2. Point to the visible **SIMULATION** badge and say: “This is a local, synthetic-data demonstration. No real person is contacted and no money is moved.”
3. Paste the synthetic KYC opening from `simulator/scripts.json` into the demo input and start a session.
4. Say: “The bot plays a slow, confused persona rather than arguing with the sender. Each turn can expose identifiers for extraction.”

## 1:10–2:15 — Live campaign demo

1. In a terminal at the repository root, run: `python -m simulator.run --live`.
2. Say: “This runs three scripted messages from one synthetic campaign, with four-second pacing so the dashboard can poll and refresh.”
3. On the dashboard, show the new sessions arriving. Point to entity identifiers as they appear.
4. Say: “The graph should connect sessions only when they share identifiers. One shared identifier is evidence for a possible link, not proof of who is behind it.”
5. Open a session and click its evidence/report action. Point out the timeline, extracted identifiers, and **SIMULATION** label.
6. If the dashboard does not update, refresh once and continue from the graph/report. Do not imply a missing edge was detected.

## 2:15–2:40 — Metrics

Open `pitch/metrics.md`, generated with `python -m simulator.evaluate --md`. Read the measured entity F1, scam-type accuracy, campaign purity/recall, average turns, and time wasted. **Use the current file values only.** Explain: “The mock extractor is intentionally dumb, so mock metrics are a plumbing check, not a claim about production accuracy.” Do not invent targets or substitute a previous run's numbers.

## 2:40–3:00 — Safety and close

**Say:** “The prototype is designed for local operation: open-source components, a local Ollama model where enabled, synthetic data, no real payments, no cloud LLM API, and human review before evidence is acted on. We aim to help preserve context and surface possible links, not automatically accuse anyone. The next step is testing false positives and validating reports with appropriate reviewers.”

## If the LLM is slow

Say: “The local model is optional. This run is using deterministic scripted fallback so the demo stays repeatable and offline.” Continue; do not wait more than a few seconds for generation.

## If Wi-Fi dies

Say: “That is expected to be survivable: the app and model are local once installed.” Keep the local server and dashboard open; use `--mode scripted` or the already-generated `runs.json`/`pitch/metrics.md`. If the local server itself is down, show the synthetic scripts and previously generated metrics, clearly labelled as recorded output rather than a live run.
