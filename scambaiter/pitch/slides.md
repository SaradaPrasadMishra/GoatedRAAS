# Slide content — Scambaiter (6 slides)

## 1. Scambaiter: an AI that talks so people don't have to
- FinTech fraud-awareness prototype — Mission'26
- P4 demo: synthetic scam conversations → extracted identifiers → possible campaign links → evidence view
- Tagline: **Keep the conversation. Preserve the evidence. Review before acting.**
- Footer: **SIMULATION — synthetic data only**

## 2. The problem
- Scam messages use urgency, authority, easy income, prizes, refunds, or instant credit.
- A single message rarely shows the wider picture; repeated identifiers across reports can help reveal a possible campaign.
- Victims need usable evidence and clear next steps, not a bot that makes accusations.
- Statistic placeholder: **[VERIFY: source]** — insert only a current, dated statistic from an authoritative source, with its definition and geography.

## 3. How it works
- **Input:** user-provided suspicious message (demo uses synthetic text).
- **Conversation:** local bot persona keeps the sender engaged without sharing real secrets or making payments.
- **Extraction:** normalised UPI IDs, phones, URLs, bank-account patterns, IFSCs, emails, and crypto wallets.
- **Linking:** graph groups sessions that share identifiers; a link is a lead, not proof.
- **Output:** timeline and evidence report for human review.
- Diagram in words: `Message → local conversation → entity extraction + normalisation → session/entity graph → reviewable report`.

## 4. Live demo
- Paste one synthetic KYC message.
- Show the bot reply and identifier extraction.
- Run `python -m simulator.run --live` to add three sessions from one campaign.
- Watch the dashboard graph connect sessions sharing identifiers.
- Open the evidence report and show timestamps, entities, and SIMULATION badge.
- Fallback plan: deterministic scripted mode if local LLM is slow; saved output if local server is unavailable.

## 5. Results — report measurements, not promises
- Entity extraction: precision **[from pitch/metrics.md]**, recall **[from pitch/metrics.md]**, F1 **[from pitch/metrics.md]**.
- Scam-type accuracy **[from pitch/metrics.md]**.
- Campaign purity and campaign recall **[from pitch/metrics.md]**.
- Average scammer turns and time wasted **[from pitch/metrics.md]**.
- Label the run: mock backend / real backend, date, number of scripts.
- Note: mock extractor is intentionally simplistic; its scores validate the evaluation pipeline, not real-world efficacy.

## 6. Safety, privacy, and standards-minded design
- **Privacy/data minimisation:** synthetic demo data; store only what is needed for the session and evidence workflow; define retention and access controls before deployment.
- **Human review:** graph links are leads, not identity proof; review false positives before escalation.
- **Safety:** no real payments, no opening scam links, no sharing OTP/PIN/passwords, SIMULATION badge on all demo screens.
- **Offline/open-source direction:** local Ollama model; no ChatGPT/Gemini/Claude API in product; no telemetry.
- **BIS angle:** reliability, transparent evidence, testable contracts, documented limitations, and human oversight. Do not claim BIS certification or endorsement unless formally confirmed.
- Close: “We turn isolated suspicious messages into reviewable evidence while keeping the demo safe, local, and synthetic.”
