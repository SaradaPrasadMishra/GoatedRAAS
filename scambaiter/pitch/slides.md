# Slide content — Scambaiter (7 slides)

## 1. Scambaiter
- **They call. We answer. Slowly.**
- An offline AI decoy that talks to scammers so real people don't have to, and turns every conversation into evidence.
- Mission'26 · VIT Chennai SCOPE + BIS · FinTech
- Footer: **SIMULATION: synthetic data only, no real payments**

## 2. The problem
- **₹22,845.73 crore** reported lost to cyber financial fraud in India in 2024, up from ₹7,465.18 crore in 2023
  (NCRP + CFCFRMS; MHA reply in Lok Sabha, 22 July 2025).
- Scams use the same tricks: urgency, fake authority, OTP/PIN requests, "collect requests", prizes and refunds.
- One message looks harmless. The gang behind it only shows when identifiers repeat across victims.
- Victims don't know what evidence to keep or how to file it.

## 3. How it works
`Scam message → local AI decoy keeps them talking → identifiers extracted every turn → gangs linked by shared identifiers → evidence report + ready-to-file complaint`
- **Decoy:** three personas (retired teacher, shopkeeper, student) on a local open-weight model (Qwen2.5 via Ollama).
- **Extraction:** UPI IDs, phones, links, bank accounts, IFSC, emails, crypto wallets, normalised.
- **Linking:** sessions sharing an identifier form a gang on the evidence board.
- **Explain:** red flags + risk level, so victims learn why it's a scam.

## 4. Safety by design
- The decoy never outputs a 4+ digit number: no OTP, PIN or account number can leak.
- Never sends money, never opens links, never breaks character; canned safe replies if the model misbehaves.
- Live safety record on every case: "OTP asked 2× · given 0 · payment asked 1× · paid 0".
- Fully offline: no cloud AI, no API keys, no telemetry. SIMULATION label on every screen.

## 5. Live demo
- Paste a scam → watch the decoy type, identifiers get stamped CAPTURED, red flags appear.
- Three more scams arrive → the evidence board ties them together with red string: one gang.
- One click: printable evidence report and a complaint ready for cybercrime.gov.in / 1930.

## 6. Results (measured)
40 synthetic scam scripts, 7 scam types, 8 gangs, run through the real pipeline:

| Metric | Result |
|---|---:|
| Identifier extraction F1 (all 7 types) | 1.00 |
| Scam-type accuracy | 1.00 |
| Gang purity / recall | 1.00 / 1.00 (8 of 8) |

Synthetic scripts the extractor was tuned on: expect lower numbers on real messages. Testing on real reported scams is next.

## 7. What's next
- Forward scams straight from WhatsApp / SMS.
- Share gang identifiers with banks and I4C so mule accounts get frozen faster.
- Regional languages (Tamil, Hindi, Telugu) for the decoy and the red-flag explainer.
- Close: **Scammers waste our time every day. Scambaiter wastes theirs.**
