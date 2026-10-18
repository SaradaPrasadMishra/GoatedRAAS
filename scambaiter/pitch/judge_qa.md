# Judge Q&A — Scambaiter

### 1. Is baiting scammers ethical?
This prototype demonstrates a controlled fraud-awareness workflow using synthetic messages against our own local API. It does not contact real scammers or impersonate a real victim. Any real-world deployment would need legal, safety, and operational review first.

### 2. How do you handle false positives?
We treat shared identifiers as leads, not proof. We measure extraction precision/recall and campaign purity, show the evidence behind a link, and require human review before action. Common/shared identifiers should be weighted cautiously.

### 3. What if scammers detect the bot?
The goal is not to guarantee every conversation continues. The system records whatever was already disclosed and can still provide useful evidence. We evaluate engagement length and avoid claims that the bot can reliably fool every sender.

### 4. Can this scale to WhatsApp?
The contract already models WhatsApp as a channel, but a production integration would need an authorised integration path, platform-policy review, consent, access controls, rate limits, and abuse monitoring. This demo does not connect to WhatsApp.

### 5. How do you address India's DPDP Act?
We minimise collection, use synthetic data in the demo, and keep the prototype local. Built in: encryption at rest (AES-256-GCM), role-based access, masking of victims' card/Aadhaar/PAN numbers and reporter contacts for analysts, a 30-day retention purge, and an audit log (SECURITY.md §5 maps each control). A deployment would still need a proper assessment of roles, lawful basis/notice where applicable, purpose limitation, retention, security safeguards, data-subject requests, and current legal requirements. This prototype is not a legal-compliance certification.

### 6. Why not just block numbers?
Numbers can change, be spoofed, or be reused. Linking multiple identifiers can provide context across reports. Blocking can still be useful, but it does not by itself preserve a conversation timeline or show relationships among sessions.

### 7. How would police or a cybercrime investigator use it?
As a lead-generation and evidence-organisation aid: review a timeline, inspect extracted identifiers, and export a report for independent verification. It does not replace official reporting channels, forensic procedures, or investigator judgment.

### 8. Is the evidence legally admissible?
We make no blanket admissibility claim, but we built for integrity: every message is sealed in an HMAC-SHA256 hash chain when captured, and the report and complaint carry the transcript's SHA-256 and the seal status. Edit one message in the database and the case shows TAMPERED (we can demo it). That supports a Bharatiya Sakshya Adhiniyam §63 certificate. Provenance, timestamps, integrity, collection method, chain of custody, and applicable evidence rules must be reviewed by qualified people. The report is a structured starting point, not a guarantee.

### 9. Why use an LLM at all?
A local model can make the conversation more flexible, while deterministic scripted mode makes the demo reproducible and robust. The system falls back to scripted messages if Ollama is unavailable or breaks character.

### 10. What about open-source compliance?
The product mandate excludes hosted ChatGPT/Gemini/Claude APIs. The intended LLM is a local open-weight model through Ollama; the team must verify the exact model and every dependency licence before release. Do not describe the whole product as “100% open-source” until all bundled assets and dependencies have been audited.

### 11. How do you protect sensitive data?
The demo uses invented identifiers and no real payments. Built in: login with admin/analyst roles, scoped and revocable API keys, rate limits and login lockout, AES-256-GCM at rest, PII masking, strict browser security headers, optional HTTPS, and a hash-chained audit log. Next steps for production: keys in a KMS/HSM, 2FA, and external anchoring of the seal. A real deployment should also apply data minimisation, encryption and access controls, retention limits, redaction, audit logs, and a process for deleting or restricting data when appropriate.

### 12. What is the BIS connection?
We align the prototype with standards-minded engineering: stable contracts, repeatable tests, measurable performance, traceable evidence, privacy-by-design, and human review. We are not claiming BIS certification, approval, or endorsement.

### 13. "There are no security protocols." What stops misuse?
Show SECURITY → Overview: login on, every case sealed, audit chain intact, AES-256 at rest. Then run `python -m backend.security tamper <case>`: the badge turns TAMPERED within 2 seconds. Every login, export and prompt-injection attempt is in the audit log. Threat model in SECURITY.md §1 (12 threats, each with its defence).

### 14. "There is no real-life integration." How does it reach the real world?
Gmail inbox: forward a scam email and get a verdict back; the decoy also answers scam emails in-thread. SMS-gateway webhook (Android forwarder or Twilio). The complaint is pre-filled with the cybercrime.gov.in financial-fraud fields. Gangs export as an Ed25519-signed mule-account alert grouped by bank. Banks and telecoms can call `/api/v1/lookup` with an API key. I4C, DoT Chakshu and NPCI APIs need government onboarding; our JSON formats are ready for it.

### 15. Can a scammer hack the AI with prompt injection?
We detect it ("ignore your instructions", "are you a bot", fake system tags), flag it as a red flag, log it, and tell the decoy to stay confused and in character. Even if the model obeyed, the output filter blocks any number of 4+ digits and any talk about its own rules, and it never sends money or opens links.
