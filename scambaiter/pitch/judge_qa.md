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
We minimise collection, use synthetic data in the demo, and keep the prototype local. A deployment would need a proper assessment of roles, lawful basis/notice where applicable, purpose limitation, retention, security safeguards, data-subject requests, and current legal requirements. This prototype is not a legal-compliance certification.

### 6. Why not just block numbers?
Numbers can change, be spoofed, or be reused. Linking multiple identifiers can provide context across reports. Blocking can still be useful, but it does not by itself preserve a conversation timeline or show relationships among sessions.

### 7. How would police or a cybercrime investigator use it?
As a lead-generation and evidence-organisation aid: review a timeline, inspect extracted identifiers, and export a report for independent verification. It does not replace official reporting channels, forensic procedures, or investigator judgment.

### 8. Is the evidence legally admissible?
We make no blanket admissibility claim. Provenance, timestamps, integrity, collection method, chain of custody, and applicable evidence rules must be reviewed by qualified people. The report is a structured starting point, not a guarantee.

### 9. Why use an LLM at all?
A local model can make the conversation more flexible, while deterministic scripted mode makes the demo reproducible and robust. The system falls back to scripted messages if Ollama is unavailable or breaks character.

### 10. What about open-source compliance?
The product mandate excludes hosted ChatGPT/Gemini/Claude APIs. The intended LLM is a local open-weight model through Ollama; the team must verify the exact model and every dependency licence before release. Do not describe the whole product as “100% open-source” until all bundled assets and dependencies have been audited.

### 11. How do you protect sensitive data?
The demo uses invented identifiers and no real payments. A real deployment should apply data minimisation, encryption and access controls, retention limits, redaction, audit logs, and a process for deleting or restricting data when appropriate.

### 12. What is the BIS connection?
We align the prototype with standards-minded engineering: stable contracts, repeatable tests, measurable performance, traceable evidence, privacy-by-design, and human review. We are not claiming BIS certification, approval, or endorsement.
