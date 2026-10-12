# Scambaiter — timed 3-minute demo script

> **Before the room (10 min early):**
> 1. Terminal 1: `python -m backend.main --reset`. The banner must say `bot Ollama qwen2.5:7b`.
> 2. Open `http://localhost:8000`, press the full-screen button (or F11). The badge top-right must say **AI live**.
> 3. Terminal 2 ready with `python -m simulator.run --live` typed but not run.
> 4. No copy-paste needed: the intake slip has one-click samples (KYC, Digital arrest, Job task, Hinglish, தமிழ்).
>
> Every screen keeps the yellow **SIMULATION** label. Synthetic messages only.

## 0:00–0:20 — Hook

**Say:** "Indians reported losing **₹22,845 crore** to cyber financial fraud in 2024, three times the year before
(Ministry of Home Affairs, Lok Sabha, 22 July 2025). Every one of those scams started with a message like this one.
What if, instead of the victim, an AI answered?"

## 0:20–0:45 — The idea

**Say:** "Scambaiter is a decoy. You forward the scam, and a local AI pretends to be a slow, trusting person. It keeps
the scammer busy, and every message they send leaks evidence: UPI IDs, phone numbers, bank accounts, links.
When two scams use the same account, we've found a gang."

Point at the caution tape: "Everything runs offline on this laptop, with an open-source model. No cloud AI, no real money."

## 0:45–1:30 — Live: talk to the decoy (proves it's real AI)

0. *(10 s, optional)* Click the **Digital arrest** sample, then **Just check: is this a scam?**: "Any citizen can paste a message and get
   a verdict with the reasons, in plain language." Close the panel.
1. In the **Intake slip**, pick **Decoy: Kamala, 68, retired teacher**, click the **KYC** sample, press **Engage Decoy**.
2. While "**Kamala is typing…**" shows, **say:** "That's the model on this laptop writing a reply, not a script."
3. Point at the big line: the UPI ID and phone get stamped **CAPTURED**.
4. Point at **Red flags**: "It also tells a victim *why* this is a scam: urgency, an OTP request, fake bank authority."
   Point at **Safety**: "OTP asked twice, given zero. Payment asked, paid zero. It never hands anything over."
5. Type one more scammer line in the chat box, e.g. `Madam do not tell anyone, send OTP fast or police case will be filed`,
   press **Transmit**. New red flags appear: Threat, Secrecy.

*Optional (if time):* pick **Decoy: Priya**, click the **தமிழ்** (Tamil) or **Hinglish** sample and engage: the decoy answers in the
scammer's language.

## 1:30–2:10 — Live: catch a gang

1. Terminal 2: run `python -m simulator.run --live`. Three scams arrive four seconds apart, each answered by a different decoy.
2. **Say:** "These three look unrelated: different wording, different times. Watch the evidence board."
3. When the red string connects them: "They share one phone number. That's one gang, and the counter says so: **Gangs linked: 1**."
4. Point at **Scammer time wasted** counting up: "Every second here is a second they aren't spending on a real victim."
5. Point at **Scammers demanded**: "Across these cases they asked for ₹___ (read it off the screen). We paid zero."

## 2:10–2:35 — The victim's takeaway

1. Click **Report**: the printable evidence report with identifiers, red flags, safety record and transcript.
2. Click **Complaint**: "One click copies a ready-to-paste complaint for cybercrime.gov.in. A victim can file in 30 seconds instead of 30 minutes."

## 2:35–3:00 — Results and close

**Say (numbers from `pitch/metrics.md`, 40 synthetic scam scripts through the real pipeline):**
"Identifier extraction F1 **1.00** across all seven identifier types, scam-type accuracy **1.00**, gang purity and recall **1.00**, 8 of 8 gangs found.
These are synthetic test scripts, so real-world numbers will be lower; that's the next thing we'd measure."

**Close:** "Scammers waste our time every day. Scambaiter wastes theirs, and turns every conversation into evidence."

## If the AI is slow or the badge says "AI off"

Say: "The decoy can fall back to safe canned replies, so the demo never stalls." Continue; extraction, red flags,
gang linking, the report and the complaint all work the same. Fix afterwards: open the Ollama app and restart the backend.

## If Wi-Fi dies

Nothing changes: the app, the model and the dashboard are all local.
