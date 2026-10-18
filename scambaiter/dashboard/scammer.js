// Scammer's phone page (synthetic demo): chats with the decoy on the laptop.
(() => {
  const API = window.API_BASE || "";
  // The laptop prints this page's link with an intake key after "#k=" (python -m backend.main --lan).
  // It stays in the fragment, so it is never sent in a URL or written to server logs.
  const KEY_STORE = "scambaiter_phone_key";
  const fromHash = new URLSearchParams(location.hash.slice(1)).get("k");
  if (fromHash) { try { localStorage.setItem(KEY_STORE, fromHash); } catch (e) {} history.replaceState(null, "", location.pathname); }
  let apiKey = fromHash;
  try { apiKey = apiKey || localStorage.getItem(KEY_STORE); } catch (e) {}
  const KEY = "scambaiter_phone_session";
  const log = document.getElementById("log");
  const text = document.getElementById("text");
  const send = document.getElementById("send");
  const statusEl = document.getElementById("status");
  let sessionId = null;
  let busy = false;
  let persona = "retired_teacher";

  // Decoy personas (same keys as backend/bot.py PERSONAS and the dashboard)
  const PERSONAS = {
    retired_teacher: { name: "Kamala", who: "68 · retired teacher" },
    busy_shopkeeper: { name: "Ramesh", who: "kirana shop owner" },
    confused_student: { name: "Priya", who: "college student" },
  };
  const personaOf = (k) => PERSONAS[k] || { name: "Target", who: "" };
  const nameEl = document.getElementById("who-name");
  const avatarEl = document.getElementById("avatar");

  function setPersona(key) {
    if (!key || key === "auto") return;
    persona = key;
    const p = personaOf(key);
    nameEl.textContent = p.name + " (target)";
    avatarEl.textContent = p.name.charAt(0);
    if (!busy) { statusEl.textContent = p.who ? "online · " + p.who : "online"; statusEl.className = ""; }
  }

  // While no chat is open, follow the decoy picked on the laptop
  async function syncDecoy() {
    if (sessionId) return;
    try { const d = await api("/api/decoy"); setPersona(d.persona); } catch (e) { /* laptop not reachable yet */ }
  }
  setInterval(syncDecoy, 3000);

  const sleep = (ms) => new Promise(r => setTimeout(r, ms));
  let typingEl = null;
  function showTyping() {
    if (typingEl) return;
    typingEl = document.createElement("div");
    typingEl.className = "msg them typing-bubble";
    typingEl.setAttribute("aria-label", personaOf(persona).name + " is typing");
    typingEl.innerHTML = "<i></i><i></i><i></i>";
    log.appendChild(typingEl);
    log.scrollTop = log.scrollHeight;
  }
  function hideTyping() { if (typingEl) { typingEl.remove(); typingEl = null; } }

  const EXAMPLES = [
    ["KYC", "Dear customer your SBI KYC has expired. Update now at sbi-kyc-update.in or your account will be blocked today."],
    ["Refund", "Sir your refund of Rs 4999 is approved. Accept the collect request from refund.desk@okaxis to receive the amount."],
    ["Job", "Part time job! Earn 3000 per day by liking YouTube videos. WhatsApp 9123456780 to start."],
    ["Police", "This is Mumbai Cyber Police. An FIR is registered against you. Call +91 98765 43210 immediately."],
  ];

  const store = {
    get() { try { return localStorage.getItem(KEY); } catch (e) { return null; } },
    set(v) { try { v ? localStorage.setItem(KEY, v) : localStorage.removeItem(KEY); } catch (e) {} },
  };
  const clock = (iso) => {
    const d = iso ? new Date(iso) : new Date();
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  };

  function bubble(cls, body, ts) {
    const intro = log.querySelector(".intro");
    if (intro) intro.remove();
    const div = document.createElement("div");
    div.className = "msg " + cls;
    div.textContent = body;                       // never innerHTML: messages are untrusted
    if (ts !== undefined) {
      const t = document.createElement("time");
      t.textContent = clock(ts);
      div.appendChild(t);
    }
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
    return div;
  }
  function note(cls, body) {
    const div = document.createElement("div");
    div.className = cls;
    div.textContent = body;
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
  }

  function showIntro() {
    log.innerHTML = "";
    const box = document.createElement("div");
    box.className = "intro";
    box.innerHTML = "<h1>You are the scammer</h1><p>Send a scam message to the target. Watch the big screen: " +
                    "the decoy keeps you talking and captures every UPI ID, number and link you share.</p>";
    const chips = document.createElement("div");
    chips.className = "chips";
    EXAMPLES.forEach(([label, msg]) => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "chip";
      const s = document.createElement("span"); s.textContent = "Try: " + label;
      b.appendChild(s);
      b.appendChild(document.createTextNode(msg));
      b.onclick = () => { text.value = msg; autosize(); text.focus(); };
      chips.appendChild(b);
    });
    box.appendChild(chips);
    log.appendChild(box);
  }

  function setBusy(on) {
    busy = on;
    send.disabled = on;
    const p = personaOf(persona);
    statusEl.textContent = on ? p.name + " is typing…" : (p.who ? "online · " + p.who : "online");
    statusEl.className = on ? "typing" : "";
  }

  async function api(path, body) {
    const res = await fetch(API + path, {
      method: body === undefined ? "GET" : "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": apiKey || "" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (res.status === 401) throw new Error("NOKEY");
    if (!res.ok) throw new Error("HTTP " + res.status);
    return res.json();
  }

  async function sendMessage(msg) {
    setBusy(true);
    bubble("me", msg, new Date().toISOString());
    const started = Date.now();
    const typingTimer = setTimeout(showTyping, 500);   // "seen", then starts typing
    try {
      let reply;
      if (!sessionId) {
        const s = await api("/api/sessions", { channel: "whatsapp", persona: "auto", first_message: msg });
        sessionId = s.id;
        store.set(sessionId);
        setPersona(s.persona);
        reply = s.messages.filter(m => m.role === "bot").pop();
      } else {
        const t = await api(`/api/sessions/${sessionId}/messages`, { text: msg });
        reply = t.bot_reply;
      }
      if (reply) {
        // keep the typing dots up for a believable moment (longer replies take longer to "type")
        const minMs = Math.min(3500, 1200 + reply.text.length * 25);
        const wait = minMs - (Date.now() - started);
        if (wait > 0) { showTyping(); await sleep(wait); }
        clearTimeout(typingTimer); hideTyping();
        bubble("them", reply.text, reply.ts);
      }
    } catch (e) {
      clearTimeout(typingTimer); hideTyping();
      note("err", e.message === "NOKEY"
        ? "This phone is not paired yet. Open the phone link shown in the laptop's backend window (it ends in #k=…)."
        : "Could not reach the laptop. Is run_demo.bat still running and are you on the same Wi-Fi?");
    } finally {
      clearTimeout(typingTimer); hideTyping();
      setBusy(false);
      text.focus();
    }
  }

  async function restore() {
    const saved = store.get();
    if (!saved) return showIntro();
    try {
      const s = await api(`/api/sessions/${saved}`);
      if (s.status === "closed") { store.set(null); return showIntro(); }
      sessionId = s.id;
      setPersona(s.persona);
      log.innerHTML = "";
      s.messages.forEach(m => bubble(m.role === "scammer" ? "me" : "them", m.text, m.ts));
      if (!s.messages.length) showIntro();
    } catch (e) {
      store.set(null);
      showIntro();
    }
  }

  function autosize() {
    text.style.height = "auto";
    text.style.height = Math.min(text.scrollHeight, 120) + "px";
  }

  document.getElementById("form").addEventListener("submit", (e) => {
    e.preventDefault();
    const msg = text.value.trim();
    if (!msg || busy) return;
    text.value = ""; autosize();
    sendMessage(msg);
  });
  text.addEventListener("input", autosize);
  text.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey && window.matchMedia("(pointer: fine)").matches) {
      e.preventDefault();
      document.getElementById("form").requestSubmit();
    }
  });
  document.getElementById("new-chat").onclick = () => {
    sessionId = null; store.set(null); showIntro(); syncDecoy(); text.focus();
  };

  restore().then(syncDecoy);
})();
