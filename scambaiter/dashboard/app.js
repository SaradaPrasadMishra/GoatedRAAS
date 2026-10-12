const API_BASE = window.API_BASE || (location.protocol === "file:" ? "http://localhost:8000" : "");

// Entity Color Palette
const COLORS = {
    upi_id: "#0f8a5f", phone: "#2448c9", url: "#b45309",
    bank_account: "#c0262d", ifsc: "#7c3aed", email: "#0e7490", crypto_wallet: "#a16207"
};
const CAMPAIGN_COLORS = ['#e3260f', '#e3260f', '#b45309', '#5b21b6', '#0f766e', '#be185d', '#1d4ed8'];

// State
let currentSessionId = null;
let isPolling = false;
let cy = null;
let knownCampaigns = new Set();
let isGraphInit = false;
let autoScroll = true;

// Utility: Escape HTML securely
const escapeHTML = (str) => str.replace(/[&<>'"]/g, tag => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
}[tag]));

// Locale-aware time formatting
const TIME_FMT = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
const CLOCK_FMT = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });

// Spread-out force layout so labels don't collide on the projector
const LAYOUT = { name: 'cose', padding: 34, nodeRepulsion: () => 10000, idealEdgeLength: () => 85, nodeOverlap: 40, componentSpacing: 45, gravity: 1, nestingFactor: 1, numIter: 2000 };
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

// Decoy personas (keys match backend/bot.py PERSONAS)
const PERSONAS = {
    retired_teacher: { name: 'Kamala', who: 'Kamala, 68 · retired teacher' },
    busy_shopkeeper: { name: 'Ramesh', who: 'Ramesh · kirana shop owner' },
    confused_student: { name: 'Priya', who: 'Priya · college student' },
};
const personaOf = (key) => PERSONAS[key] || { name: 'Decoy', who: 'Decoy' };

// Red flags a victim should learn to spot. Checked on the scammer's messages only.
const RED_FLAGS = [
    ['Urgency', /\b(urgent|immediately|right now|today|hurry|fast|quick(ly)?|expire[sd]?|last (reminder|chance)|time is running|within \d+ ?(min|minutes|hours?))\b/i],
    ['Asks for OTP / PIN', /\b(otp|pin|cvv|password|passcode)\b/i],
    ['Demands payment', /\b(pay|payment|transfer|deposit|fee|charges?|send (money|rs|₹)|collect request|(accept|approve) (the )?(collect )?request|scan (the )?qr)\b|₹|\brs\.? ?\d/i],
    ['Fake authority', /\b(rbi|police|cbi|cyber ?cell|customs|income tax|trai|court|government|ministry|bank (official|manager|head office)|kyc (team|department)|sbi|hdfc|icici|amazon|flipkart|electricity board)\b/i],
    ['Threat', /\b(block(ed)?|suspend(ed)?|arrest|legal action|penalty|freeze|frozen|disconnect(ed)?|fir|warrant|money laundering|case (is )?(registered|filed))\b/i],
    ['Too good to be true', /\b(won|winner|lottery|prize|reward|cashback|double|guaranteed|profit|returns?|loan (is )?approved|earn(ings)?|bonus|refund)\b/i],
    ['Secrecy', /\b(do not (tell|inform|share with)|don'?t tell|keep (it|this) (secret|confidential)|stay on (the|this) call)\b/i],
];
const OTP_ASK = /\b(otp|pin|cvv|password|passcode)\b/i;
const PAY_ASK = RED_FLAGS[2][1];
const DIGITS4 = /\d(?:[\s-]?\d){3,}/;           // 4+ digit run: an OTP, PIN or account number
const PAID = /\bi(?: have|'ve)? (?:sent|paid|transferred)\b/i;

function analyse(session) {
    const scam = session.messages.filter(m => m.role === 'scammer');
    const bot = session.messages.filter(m => m.role === 'bot');
    const text = scam.map(m => m.text).join('\n');
    const flags = RED_FLAGS.filter(([, rx]) => rx.test(text)).map(([name]) => name);
    if (session.entities.some(e => e.type === 'url')) flags.push('Suspicious link');
    const level = flags.length >= 4 ? 'HIGH' : flags.length >= 2 ? 'MEDIUM' : 'LOW';
    return {
        flags, level,
        otpAsked: scam.filter(m => OTP_ASK.test(m.text)).length,
        payAsked: scam.filter(m => PAY_ASK.test(m.text)).length,
        secretsShared: bot.filter(m => DIGITS4.test(m.text)).length,
        paid: bot.filter(m => PAID.test(m.text)).length,
    };
}

function renderIntel(session) {
    const intel = document.getElementById('intel');
    if (!session.messages.some(m => m.role === 'scammer')) { intel.hidden = true; return; }
    intel.hidden = false;
    const a = analyse(session);
    const risk = document.getElementById('risk');
    risk.textContent = a.level + ' RISK';
    risk.className = 'risk ' + a.level.toLowerCase();
    document.getElementById('flags').innerHTML = a.flags.length
        ? a.flags.map(f => `<span class="flag">${escapeHTML(f)}</span>`).join('')
        : '<span class="flag">none yet</span>';
    const n = (v) => `<b class="${v ? 'bad' : ''}">${v}</b>`;
    document.getElementById('safety').innerHTML =
        `OTP/PIN asked ${a.otpAsked}× · given ${n(a.secretsShared)} &nbsp;·&nbsp; payment asked ${a.payAsked}× · paid ${n(a.paid)} &nbsp;·&nbsp; links opened <b>0</b>`;
}

// Format seconds to Xh Ym
const formatTime = (secs) => secs >= 3600
    ? `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`
    : `${Math.floor(secs / 60)}m ${secs % 60}s`;

// Initialize Graph
function initGraph() {
    cy = cytoscape({
        container: document.getElementById('cy'),
        style: [
            {
                selector: 'node[type="session"]',
                style: { 'shape': 'ellipse', 'background-color': '#16130f', 'border-width': 4, 'border-color': 'data(color)', 'label': 'data(label)', 'color': '#16130f', 'font-family': 'Bahnschrift SemiBold Condensed, Bahnschrift, Arial Narrow, sans-serif', 'font-weight': 700, 'font-size': '13px', 'text-transform': 'uppercase', 'text-valign': 'bottom', 'text-margin-y': 6, 'text-background-color': '#fbf7ef', 'text-background-opacity': 1, 'text-background-padding': '3px', 'text-border-color': '#16130f', 'text-border-width': 1, 'text-border-opacity': 1, 'width': 30, 'height': 30 }
            },
            {
                selector: 'node[type!="session"]',
                style: { 'shape': 'round-rectangle', 'background-color': 'data(color)', 'label': 'data(label)', 'color': '#3a332b', 'font-family': 'Cascadia Mono, Consolas, monospace', 'font-size': '11px', 'text-valign': 'bottom', 'text-margin-y': 4, 'text-wrap': 'ellipsis', 'text-max-width': '130px', 'width': 14, 'height': 14, 'border-width': 2, 'border-color': '#fbf7ef' }
            },
            {
                selector: 'node[?shared]',
                style: { 'width': 24, 'height': 24, 'color': '#c4210d', 'font-weight': 700, 'font-size': '10px', 'border-color': '#e3260f', 'border-width': 3, 'underlay-color': '#e3260f', 'underlay-opacity': 0.18, 'underlay-padding': 10, 'underlay-shape': 'ellipse' }
            },
            {
                selector: 'edge',
                style: { 'width': 2.2, 'line-color': '#d7261e', 'curve-style': 'straight', 'target-arrow-shape': 'none', 'opacity': 0.9 }
            }
        ],
        layout: LAYOUT,
        minZoom: 0.4, maxZoom: 1.4
    });
}

// Show Toast
function showToast(msg, isError = false) {
    const t = document.createElement('div');
    t.className = isError ? 'toast toast-error' : 'toast';
    t.innerText = msg;
    document.getElementById('toast-container').appendChild(t);
    // subtle exit: short fade up, then remove
    setTimeout(() => { t.classList.add('leaving'); setTimeout(() => t.remove(), 160); }, 5000);
}

// Fetch Wrapper
async function fetchAPI(endpoint, options = {}) {
    try {
        const res = await fetch(API_BASE + endpoint, options);
        document.getElementById('offline-pill').style.display = 'none';
        if (!res.ok) throw new Error("HTTP " + res.status);
        return await res.json();
    } catch (err) {
        document.getElementById('offline-pill').style.display = 'inline-block';
        throw err;
    }
}

let lastStats = null, lastSessions = [], lastGraph = null, currentSession = null;
const IDLE_CAP = 120; // a silent scammer stops counting after 2 minutes

// Seconds since a session's last message, while it is still active
const liveExtra = (s, now) => {
    if (s.status !== 'active') return 0;
    const last = Date.parse(s.created_at) + s.time_wasted_seconds * 1000;
    return Math.max(0, Math.min(IDLE_CAP, Math.floor((now - last) / 1000)));
};

// Every second: the headline stat keeps counting while scammers are on the line
function tick() {
    const now = Date.now();
    if (lastStats) {
        const live = lastSessions.reduce((sum, s) => sum + liveExtra(s, now), 0);
        document.getElementById('stat-time').innerText = formatTime(lastStats.time_wasted_seconds + live);
    }
    const meta = document.getElementById('call-meta');
    if (currentSession) {
        const s = currentSession;
        const secs = s.status === 'active'
            ? s.time_wasted_seconds + liveExtra({ ...s, created_at: s.messages[0]?.ts || s.created_at }, now)
            : s.time_wasted_seconds;
        meta.hidden = false;
        document.getElementById('call-persona').textContent = 'as ' + personaOf(s.persona).name;
        document.getElementById('call-persona').title = personaOf(s.persona).who;
        document.getElementById('call-timer').textContent = (s.status === 'active' ? 'on call ' : 'closed after ') + formatClock(secs);
    } else {
        meta.hidden = true;
    }
}
setInterval(tick, 1000);
const formatClock = (secs) => `${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, '0')}`;

// Main Polling Loop
async function pollData() {
    if (isPolling) return;
    isPolling = true;

    try {
        // 1. Health
        const health = await fetchAPI('/api/health').catch(() => null);
        if (health) {
            const live = health.llm !== 'fallback';
            const badge = document.getElementById('health-status');
            badge.innerText = live ? `AI live · ${health.model || 'qwen2.5'}` : 'AI off · canned replies';
            badge.title = live ? 'Decoy replies are written by the local model' : 'Ollama is not reachable or the model is not installed. Start Ollama / run: ollama pull qwen2.5:7b';
            badge.classList.toggle('is-off', !live);
        }

        // 2. Stats
        const stats = await fetchAPI('/api/stats');
        animateValue('stat-sessions', stats.sessions);
        animateValue('stat-entities', stats.entities_total);
        animateValue('stat-campaigns', stats.campaigns);
        lastStats = stats;

        // 3. Sessions list
        const sessions = await fetchAPI('/api/sessions');
        lastSessions = sessions;
        renderSessionList(sessions);
        tick();

        // 4. Graph
        const graphData = await fetchAPI('/api/graph');
        lastGraph = graphData;
        updateGraph(graphData);

        // 5. Active Chat
        if (currentSessionId) {
            const sessionData = await fetchAPI(`/api/sessions/${currentSessionId}`);
            currentSession = sessionData;
            renderChat(sessionData);
        }
    } catch (e) {
        console.error("Poll error:", e);
    } finally {
        isPolling = false;
    }
}

function animateValue(id, value) {
    const el = document.getElementById(id);
    const from = parseInt(el.innerText, 10) || 0;
    if (from === value) return;
    el.classList.add('bump');
    const start = performance.now(), dur = 700;
    const step = (t) => {
        const p = Math.min(1, (t - start) / dur);
        el.innerText = Math.round(from + (value - from) * (1 - Math.pow(1 - p, 3)));
        if (p < 1) requestAnimationFrame(step); else setTimeout(() => el.classList.remove('bump'), 600);
    };
    requestAnimationFrame(step);
}

// HUD clock
setInterval(() => {
    const c = document.getElementById('hud-clock');
    if (c) c.innerText = CLOCK_FMT.format(new Date());
}, 1000);

// Render Left Column
let lastListKey = '';
function renderSessionList(sessions) {
    const container = document.getElementById('session-list');
    // Re-render only when something changed, so keyboard focus survives polling
    const key = currentSessionId + '|' + JSON.stringify(sessions);
    if (key === lastListKey) return;
    lastListKey = key;
    const hadFocus = container.contains(document.activeElement) ? document.activeElement.dataset.id : null;
    container.innerHTML = '';
    if (!sessions.length) {
        container.innerHTML = '<div class="session-empty">[ no sessions yet ]<br>Paste a scam message below and press Engage Decoy.</div>';
        return;
    }
    sessions.forEach(s => {
        const div = document.createElement('button');
        div.type = 'button';
        div.dataset.id = s.id;
        div.className = `session-item ${s.id === currentSessionId ? 'selected' : ''}`;
        div.setAttribute('aria-pressed', s.id === currentSessionId ? 'true' : 'false');
        div.onclick = () => selectSession(s.id);
        
        let cColor = s.campaign_id ? '#ff3b1f' : '#6f675e';
        let cBadge = s.campaign_id ? `<span class="chip chip-campaign" style="border-color: ${cColor}; color: ${cColor}">GANG ${escapeHTML(s.campaign_id)}</span>` : '';
        
        div.innerHTML = `
            <div class="case-no">CASE #${escapeHTML(s.id.replace(/^s_/, '').toUpperCase())}</div>
            <div>
                <span class="chip">${escapeHTML(s.scam_type.replace(/_/g, ' '))}</span>
                ${cBadge}
            </div>
            <div class="session-meta">${escapeHTML(s.channel)} • ${plural(s.message_count, 'msg')} • ${plural(s.entity_count, 'identifier')}</div>
        `;
        container.appendChild(div);
        if (hadFocus === s.id) div.focus();
    });
}

// Render Center Chat
// Lyric-video stage: the latest scammer line appears word by word,
// and any identifier in it gets stamped CAPTURED
let lastStageId = null;
function renderStage(session) {
    const stage = document.getElementById('stage');
    const last = [...session.messages].reverse().find(m => m.role === 'scammer');
    if (!last) { stage.hidden = true; lastStageId = null; return; }
    stage.hidden = false;
    const stageKey = session.id + '|' + last.id + '|' + session.entities.length;
    if (stageKey === lastStageId) return;
    lastStageId = stageKey;
    const raws = session.entities.filter(e => e.message_id === last.id).map(e => e.raw);
    // split text into identifier hits and plain words, keeping order
    const parts = [];
    let rest = last.text;
    while (rest.length) {
        let best = null;
        raws.forEach(r => { const i = rest.indexOf(r); if (i >= 0 && (!best || i < best.i)) best = { i, r }; });
        if (!best) { parts.push(...rest.split(/\s+/).filter(Boolean).map(w => ({ w }))); break; }
        parts.push(...rest.slice(0, best.i).split(/\s+/).filter(Boolean).map(w => ({ w })));
        parts.push({ w: best.r, hit: true });
        rest = rest.slice(best.i + best.r.length);
    }
    document.getElementById('stage-text').innerHTML = parts.map((p, i) =>
        `<span class="w${p.hit ? ' hit' : ''}" style="animation-delay:${(i * 0.08).toFixed(2)}s">${escapeHTML(p.w)}</span>`
    ).join(' ');
}

let lastChatKey = '';
let lastChatSession = null;
let lastChatCount = 0;
function renderChat(session) {
    const win = document.getElementById('chat-window');
    // Only redraw when something changed, so messages don't flicker every poll
    const key = [session.id, session.status, session.messages.length, session.entities.length].join('|');
    if (key === lastChatKey) return;
    const sameSession = lastChatSession === session.id;
    const firstNew = sameSession ? lastChatCount : session.messages.length; // animate only newly arrived msgs
    lastChatKey = key; lastChatSession = session.id; lastChatCount = session.messages.length;
    win.innerHTML = '';
    
    document.getElementById('chat-actions').style.display = 'flex';
    document.getElementById('chat-input-area').style.display = session.status === 'active' ? 'flex' : 'none';
    document.getElementById('btn-report').href = `${API_BASE}/api/sessions/${session.id}/report`;
    
    session.messages.forEach((m, idx) => {
        const msgDiv = document.createElement('div');
        msgDiv.className = `message msg-${m.role}${idx >= firstNew ? ' new' : ''}`;
        
        // Find entities for this message
        const mEntities = session.entities.filter(e => e.message_id === m.id);
        let htmlText = escapeHTML(m.text);
        
        // Highlight logic
        mEntities.forEach(ent => {
            const eRaw = escapeHTML(ent.raw);
            const color = COLORS[ent.type] || '#fff';
            const span = `<span style="color: ${color}; font-weight: bold; background: ${color}22; box-shadow: inset 0 0 0 1px ${color}66;">${eRaw}</span>`;
            htmlText = htmlText.split(eRaw).join(span);
        });

        msgDiv.innerHTML = `<div>${htmlText}</div><div class="msg-ts">${TIME_FMT.format(new Date(m.ts))}</div>`;
        win.appendChild(msgDiv);
    });

    // the backend saves the scammer's message before the model answers: show the decoy typing
    const last = session.messages[session.messages.length - 1];
    if (session.status === 'active' && last && last.role === 'scammer') {
        const t = document.createElement('div');
        t.className = 'typing';
        t.innerHTML = `${escapeHTML(personaOf(session.persona).name)} is typing <i></i><i></i><i></i>`;
        win.appendChild(t);
    }

    renderStage(session);
    renderIntel(session);
    tick();
    if (autoScroll) win.scrollTop = win.scrollHeight;
}

// Auto-scroll logic
document.getElementById('chat-window').addEventListener('scroll', (e) => {
    const el = e.target;
    autoScroll = el.scrollTop + el.clientHeight >= el.scrollHeight - 10;
});

function selectSession(id) {
    currentSessionId = id;
    pollData(); // Force immediate update
}

// Jitter-free Graph Update
function getCampaignColor(cid) {
    if (!cid) return '#6f675e'; // unlinked = grey
    const num = parseInt(cid.replace(/\D/g, '')) || 0;
    return CAMPAIGN_COLORS[num % CAMPAIGN_COLORS.length];
}

function updateGraph(data) {
    if (!cy) initGraph();
    
    const currentIds = new Set(cy.elements().map(e => e.id()));
    const incomingIds = new Set();
    const newElements = [];
    let changed = false;

    // Track shared entities and new campaigns
    const sharedEntities = new Set();
    data.campaigns.forEach(c => {
        c.shared_entities.forEach(se => sharedEntities.add(se));
        if (isGraphInit && !knownCampaigns.has(c.id)) {
            knownCampaigns.add(c.id);
            const firstShared = (c.shared_entities[0] || '').split(':').slice(1).join(':');
            showToast(firstShared ? `New campaign ${c.id} linked: ${c.size} sessions share ${firstShared}` : `New campaign ${c.id} linked: ${c.size} sessions`);
        } else {
            knownCampaigns.add(c.id);
        }
    });

    data.nodes.forEach(n => {
        incomingIds.add(n.id);
        const color = n.type === 'session' ? getCampaignColor(n.campaign_id) : (COLORS[n.type] || '#9ca3af');
        if (!currentIds.has(n.id)) {
            changed = true;
            newElements.push({ group: 'nodes', data: { id: n.id, label: n.label, type: n.type, color: color, shared: sharedEntities.has(n.id) } });
        } else {
            const node = cy.getElementById(n.id);
            if (node.data('color') !== color || node.data('shared') !== sharedEntities.has(n.id)) {
                node.data({ color: color, shared: sharedEntities.has(n.id) });
            }
        }
    });

    data.edges.forEach(e => {
        const eid = `${e.source}->${e.target}`;
        incomingIds.add(eid);
        if (!currentIds.has(eid)) {
            changed = true;
            newElements.push({ group: 'edges', data: { id: eid, source: e.source, target: e.target } });
        }
    });

    // Remove missing
    currentIds.forEach(id => {
        if (!incomingIds.has(id)) {
            changed = true;
            cy.getElementById(id).remove();
        }
    });

    if (newElements.length > 0) cy.add(newElements);
    document.getElementById('graph-empty').hidden = data.nodes.length > 0;

    if (changed) {
        if (isGraphInit) {
            cy.layout({ ...LAYOUT, animate: true, randomize: false, fit: true }).run();
        } else {
            cy.layout(LAYOUT).run();
            isGraphInit = true;
        }
    }
}

// User Actions
const OFFLINE_HELP = "Can't reach the backend on :8000. Start it with python -m backend.main (or tools/mock_server.py) and try again.";

// Disable a button and show a busy label while a request runs
async function withBusy(btn, busyLabel, fn) {
    const label = btn.innerText;
    btn.disabled = true;
    btn.innerText = busyLabel;
    try { await fn(); }
    catch (e) { showToast(OFFLINE_HELP, true); }
    finally { btn.disabled = false; btn.innerText = label; }
}

document.getElementById('btn-create-session').onclick = () => {
    const box = document.getElementById('new-message');
    const text = box.value.trim();
    if (!text) { showToast('Paste a scam message first, then press Engage Decoy.', true); box.focus(); return; }
    const btn = document.getElementById('btn-create-session');
    withBusy(btn, 'Engaging…', async () => {
        const req = { channel: document.getElementById('new-channel').value, first_message: text, persona: document.getElementById('new-persona').value };
        const session = await fetchAPI('/api/sessions', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(req) });
        box.value = '';
        selectSession(session.id);
    });
};

document.getElementById('btn-send-msg').onclick = () => {
    const input = document.getElementById('manual-msg');
    const text = input.value.trim();
    if (!text || !currentSessionId) return;
    withBusy(document.getElementById('btn-send-msg'), 'Sending…', async () => {
        await fetchAPI(`/api/sessions/${currentSessionId}/messages`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({text}) });
        input.value = '';
        pollData();
    });
};
document.getElementById('manual-msg').addEventListener('keydown', (e) => { if (e.key === 'Enter') document.getElementById('btn-send-msg').click(); });

// Terminate is destructive: first click arms it, second click within 3 s confirms
let terminateTimer = null;
document.getElementById('btn-close').onclick = () => {
    const btn = document.getElementById('btn-close');
    if (!currentSessionId) return;
    if (!btn.classList.contains('armed')) {
        btn.classList.add('armed');
        btn.innerText = 'Confirm Terminate?';
        terminateTimer = setTimeout(() => { btn.classList.remove('armed'); btn.innerText = 'Terminate'; }, 3000);
        return;
    }
    clearTimeout(terminateTimer);
    btn.classList.remove('armed');
    btn.innerText = 'Terminate';
    withBusy(btn, 'Terminating…', async () => {
        await fetchAPI(`/api/sessions/${currentSessionId}/close`, { method: 'POST' });
        pollData();
    });
};

setInterval(pollData, 2000);
pollData();

// Full-screen toggle for the projector (F11 also works)
const fsBtn = document.getElementById('btn-fullscreen');
if (fsBtn) {
    fsBtn.onclick = () => {
        if (document.fullscreenElement) document.exitFullscreen();
        else document.documentElement.requestFullscreen().catch(() => showToast('Full screen was blocked by the browser. Press F11 instead.', true));
    };
    document.addEventListener('fullscreenchange', () => {
        const on = !!document.fullscreenElement;
        fsBtn.setAttribute('aria-pressed', on);
        fsBtn.setAttribute('aria-label', on ? 'Exit full screen' : 'Enter full screen');
        fsBtn.title = on ? 'Exit full screen' : 'Full screen';
    });
}

// Preloader: count 00 -> 100, then wipe up
(function preloader() {
    const el = document.getElementById('preloader');
    if (!el) return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) { el.remove(); return; }
    const num = document.getElementById('pre-count'), bar = document.getElementById('pre-bar');
    const start = performance.now(), dur = 1100;
    const tick = (t) => {
        const p = Math.min(1, (t - start) / dur);
        const v = Math.round(100 * (1 - Math.pow(1 - p, 2)));
        num.textContent = String(v).padStart(2, '0');
        bar.style.width = v + '%';
        if (p < 1) requestAnimationFrame(tick);
        else { el.classList.add('done'); setTimeout(() => el.remove(), 1000); }
    };
    requestAnimationFrame(tick);
})();

// "Complaint" button: a ready-to-paste complaint for cybercrime.gov.in (copied, or downloaded as .txt)
const LABEL = { upi_id: 'UPI ID', phone: 'Phone number', url: 'Website / link', bank_account: 'Bank account', ifsc: 'IFSC code', email: 'Email', crypto_wallet: 'Crypto wallet' };
const TS_FMT = new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });

function complaintText(s) {
    const a = analyse(s);
    const scam = s.messages.filter(m => m.role === 'scammer');
    const first = s.messages[0] ? TS_FMT.format(new Date(s.messages[0].ts)) : '-';
    const last = s.messages.length ? TS_FMT.format(new Date(s.messages[s.messages.length - 1].ts)) : '-';
    const camp = lastGraph && lastGraph.campaigns.find(c => c.session_ids.includes(s.id));
    const lines = [
        'SCAM COMPLAINT [SIMULATION - generated by Scambaiter]',
        '',
        `Incident: ${s.scam_type.replace(/_/g, ' ')} scam received on ${s.channel}`,
        `Date/time: ${first} to ${last}`,
        `Red flags: ${a.flags.join(', ') || 'none detected'}`,
        '',
        'Identifiers used by the scammer:',
        ...(s.entities.length ? s.entities.map(e => `- ${LABEL[e.type] || e.type}: ${e.value}`) : ['- none captured']),
        '',
        camp ? `The same identifiers appear in ${camp.size - 1} other report(s) (linked campaign ${camp.id}), which suggests an organised group.` : 'No link to other reports found yet.',
        '',
        `What happened: I received messages asking me to ${a.payAsked ? 'make a payment' : 'take action'}${a.otpAsked ? ' and share an OTP/PIN' : ''}. ` +
        (a.secretsShared || a.paid
            ? 'Please check the transcript below: a number or payment may have been shared.'
            : 'I did not share any OTP, PIN or bank details and did not send any money.'),
        '',
        "Scammer's messages:",
        ...scam.map(m => `[${TS_FMT.format(new Date(m.ts))}] ${m.text}`),
        '',
        'Report at https://cybercrime.gov.in or call 1930. Identifiers are machine-extracted; please verify before legal action.',
    ];
    return lines.join('\n');
}

document.getElementById('btn-complaint').onclick = async () => {
    if (!currentSession) return;
    const text = complaintText(currentSession);
    try {
        await navigator.clipboard.writeText(text);
        showToast('Complaint copied. Paste it at cybercrime.gov.in');
    } catch (e) {
        const blob = new Blob([text], { type: 'text/plain' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `complaint-${currentSession.id}.txt`;
        a.click();
        URL.revokeObjectURL(a.href);
        showToast('Complaint downloaded as a text file');
    }
};
