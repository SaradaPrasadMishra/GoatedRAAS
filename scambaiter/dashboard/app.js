const API_BASE = window.API_BASE || (location.protocol === "file:" ? "http://localhost:8000" : "");

// Entity Color Palette
const COLORS = {
    upi_id: "#0f8a5f", phone: "#2448c9", url: "#b45309",
    bank_account: "#c0262d", ifsc: "#7c3aed", email: "#0e7490", crypto_wallet: "#a16207"
};
const CAMPAIGN_COLORS = ['#e3260f', '#e3260f', '#b45309', '#5b21b6', '#0f766e', '#be185d', '#1d4ed8'];

// State
let currentSessionId = null;
let knownSessionIds = null; // ids seen on the previous poll (null until the first poll)
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

// Red flags, risk, safety record and money for the open case come from the backend
// (report/analysis.py), so the dashboard, the report and the quick check always agree.
let currentAnalysis = null;
let replayIds = new Set(), replayNames = [];
const rupees = (n) => '₹' + Number(n || 0).toLocaleString('en-IN');

function renderIntel(session, a) {
    const intel = document.getElementById('intel');
    if (!a || !session.messages.some(m => m.role === 'scammer')) { intel.hidden = true; return; }
    intel.hidden = false;
    const risk = document.getElementById('risk');
    risk.textContent = a.level + ' RISK';
    risk.className = 'risk ' + a.level.toLowerCase();
    document.getElementById('flags').innerHTML = a.flags.length
        ? a.flags.map(f => `<span class="flag">${escapeHTML(f)}</span>`).join('')
        : '<span class="flag">none yet</span>';
    const n = (v) => `<b class="${v ? 'bad' : ''}">${v}</b>`;
    const money = a.demanded ? ` (${rupees(a.demanded)})` : '';
    document.getElementById('safety').innerHTML =
        `OTP/PIN asked ${a.otp_asked}× · given ${n(a.shared)} &nbsp;·&nbsp; payment asked ${a.pay_asked}×${money} · paid ${n(a.paid)} &nbsp;·&nbsp; links opened <b>0</b>`;
    // evidence seal: every message is hash-chained when captured; any later edit shows here
    const seal = document.getElementById('seal');
    if (currentSeal && currentSeal.ok) {
        seal.className = 'seal-badge ok';
        seal.textContent = `SEALED ✓ ${plural(currentSeal.messages, 'msg')}${currentSeal.encrypted ? ' · encrypted' : ''}`;
        seal.title = 'Every message is in an HMAC-SHA256 hash chain made at capture. Chain head ' + (currentSeal.head || '').slice(0, 16);
    } else if (currentSeal) {
        seal.className = 'seal-badge bad';
        seal.textContent = 'TAMPERED ✗';
        seal.title = currentSeal.reason || 'The stored transcript no longer matches its seal';
    } else {
        seal.className = 'seal-badge'; seal.textContent = 'checking…'; seal.title = '';
    }
    const src = sources[session.id];
    document.getElementById('src-info').textContent = !src ? '' :
        src.mode === 'report' ? `✉ forwarded by ${src.reporter || 'a user'} · sender ${src.peer || '?'}`
        : src.source === 'sms_gateway' ? `SMS from ${src.peer}`
        : `✉ ${src.peer || ''}${src.subject ? ' · “' + src.subject + '”' : ''}`;
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
    // click anything that belongs to a gang to open its dossier
    cy.on('tap', 'node', (e) => { const c = e.target.data('campaign'); if (c) openDossier(c); });
    cy.on('mouseover', 'node', (e) => { document.getElementById('cy').style.cursor = e.target.data('campaign') ? 'pointer' : ''; });
    cy.on('mouseout', 'node', () => { document.getElementById('cy').style.cursor = ''; });
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

// Fetch Wrapper: sends the login cookie; a 401 means the login expired, so go back to the login page
async function fetchAPI(endpoint, options = {}) {
    let res;
    try {
        res = await fetch(API_BASE + endpoint, { credentials: 'same-origin', ...options });
    } catch (err) {
        document.getElementById('offline-pill').style.display = 'inline-block';
        throw err;
    }
    document.getElementById('offline-pill').style.display = 'none';
    if (res.status === 401) { location.href = '/login.html'; throw new Error('login required'); }
    if (!res.ok) {
        let detail = '';
        try { detail = (await res.json()).detail; } catch (e) { /* not JSON */ }
        const err = new Error(typeof detail === 'string' && detail ? detail : 'HTTP ' + res.status);
        err.status = res.status;
        throw err;
    }
    return await res.json();
}
const postJSON = (endpoint, body = {}) =>
    fetchAPI(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

// Who is signed in: admins also get the Security console and unmasked data
let me = { role: 'analyst' };
fetchAPI('/api/me').then(m => {
    me = m;
    document.getElementById('user-chip').textContent = `${m.role.toUpperCase()} · ${m.user}`;
    document.getElementById('btn-security').hidden = m.role !== 'admin';
    document.getElementById('btn-logout').hidden = m.kind !== 'user';
}).catch(() => {});
document.getElementById('btn-logout').onclick = async () => {
    try { await postJSON('/api/logout'); } finally { location.href = '/login.html'; }
};

let lastStats = null, lastSessions = [], lastGraph = null, currentSession = null;
let sources = {}, currentSeal = null, currentLinks = null;   // where each case came from (Gmail, SMS gateway, .eml); evidence seal of the open case
const SOURCE_TAG = { gmail: '✉ EMAIL', eml_upload: '✉ EMAIL', sms_gateway: 'SMS GATEWAY' };
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
        document.getElementById('btn-save-replay').hidden = false;
        const reported = sources[s.id] && sources[s.id].mode === 'report';
        document.getElementById('call-persona').textContent = reported ? 'Reported scam · no decoy reply'
            : (replayIds.has(s.id) ? '▶ REPLAY · ' : '') + 'as ' + personaOf(s.persona).name;
        document.getElementById('call-persona').title = personaOf(s.persona).who;
        document.getElementById('call-timer').textContent = (s.status === 'active' ? 'on call ' : 'closed after ') + formatClock(secs);
    } else {
        meta.hidden = true;
        document.getElementById('btn-save-replay').hidden = true;
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
        fetchAPI('/api/money').then(m => {
            document.getElementById('stat-money').innerText = rupees(m.demanded);
            document.getElementById('money-paid').innerText = m.paid_times ? 'paid: check report' : 'paid ₹0';
        }).catch(() => {});

        // 3. Sessions list
        const sessions = await fetchAPI('/api/sessions');
        lastSessions = sessions;
        sources = await fetchAPI('/api/sources').catch(() => sources);
        const rp = await fetchAPI('/api/replays').catch(() => null);
        if (rp) { replayIds = new Set(rp.replay_sessions); replayNames = rp.recordings; }
        // Auto-follow: when a brand-new case arrives (e.g. from the scammer's phone), switch to it
        const ids = new Set(sessions.map(s => s.id));
        if (knownSessionIds !== null) {
            const fresh = sessions.find(s => !knownSessionIds.has(s.id));
            if (fresh) currentSessionId = fresh.id;
        }
        knownSessionIds = ids;
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
            currentAnalysis = await fetchAPI(`/api/sessions/${currentSessionId}/analysis`).catch(() => null);
            currentSeal = await fetchAPI(`/api/sessions/${currentSessionId}/verify`).catch(() => null);
            currentLinks = sessionData.entities.some(e => e.type === 'url')
                ? await fetchAPI(`/api/sessions/${currentSessionId}/links`).catch(() => currentLinks) : null;
            renderLinks(sessionData);
            renderChat(sessionData);
            renderIntel(sessionData, currentAnalysis);
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
    const key = currentSessionId + '|' + [...replayIds].join(',') + '|' + Object.keys(sources).length + '|' + JSON.stringify(sessions);
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
            <div class="case-no">CASE #${escapeHTML(s.id.replace(/^s_/, '').toUpperCase())}${replayIds.has(s.id) ? ' <span class="replay-tag">▶ REPLAY</span>' : ''}</div>
            <div>
                <span class="chip">${escapeHTML(s.scam_type.replace(/_/g, ' '))}</span>
                ${cBadge}
            </div>
            <div class="session-meta">${sources[s.id] ? `<span class="src-tag">${SOURCE_TAG[sources[s.id].source] || ''}${sources[s.id].mode === 'report' ? ' · REPORTED' : ''}</span>` : escapeHTML(s.channel)} • ${plural(s.message_count, 'msg')} • ${plural(s.entity_count, 'identifier')}</div>
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
    document.querySelector('#stage .stage-label').textContent = replayIds.has(session.id) ? 'Replay of a recorded case · scammer says' : 'Scammer says';
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
    document.getElementById('btn-complaint').href = `${API_BASE}/api/sessions/${session.id}/complaint`;
    
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
    document.getElementById('check-panel').hidden = true;
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
            newElements.push({ group: 'nodes', data: { id: n.id, label: n.label, type: n.type, color: color, shared: sharedEntities.has(n.id), campaign: n.campaign_id || null } });
        } else {
            const node = cy.getElementById(n.id);
            if (node.data('color') !== color || node.data('shared') !== sharedEntities.has(n.id) || node.data('campaign') !== (n.campaign_id || null)) {
                node.data({ color: color, shared: sharedEntities.has(n.id), campaign: n.campaign_id || null });
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
    catch (e) { showToast(e.status ? e.message : OFFLINE_HELP, true); }
    finally { btn.disabled = false; btn.innerText = label; }
}

document.getElementById('new-form').addEventListener('submit', (e) => e.preventDefault());
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

// "Complaint" opens /api/sessions/{id}/complaint: the NCRP form fields, printable, with a JSON download
const LABEL = { upi_id: 'UPI ID', phone: 'Phone number', url: 'Website / link', bank_account: 'Bank account', ifsc: 'IFSC code', email: 'Email', crypto_wallet: 'Crypto wallet' };
const TS_FMT = new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });

// The decoy picker is the backend's default for every new case, including ones started from the
// scammer's phone page. A case keeps its decoy once it starts: say so when the picker changes mid-case.
fetchAPI('/api/decoy').then(d => { document.getElementById('new-persona').value = d.persona; }).catch(() => {});
document.getElementById('new-persona').addEventListener('change', (e) => {
    const picked = personaOf(e.target.value).name;
    fetchAPI('/api/decoy', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ persona: e.target.value }) })
        .catch(() => showToast('Could not save the decoy choice. Is the backend running?', true));
    if (currentSession && currentSession.status === 'active' && currentSession.persona !== e.target.value) {
        showToast(`${personaOf(currentSession.persona).name} stays on this case. Press Engage Decoy to start a new one with ${picked}.`);
    }
});

// One-click sample scams (synthetic) so nobody has to type on stage
const SAMPLES = {
    kyc: ['sms', 'URGENT: Your SBI account will be blocked today. Share the OTP and pay Rs 10 to sbi.kyc@okaxis or call 9876543210'],
    arrest: ['whatsapp', 'This is CBI cyber cell. A parcel in your name has illegal drugs and you are under digital arrest. Stay on this call and do not tell anyone. Transfer Rs 50,000 to account 39200188765012 IFSC SBIN0004521 for verification.'],
    job: ['whatsapp', 'Part time job! Earn Rs 3000 per day by liking YouTube videos. Pay the joining fee of Rs 499 to hr.tasks@ybl. WhatsApp 9123456780 to start.'],
    hinglish: ['sms', 'Aapka Paytm KYC expire ho gaya hai. Abhi update karo warna wallet block ho jayega. Rs 1 bhejo kyc.update@paytm pe ya call karo 8765432109.'],
    hinglish_job: ['whatsapp', 'Ghar baithe kamao Rs 3000 roz! Bas YouTube videos like karne hain. Joining fee Rs 499 bhejo hr.tasks@ybl pe aur WhatsApp karo 9123456780. Jaldi karo, offer sirf aaj ke liye hai.'],
};
document.querySelectorAll('.sample').forEach(b => b.addEventListener('click', () => {
    const [channel, text] = SAMPLES[b.dataset.sample];
    document.getElementById('new-channel').value = channel;
    const box = document.getElementById('new-message');
    box.value = text;
    box.focus();
}));

// "Is this a scam?" quick check: verdict, red flags and identifiers, without starting a decoy
const WHY = {
    'Urgency': 'Rushes you so you do not stop to think.',
    'Asks for OTP / PIN': 'No bank or agency ever asks for your OTP or PIN.',
    'Demands payment': 'Real refunds, prizes and jobs never ask you to pay first.',
    'Fake authority': 'Pretends to be a bank, police or a big company to sound official.',
    'Threat': 'Scares you with blocked accounts, arrest or penalties.',
    'Too good to be true': 'Promises easy money, prizes or refunds.',
    'Secrecy': 'Tells you not to tell anyone, so nobody can warn you.',
    'Moves you to WhatsApp / Telegram': 'Pulls you into a private chat app, away from official channels.',
    'Suspicious link': 'Contains a link. Never open links from unknown senders.',
    'Tries to trick the AI': 'Gives orders meant for an AI, or tests whether it is one. The decoy ignores them.',
};
const VERDICT = { HIGH: 'Very likely a scam', MEDIUM: 'Likely a scam', LOW: 'No strong scam signs' };

document.getElementById('btn-check').onclick = () => {
    const text = document.getElementById('new-message').value.trim();
    if (!text) { showToast('Paste a message first, then press Check.', true); document.getElementById('new-message').focus(); return; }
    withBusy(document.getElementById('btn-check'), 'Checking…', async () => {
        const r = await fetchAPI('/api/check', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text }) });
        const low = r.level === 'LOW' && !r.flags.length;
        const v = document.getElementById('check-verdict');
        v.textContent = low ? 'No common scam signs found' : VERDICT[r.level];
        v.className = 'check-verdict' + (r.level === 'HIGH' ? ' high' : '');
        document.getElementById('check-sub').innerHTML =
            `<span class="risk ${r.level.toLowerCase()}">${r.level} RISK</span>` +
            (r.scam_type && !['unknown', 'other'].includes(r.scam_type) ? `<span>looks like: ${escapeHTML(r.scam_type.replace(/_/g, ' '))}</span>` : '') +
            (r.demanded ? `<span>asks for ${rupees(r.demanded)}</span>` : '');
        document.getElementById('check-flags').innerHTML = r.flags.map(f =>
            `<li><b>${escapeHTML(f)}</b>${escapeHTML(WHY[f] || '')}</li>`).join('') ||
            '<li><b>Still careful</b>Scammers change their wording. If in doubt, call the company on its official number.</li>';
        document.getElementById('check-ids').innerHTML = r.entities.length
            ? r.entities.map(e => `<span style="color:${COLORS[e.type] || '#16130f'}">${escapeHTML(LABEL[e.type] || e.type)}: ${escapeHTML(e.value)}</span>`).join('')
            : '';
        document.getElementById('check-panel').hidden = false;
        document.getElementById('check-close').focus();
    });
};
const closeCheck = () => { document.getElementById('check-panel').hidden = true; };
document.getElementById('check-close').onclick = closeCheck;
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeCheck(); });
document.getElementById('check-engage').onclick = () => { closeCheck(); document.getElementById('btn-create-session').click(); };

// ---------------------------------------------------------------- gang dossier
const fmtDate = (iso) => iso ? TS_FMT.format(new Date(iso)) : '-';
let openGang = null;

async function openDossier(cid) {
    let d;
    try { d = await fetchAPI(`/api/campaigns/${cid}/dossier`); }
    catch (e) { showToast('Could not load that gang. Is the backend running?', true); return; }
    openGang = d;
    document.getElementById('gang-title').textContent = 'Gang ' + d.id.toUpperCase();
    document.getElementById('gang-sub').textContent =
        `${d.dominant_scam_type.replace(/_/g, ' ')} · first seen ${fmtDate(d.first_seen)} · last seen ${fmtDate(d.last_seen)}`;
    document.getElementById('gang-stats').innerHTML = [
        [d.size, plural(d.size, 'case').replace(/^\d+ /, '')],
        [d.identifiers.length, 'identifiers'],
        [rupees(d.demanded), 'demanded'],
        [formatTime(d.time_wasted_seconds), 'wasted'],
    ].map(([v, k]) => `<div><b>${escapeHTML(String(v))}</b><span>${k}</span></div>`).join('');
    document.getElementById('gang-ids').innerHTML = d.identifiers.map(i =>
        `<li class="${i.shared ? 'shared' : ''}"><span class="t" style="color:${COLORS[i.type] || '#16130f'}">${escapeHTML(LABEL[i.type] || i.type)}</span>` +
        `<code>${escapeHTML(i.value)}</code><span class="n">${i.shared ? 'links ' : ''}${plural(i.cases, 'case')}</span></li>`).join('');
    document.getElementById('gang-cases').innerHTML = d.cases.map(c =>
        `<li><button type="button" data-id="${escapeHTML(c.id)}">#${escapeHTML(c.id.replace(/^s_/, '').toUpperCase())}` +
        ` · ${escapeHTML(c.scam_type.replace(/_/g, ' '))} · ${escapeHTML(c.channel)}${c.demanded ? ' · ' + rupees(c.demanded) : ''}${c.replay ? ' · replay' : ''}</button></li>`).join('');
    document.querySelectorAll('#gang-cases button').forEach(b => b.onclick = () => { closeDossier(); selectSession(b.dataset.id); });
    document.getElementById('gang-panel').hidden = false;
    document.getElementById('gang-close').focus();
}
function closeDossier() { document.getElementById('gang-panel').hidden = true; openGang = null; }
document.getElementById('gang-close').onclick = closeDossier;
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDossier(); });

// CSV a bank fraud desk or I4C can load: one row per identifier
document.getElementById('gang-export').onclick = () => {
    const d = openGang;
    if (!d) return;
    const q = (v) => `"${String(v).replace(/"/g, '""')}"`;
    const rows = [['gang', 'identifier_type', 'value', 'cases', 'links_cases', 'first_seen', 'last_seen', 'scam_type', 'note']];
    d.identifiers.forEach(i => rows.push([d.id, i.type, i.value, i.cases, i.shared ? 'yes' : 'no', d.first_seen, d.last_seen,
        d.dominant_scam_type, 'SIMULATION - machine-extracted, verify before action']));
    const blob = new Blob([rows.map(r => r.map(q).join(',')).join('\r\n') + '\r\n'], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `scambaiter-gang-${d.id}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
    showToast(`Gang ${d.id.toUpperCase()}: ${plural(d.identifiers.length, 'identifier')} exported for bank / I4C`);
};

// ---------------------------------------------------------------- backup replay
// "Save for replay" records the open case (do it in rehearsal, with the real AI on).
// Shift+R on stage replays the newest recording as a new case, clearly labelled REPLAY.
document.getElementById('btn-save-replay').onclick = () => {
    if (!currentSessionId) return;
    withBusy(document.getElementById('btn-save-replay'), 'Saving…', async () => {
        const r = await fetchAPI(`/api/sessions/${currentSessionId}/save-replay`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
        showToast(`Saved for replay (${plural(r.turns, 'turn')}, AI was ${r.llm === 'ollama' ? 'live' : 'off'}). Shift+R replays it.`);
    });
};
document.addEventListener('keydown', async (e) => {
    if (!(e.shiftKey && (e.key === 'R' || e.key === 'r'))) return;
    if (/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)) return;
    e.preventDefault();
    try {
        const r = await fetchAPI('/api/replays', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
        showToast(`▶ Replaying a recorded case (${plural(r.turns, 'turn')})`);
        selectSession(r.session_id);
    } catch (err) {
        showToast('No recording yet. In rehearsal, open a good case and press "Save".', true);
    }
});

// ---------------------------------------------------------------- signed bank alert
// Mule-account alert for a gang: what each bank / UPI app should freeze, signed with the node's Ed25519 key
const download = (name, text, type) => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], { type }));
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
};
document.getElementById('gang-alert').onclick = () => {
    const d = openGang;
    if (!d) return;
    withBusy(document.getElementById('gang-alert'), 'Signing…', async () => {
        const alert = await fetchAPI(`/api/campaigns/${d.id}/alert`);
        download(`mule-alert-${d.id}.json`, JSON.stringify(alert, null, 2), 'application/json');
        const banks = Object.keys(alert.by_bank);
        showToast(`Signed alert for ${banks.length ? banks.join(', ') : 'the fraud desk'} · key ${alert.signature.key_id}`);
    });
};

// ---------------------------------------------------------------- scam email (.eml) intake
// The same code path as the Gmail inbox: a forwarded scam becomes a reported case,
// a direct scam email starts a decoy conversation.
async function uploadEml(file) {
    if (!file) return;
    if (file.size > 2 * 1024 * 1024) { showToast('That email is over 2 MB.', true); return; }
    try {
        const raw = await file.arrayBuffer();
        const r = await fetchAPI('/api/intake/email', { method: 'POST', headers: { 'Content-Type': 'message/rfc822' }, body: raw });
        showToast(r.action === 'report'
            ? `Reported email: ${r.level} risk, ${plural(r.flags.length, 'red flag')}`
            : 'Scam email received: the decoy is answering it');
        if (r.session_id) selectSession(r.session_id);
        pollData();
    } catch (e) {
        showToast(e.status ? e.message : OFFLINE_HELP, true);
    }
}
const emlInput = document.getElementById('eml-file');
document.getElementById('btn-eml').onclick = () => emlInput.click();
emlInput.onchange = () => { uploadEml(emlInput.files[0]); emlInput.value = ''; };
const slip = document.getElementById('new-form');
slip.addEventListener('dragover', (e) => { e.preventDefault(); slip.classList.add('drop'); });
slip.addEventListener('dragleave', () => slip.classList.remove('drop'));
slip.addEventListener('drop', (e) => {
    e.preventDefault();
    slip.classList.remove('drop');
    const f = e.dataTransfer.files[0];
    if (f && /\.eml$/i.test(f.name)) uploadEml(f);
    else if (f) showToast('Drop an email saved as .eml (Gmail: ⋮ → Download message).', true);
});

// ---------------------------------------------------------------- security console (admin)
const secPanel = document.getElementById('sec-panel');
const kv = (rows) => '<dl class="kv">' + rows.map(([k, v, cls]) =>
    `<dt>${escapeHTML(k)}</dt><dd class="${cls || ''}">${v}</dd>`).join('') + '</dl>';
const ok = (good, yes, no) => `<b class="${good ? 'good' : 'bad'}">${escapeHTML(good ? yes : no)}</b>`;
const fmtTs = (iso) => iso ? CLOCK_FMT.format(new Date(iso)) : '-';

async function loadSecurity(tab) {
    document.querySelectorAll('.sec-tabs [role=tab]').forEach(b => b.setAttribute('aria-selected', b.dataset.tab === tab));
    ['overview', 'audit', 'keys', 'integrations'].forEach(t => document.getElementById('sec-' + t).hidden = t !== tab);
    try {
        if (tab === 'overview') {
            const o = await fetchAPI('/api/admin/security');
            const seal = o.evidence_seal, audit = o.audit_log;
            document.getElementById('sec-overview').innerHTML = `
                <div class="sec-cards">
                    <div class="sec-card"><span>Login</span><b>${escapeHTML(o.auth.toUpperCase())}</b><small>roles: admin, analyst · API keys: intake, lookup</small></div>
                    <div class="sec-card"><span>Evidence seal</span><b class="${seal.tampered.length ? 'bad' : 'good'}">${seal.sealed}/${seal.cases}</b><small>${seal.tampered.length ? 'TAMPERED: ' + seal.tampered.map(escapeHTML).join(', ') : 'every case verified'}</small></div>
                    <div class="sec-card"><span>Audit log</span><b class="${audit.ok ? 'good' : 'bad'}">${audit.ok ? 'INTACT' : 'BROKEN'}</b><small>${audit.entries} entries${audit.ok ? '' : ', broken at #' + audit.broken_at}</small></div>
                    <div class="sec-card"><span>At rest</span><b class="${o.encryption.startsWith('AES') ? 'good' : 'bad'}">${o.encryption.startsWith('AES') ? 'AES-256' : 'OFF'}</b><small>retention ${o.retention_days} days</small></div>
                </div>
                ${kv([
                    ['Encryption', escapeHTML(o.encryption)],
                    ['Evidence seal', escapeHTML(seal.algorithm)],
                    ['Listening on', escapeHTML(o.bind) + (o.tls ? ' · HTTPS' : ' · HTTP (use --tls-cert or a TLS proxy in production)')],
                    ['Rate limits', escapeHTML(Object.values(o.rate_limits).join(' · '))],
                    ['Cross-origin', escapeHTML(Array.isArray(o.cors) ? o.cors.join(', ') : o.cors)],
                    ['Users', escapeHTML(o.users.join(', '))],
                    ['Active API keys', String(o.api_keys)],
                    ['Signing key', `<code>${escapeHTML(o.signing_key)}</code> (Ed25519, public key at /api/v1/public-key)`],
                    ['Local tools', o.trusted_local_tools ? 'trusted from 127.0.0.1 (start with --strict to require keys)' : 'need an API key'],
                    ['Last retention purge', escapeHTML(o.last_purge || '-')],
                ])}
                <div class="sec-actions"><button type="button" id="sec-purge">Run retention purge now</button></div>`;
            document.getElementById('sec-purge').onclick = () => withBusy(document.getElementById('sec-purge'), 'Purging…', async () => {
                const r = await postJSON('/api/admin/purge', {});
                showToast(`Retention purge: ${plural(r.deleted.length, 'expired case')} deleted`);
                loadSecurity('overview');
            });
        } else if (tab === 'audit') {
            const a = await fetchAPI('/api/admin/audit?limit=200');
            document.getElementById('sec-audit').innerHTML = `
                <p class="sec-note">${ok(a.chain.ok, 'CHAIN INTACT', 'CHAIN BROKEN at #' + a.chain.broken_at)} · ${a.chain.entries} entries, each one hash-linked to the one before it. Editing or deleting any row breaks the chain from that row on.</p>
                <table class="audit"><thead><tr><th>#</th><th>Time</th><th>Who</th><th>From</th><th>Action</th><th>Target</th><th>Detail</th></tr></thead><tbody>
                ${a.entries.map(e => `<tr class="${/fail|locked|rate|injection|tamper/.test(e.action) ? 'warn' : ''}"><td>${e.seq}</td><td>${fmtTs(e.ts)}</td><td>${escapeHTML(e.actor)} <small>${escapeHTML(e.role)}</small></td><td>${escapeHTML(e.ip)}</td><td><b>${escapeHTML(e.action.replace(/_/g, ' '))}</b></td><td><code>${escapeHTML(e.target)}</code></td><td>${escapeHTML(e.detail)}</td></tr>`).join('')}
                </tbody></table>`;
        } else if (tab === 'keys') {
            const keys = await fetchAPI('/api/admin/keys');
            document.getElementById('key-list').innerHTML = keys.length ? `<table class="audit"><thead><tr><th>Name</th><th>Scope</th><th>Created</th><th>Last used</th><th>Uses</th><th></th></tr></thead><tbody>
                ${keys.map(k => `<tr class="${k.revoked ? 'revoked' : ''}"><td>${escapeHTML(k.name)}</td><td><code>${escapeHTML(k.scope)}</code></td><td>${fmtDate(k.created)}</td><td>${k.last_used ? fmtDate(k.last_used) : '-'}</td><td>${k.uses || 0}</td>
                <td>${k.revoked ? 'revoked' : `<button type="button" class="revoke" data-id="${escapeHTML(k.id)}">Revoke</button>`}</td></tr>`).join('')}</tbody></table>`
                : '<p class="sec-note">No API keys yet. Banks and telecoms call /api/v1/lookup and /api/v1/check with a lookup key; SMS gateways post to /api/intake/sms with an intake key.</p>';
            document.querySelectorAll('#key-list .revoke').forEach(b => b.onclick = () => withBusy(b, '…', async () => {
                await postJSON(`/api/admin/keys/${b.dataset.id}/revoke`);
                showToast('Key revoked: it stops working immediately');
                loadSecurity('keys');
            }));
        } else {
            const i = await fetchAPI('/api/integrations');
            const g = i.gmail || {};
            document.getElementById('sec-integrations').innerHTML = `
                <h3>Gmail inbox</h3>
                ${g.enabled ? kv([
                    ['Address', `<code>${escapeHTML(g.address)}</code>`],
                    ['How to use', 'Forward a scam email to this address: it becomes a case and the sender gets a verdict email. Emails sent straight to it start a decoy conversation (allow-listed senders only).'],
                    ['Decoy replies to', escapeHTML((g.decoy_allow || []).join(', ') || 'nobody (log only)')],
                    ['Last check', `${escapeHTML(g.last_poll || '-')}${g.last_error ? ' · <b class="bad">' + escapeHTML(g.last_error) + '</b>' : ''}`],
                    ['Counts', `${g.received} received · ${g.reports} reports · ${g.decoy_threads} decoy threads · ${g.replied} replies sent`],
                ]) + '<div class="sec-actions"><button type="button" id="gmail-poll">Check inbox now</button></div>'
                : '<p class="sec-note">Off. Set SCAMBAITER_GMAIL_USER and SCAMBAITER_GMAIL_APP_PASSWORD (a Gmail App Password) and restart. Until then, drop a scam email saved as .eml on the intake slip: it takes the same path.</p>'}
                <h3>Scammer's phone page</h3>
                <p class="sec-note">${i.phone_links && i.phone_links.length
                    ? 'Open on the phone (same Wi-Fi). The key after #k= pairs it, with intake rights only:<br>' + i.phone_links.map(l => `<code>${escapeHTML(l)}</code>`).join('<br>')
                    : 'Off: start the backend with <code>--lan</code> (run_demo.bat does) to pair a phone.'}</p>
                <h3>Link sandbox</h3>
                <p class="sec-note">Mode <b>${escapeHTML(i.link_sandbox.mode)}</b> · egress: ${escapeHTML(i.link_sandbox.egress)} · JavaScript ${escapeHTML(i.link_sandbox.javascript)} · forms ${escapeHTML(i.link_sandbox.forms)} · downloads ${escapeHTML(i.link_sandbox.downloads)}.
                Live mode: <code>SCAMBAITER_SANDBOX=live</code> on an isolated machine with <code>SCAMBAITER_SANDBOX_PROXY</code> set to a separate egress.</p>
                <h3>SMS gateway</h3>
                <p class="sec-note">POST <code>/api/intake/sms</code> with an intake API key: JSON <code>{"from": "+91…", "text": "…"}</code> from an Android SMS-forwarder app, or a Twilio / Exotel form webhook (the decoy's reply comes back as TwiML).</p>
                <h3>Public API for banks and telecoms</h3>
                <p class="sec-note"><code>GET /api/v1/lookup?type=upi_id&amp;value=…</code> · <code>POST /api/v1/check</code> with a lookup API key. Alerts are signed: verify with <code>/api/v1/public-key</code>.</p>`;
            const btn = document.getElementById('gmail-poll');
            if (btn) btn.onclick = () => withBusy(btn, 'Checking…', async () => {
                const r = await postJSON('/api/integrations/gmail/poll');
                showToast(`Gmail: ${plural(r.fetched, 'new email')}`);
                loadSecurity('integrations');
                pollData();
            });
        }
    } catch (e) {
        showToast(e.status ? e.message : OFFLINE_HELP, true);
    }
}
document.getElementById('btn-security').onclick = () => { secPanel.hidden = false; loadSecurity('overview'); document.getElementById('sec-close').focus(); };
document.getElementById('sec-close').onclick = () => { secPanel.hidden = true; };
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') secPanel.hidden = true; });
document.querySelectorAll('.sec-tabs [role=tab]').forEach(b => b.onclick = () => loadSecurity(b.dataset.tab));
document.getElementById('key-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const btn = e.target.querySelector('button');
    withBusy(btn, 'Creating…', async () => {
        const k = await postJSON('/api/admin/keys', { name: document.getElementById('key-name').value, scope: document.getElementById('key-scope').value });
        const box = document.getElementById('key-new');
        box.hidden = false;
        box.innerHTML = `<b>Copy this key now: it is shown only once.</b><code>${escapeHTML(k.key)}</code>`;
        document.getElementById('key-name').value = '';
        loadSecurity('keys');
    });
});

// ---------------------------------------------------------------- link sandbox
// Captured links are opened in the sandbox (never by the decoy): verdict, redirect path, what the page
// asks for, and payment details printed on it, which join the case and can link gangs.
const VERDICT_CLS = { MALICIOUS: 'v-bad', SUSPICIOUS: 'v-warn', 'NO SIGNS FOUND': 'v-ok' };
let linksKey = '';
function renderLinks(session) {
    const row = document.getElementById('links-row');
    const urls = session.entities.filter(e => e.type === 'url');
    row.hidden = !urls.length;
    if (!urls.length) return;
    const res = (currentLinks && currentLinks.links) || {};
    const key = session.id + JSON.stringify(urls.map(u => [u.value, res[u.value] && res[u.value].verdict]));
    if (key === linksKey) return;
    linksKey = key;
    const box = document.getElementById('links');
    box.innerHTML = urls.map(u => {
        const r = res[u.value];
        return `<button type="button" class="link-chip ${r ? VERDICT_CLS[r.verdict] || 'v-warn' : ''}" data-url="${escapeHTML(u.value)}">` +
            `${escapeHTML(u.value.length > 34 ? u.value.slice(0, 33) + '…' : u.value)} · ${r ? escapeHTML(r.verdict) : 'check in sandbox ▶'}</button>`;
    }).join('');
    box.querySelectorAll('.link-chip').forEach(b => b.onclick = () => openLink(b.dataset.url, b));
}

async function openLink(url, btn) {
    let r = currentLinks && currentLinks.links && currentLinks.links[url];
    if (!r) {
        await withBusy(btn, 'opening in sandbox…', async () => {
            r = await postJSON(`/api/sessions/${currentSessionId}/detonate`, { url });
        });
        if (!r) return;
        pollData();
    }
    const v = document.getElementById('link-verdict');
    v.textContent = r.verdict;
    v.className = 'check-verdict' + (r.verdict === 'MALICIOUS' ? ' high' : '');
    document.getElementById('link-sub').innerHTML =
        `<span class="risk ${r.verdict === 'MALICIOUS' ? 'high' : r.verdict === 'SUSPICIOUS' ? 'medium' : 'low'}">${escapeHTML(r.verdict)}</span>` +
        `<span>${escapeHTML(url)}</span>` + (r.title ? `<span>“${escapeHTML(r.title)}”</span>` : '') +
        (r.simulation ? '<span class="replay-tag">SIMULATION · demo site</span>' : '');
    document.getElementById('link-findings').innerHTML = (r.findings || []).map(f =>
        `<li class="sev-${escapeHTML(f.severity)}"><b>${escapeHTML(f.severity)}</b>${escapeHTML(f.finding)}</li>`).join('') ||
        `<li><b>${escapeHTML(r.verdict)}</b>${escapeHTML(r.reason || 'No warning signs on the page. That does not make it safe.')}</li>`;
    document.getElementById('link-chain').innerHTML = (r.chain || []).length
        ? 'Path: ' + r.chain.map(h => `<code>${escapeHTML(h.url)}</code> <small>${h.status} · ${escapeHTML(h.ip || '')}</small>`).join(' → ')
        : '';
    document.getElementById('link-ids').innerHTML = (r.identifiers || []).map(e =>
        `<span style="color:${COLORS[e.type] || '#16130f'}">${escapeHTML(LABEL[e.type] || e.type)}: ${escapeHTML(e.value)}</span>`).join('');
    document.getElementById('link-note').textContent =
        (r.new_identifiers && r.new_identifiers.length ? `${plural(r.new_identifiers.length, 'new identifier')} from the page added to this case. ` : '') +
        'Opened by the sandbox, never by the decoy: no JavaScript run, no form submitted, downloads only hashed.' +
        (r.sha256 ? ` Page SHA-256 ${r.sha256.slice(0, 16)}…` : '');
    document.getElementById('link-panel').hidden = false;
    document.getElementById('link-close').focus();
}
document.getElementById('link-close').onclick = () => { document.getElementById('link-panel').hidden = true; };
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') document.getElementById('link-panel').hidden = true; });
