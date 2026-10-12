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
        minZoom: 0.4, maxZoom: 2.5
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

// Main Polling Loop
async function pollData() {
    if (isPolling) return;
    isPolling = true;

    try {
        // 1. Health
        const health = await fetchAPI('/api/health').catch(() => null);
        if (health) {
            document.getElementById('health-status').innerText = health.llm === 'fallback' ? 'Fallback replies' : `Local model: ${health.model || 'qwen2.5'}`;
        }

        // 2. Stats
        const stats = await fetchAPI('/api/stats');
        animateValue('stat-sessions', stats.sessions);
        animateValue('stat-entities', stats.entities_total);
        animateValue('stat-campaigns', stats.campaigns);
        document.getElementById('stat-time').innerText = formatTime(stats.time_wasted_seconds);

        // 3. Sessions list
        const sessions = await fetchAPI('/api/sessions');
        renderSessionList(sessions);

        // 4. Graph
        const graphData = await fetchAPI('/api/graph');
        updateGraph(graphData);

        // 5. Active Chat
        if (currentSessionId) {
            const sessionData = await fetchAPI(`/api/sessions/${currentSessionId}`);
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

    renderStage(session);
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
        const req = { channel: document.getElementById('new-channel').value, first_message: text, persona: "retired_teacher" };
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
