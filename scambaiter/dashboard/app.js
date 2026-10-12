const API_BASE = window.API_BASE || (location.protocol === "file:" ? "http://localhost:8000" : "");

// Entity Color Palette
const COLORS = {
    upi_id: "#3ee6a8", phone: "#6aa8ff", url: "#ffb547",
    bank_account: "#ff6b6b", ifsc: "#c08bff", email: "#4cd7f5", crypto_wallet: "#ffd84a"
};
const CAMPAIGN_COLORS = ['#ff5c8a', '#ff5c8a', '#ffb547', '#b48cff', '#3ee6a8', '#ff7ae0', '#33d6ff'];

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

// Format seconds to Xh Ym
const formatTime = (secs) => `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;

// Initialize Graph
function initGraph() {
    cy = cytoscape({
        container: document.getElementById('cy'),
        style: [
            {
                selector: 'node[type="session"]',
                style: { 'shape': 'ellipse', 'background-color': '#ffffff', 'background-opacity': 0.12, 'border-width': 3, 'border-color': 'data(color)', 'label': 'data(label)', 'color': '#f4f6ff', 'font-family': 'Segoe UI, system-ui, sans-serif', 'font-weight': 600, 'font-size': '10px', 'text-valign': 'bottom', 'text-margin-y': 6, 'text-outline-color': '#0a0f3a', 'text-outline-width': 3, 'width': 28, 'height': 28, 'underlay-color': 'data(color)', 'underlay-opacity': 0.3, 'underlay-padding': 6, 'underlay-shape': 'ellipse' }
            },
            {
                selector: 'node[type!="session"]',
                style: { 'shape': 'round-diamond', 'background-color': 'data(color)', 'label': 'data(label)', 'color': 'rgba(230,236,255,0.75)', 'font-family': 'Cascadia Mono, Consolas, monospace', 'font-size': '8px', 'text-valign': 'bottom', 'text-margin-y': 5, 'text-outline-color': '#0a0f3a', 'text-outline-width': 3, 'width': 16, 'height': 16 }
            },
            {
                selector: 'node[?shared]',
                style: { 'width': 30, 'height': 30, 'color': '#fff1d6', 'font-size': '9px', 'underlay-color': '#ffb547', 'underlay-opacity': 0.4, 'underlay-padding': 10, 'underlay-shape': 'ellipse', 'border-width': 2, 'border-color': '#ffffff' }
            },
            {
                selector: 'edge',
                style: { 'width': 1.5, 'line-color': '#ffffff', 'line-style': 'solid', 'target-arrow-shape': 'none', 'curve-style': 'bezier', 'opacity': 0.28 }
            }
        ],
        layout: { name: 'cose' }
    });
}

// Show Toast
function showToast(msg, isError = false) {
    const t = document.createElement('div');
    t.className = isError ? 'toast toast-error' : 'toast';
    t.innerText = msg;
    document.getElementById('toast-container').appendChild(t);
    setTimeout(() => t.remove(), 5000);
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
        
        let cColor = s.campaign_id ? getCampaignColor(s.campaign_id) : 'rgba(255,255,255,0.4)';
        let cBadge = s.campaign_id ? `<span class="chip chip-campaign" style="border-color: ${cColor}; color: ${cColor}">${s.campaign_id}</span>` : '';
        
        div.innerHTML = `
            <div>
                <span class="chip">${escapeHTML(s.scam_type)}</span>
                ${cBadge}
            </div>
            <div class="session-meta">${s.channel} • ${s.message_count} msgs • ${s.entity_count} entities</div>
        `;
        container.appendChild(div);
        if (hadFocus === s.id) div.focus();
    });
}

// Render Center Chat
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
    if (!cid) return '#ffffff'; // unlinked = white
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
            cy.layout({ name: 'cose', animate: true, randomize: false, fit: false }).run();
        } else {
            cy.layout({ name: 'cose' }).run();
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

// Liquid-glass specular highlight follows the pointer
document.addEventListener('pointermove', (e) => {
    const el = e.target.closest && e.target.closest('.glass');
    if (!el) return;
    const r = el.getBoundingClientRect();
    el.style.setProperty('--mx', `${e.clientX - r.left}px`);
    el.style.setProperty('--my', `${e.clientY - r.top}px`);
});
