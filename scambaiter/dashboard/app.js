const API_BASE = window.API_BASE || (location.protocol === "file:" ? "http://localhost:8000" : "");

// Entity Color Palette
const COLORS = {
    upi_id: "#22c55e", phone: "#3b82f6", url: "#f59e0b",
    bank_account: "#ef4444", ifsc: "#a855f7", email: "#06b6d4", crypto_wallet: "#eab308"
};
const CAMPAIGN_COLORS = ['#ff2e63', '#ff2e63', '#ffb627', '#a855f7', '#22c55e', '#ec4899', '#3b82f6'];

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

// Format seconds to Xh Ym
const formatTime = (secs) => `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;

// Initialize Graph
function initGraph() {
    cy = cytoscape({
        container: document.getElementById('cy'),
        style: [
            {
                selector: 'node[type="session"]',
                style: { 'shape': 'ellipse', 'background-color': '#03060d', 'border-width': 3, 'border-color': 'data(color)', 'label': 'data(label)', 'color': '#d7f6ff', 'font-family': 'Cascadia Mono, Consolas, monospace', 'font-size': '9px', 'text-valign': 'bottom', 'text-margin-y': 6, 'text-outline-color': '#03060d', 'text-outline-width': 3, 'width': 26, 'height': 26, 'underlay-color': 'data(color)', 'underlay-opacity': 0.25, 'underlay-padding': 5, 'underlay-shape': 'ellipse' }
            },
            {
                selector: 'node[type!="session"]',
                style: { 'shape': 'diamond', 'background-color': 'data(color)', 'label': 'data(label)', 'color': '#6f8fa8', 'font-family': 'Cascadia Mono, Consolas, monospace', 'font-size': '8px', 'text-valign': 'bottom', 'text-margin-y': 5, 'text-outline-color': '#03060d', 'text-outline-width': 3, 'width': 16, 'height': 16 }
            },
            {
                selector: 'node[?shared]',
                style: { 'width': 30, 'height': 30, 'color': '#ffe2a8', 'font-size': '9px', 'underlay-color': '#ffb627', 'underlay-opacity': 0.35, 'underlay-padding': 9, 'underlay-shape': 'ellipse', 'border-width': 2, 'border-color': '#ffb627' }
            },
            {
                selector: 'edge',
                style: { 'width': 1.5, 'line-color': '#2de2e6', 'line-style': 'dashed', 'line-dash-pattern': [4, 3], 'target-arrow-shape': 'none', 'curve-style': 'bezier', 'opacity': 0.45 }
            }
        ],
        layout: { name: 'cose' }
    });
}

// Show Toast
function showToast(msg) {
    const t = document.createElement('div');
    t.className = 'toast';
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
    if (c) c.innerText = new Date().toLocaleTimeString('en-GB');
}, 1000);

// Render Left Column
function renderSessionList(sessions) {
    const container = document.getElementById('session-list');
    container.innerHTML = '';
    sessions.forEach(s => {
        const div = document.createElement('div');
        div.className = `session-item ${s.id === currentSessionId ? 'selected' : ''}`;
        div.onclick = () => selectSession(s.id);
        
        let cColor = s.campaign_id ? getCampaignColor(s.campaign_id) : '#374151';
        let cBadge = s.campaign_id ? `<span class="chip chip-campaign" style="border-color: ${cColor}; color: ${cColor}">${s.campaign_id}</span>` : '';
        
        div.innerHTML = `
            <div>
                <span class="chip" style="background: #374151">${s.scam_type}</span>
                ${cBadge}
            </div>
            <div class="session-meta">${s.channel} • ${s.message_count} msgs • ${s.entity_count} entities</div>
        `;
        container.appendChild(div);
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
            const span = `<span style="color: ${color}; font-weight: bold; background: rgba(0,0,0,0.2); padding: 0 4px; border-radius: 4px;">${eRaw}</span>`;
            htmlText = htmlText.split(eRaw).join(span);
        });

        msgDiv.innerHTML = `<div>${htmlText}</div><div class="msg-ts">${new Date(m.ts).toLocaleTimeString()}</div>`;
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
    if (!cid) return '#2de2e6'; // unlinked = cyan
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
document.getElementById('btn-create-session').onclick = async () => {
    const text = document.getElementById('new-message').value.trim();
    if (!text) return;
    const req = { channel: document.getElementById('new-channel').value, first_message: text, persona: "retired_teacher" };
    const session = await fetchAPI('/api/sessions', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(req) });
    document.getElementById('new-message').value = '';
    selectSession(session.id);
};

document.getElementById('btn-send-msg').onclick = async () => {
    const text = document.getElementById('manual-msg').value.trim();
    if (!text || !currentSessionId) return;
    await fetchAPI(`/api/sessions/${currentSessionId}/messages`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({text}) });
    document.getElementById('manual-msg').value = '';
    pollData();
};
document.getElementById('manual-msg').addEventListener('keypress', (e) => { if (e.key === 'Enter') document.getElementById('btn-send-msg').click(); });

document.getElementById('btn-close').onclick = async () => {
    if (!currentSessionId) return;
    await fetchAPI(`/api/sessions/${currentSessionId}/close`, { method: 'POST' });
    pollData();
};

setInterval(pollData, 2000);
pollData();