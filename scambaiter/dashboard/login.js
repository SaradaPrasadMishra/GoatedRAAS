// Sign-in for the Scambaiter console. The session is an HttpOnly, SameSite=Strict cookie set by the backend.
(() => {
    const form = document.getElementById('login-form');
    const err = document.getElementById('login-error');
    const btn = document.getElementById('login-btn');
    const show = (msg) => { err.textContent = msg; err.hidden = false; };

    // already signed in? go straight to the console
    fetch('/api/me', { credentials: 'same-origin' }).then(r => r.json())
        .then(m => { if (m.role === 'admin' || m.role === 'analyst') location.replace('/'); }).catch(() => {});

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = form.username.value.trim(), password = form.password.value;
        if (!username || !password) { show('Enter your username and password.'); return; }
        err.hidden = true;
        btn.disabled = true;
        btn.firstChild.textContent = 'Checking… ';
        try {
            const res = await fetch('/api/login', {
                method: 'POST', credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password }),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) throw new Error(data.detail || 'Sign-in failed');
            location.replace('/');
        } catch (ex) {
            show(ex.message === 'Failed to fetch' ? "Can't reach the backend. Is it running?" : ex.message);
            form.password.value = '';
            form.password.focus();
        } finally {
            btn.disabled = false;
            btn.firstChild.textContent = 'Enter console ';
        }
    });
})();
