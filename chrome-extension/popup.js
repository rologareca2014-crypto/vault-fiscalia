/* ==========================================
   JS LOGIC - CHROME EXTENSION POPUP.JS
   ========================================== */

const API_BASE = "http://127.0.0.1:5000";

let token = null;
let email = null;
let temp2FAToken = null; // Temp token for 2FA verification
let allCredentials = []; // Cache list for pull search

document.addEventListener('DOMContentLoaded', () => {
    setupFormEvents();
    loadSession();
});

// Load session from chrome local storage
function loadSession() {
    chrome.storage.local.get(['vault_token', 'vault_email', 'last_activity_time', 'idle_timeout_minutes'], (result) => {
        if (result.vault_token) {
            token = result.vault_token;
            email = result.vault_email;
            
            // Check Inactivity timeout
            const lastActivity = result.last_activity_time || Date.now();
            const timeoutMinutes = result.idle_timeout_minutes || 15;
            const elapsedMs = Date.now() - lastActivity;
            
            if (elapsedMs > (timeoutMinutes * 60 * 1000)) {
                logoutDueToInactivity();
                return;
            }
            
            // Update last activity time
            chrome.storage.local.set({ last_activity_time: Date.now() });
            
            showSaveView();
            syncIdleTimeout();
        } else {
            showView('login-view');
        }
    });
}

function showView(viewId) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.getElementById(viewId).classList.add('active');
}

function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = `toast ${type}`;
    toast.classList.remove('hidden');
    
    setTimeout(() => {
        toast.classList.add('hidden');
    }, 3500);
}

function setupFormEvents() {
    // 1. Submit Login Form
    document.getElementById('login-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const emailInput = document.getElementById('login-email').value.trim();
        const passwordInput = document.getElementById('login-password').value;
        
        if (!emailInput.endsWith('@fiscalia.gob.bo')) {
            showToast('Debe usar un correo institucional @fiscalia.gob.bo', 'danger');
            return;
        }
        
        try {
            const response = await fetch(`${API_BASE}/api/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: emailInput, password: passwordInput })
            });
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Error al iniciar sesión.');
            }
            
            if (data.totp_setup_required) {
                temp2FAToken = data.token;
                showView('totp-setup-view');
                loadExtension2FASetup();
                showToast(data.message, 'warning');
            } else if (data.totp_required) {
                temp2FAToken = data.token;
                showView('totp-view');
                document.getElementById('totp-code').value = '';
                document.getElementById('totp-code').focus();
            } else {
                saveSession(data.token, emailInput);
            }
        } catch (error) {
            showToast(error.message, 'danger');
        }
    });

    // 2. Submit 2FA Form
    document.getElementById('totp-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const code = document.getElementById('totp-code').value.trim();
        
        try {
            const response = await fetch(`${API_BASE}/api/auth/login/2fa`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${temp2FAToken}`
                },
                body: JSON.stringify({ code })
            });
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Código incorrecto.');
            }
            
            temp2FAToken = null;
            saveSession(data.token, data.user.email);
        } catch (error) {
            showToast(error.message, 'danger');
            document.getElementById('totp-code').value = '';
        }
    });

    document.getElementById('totp-cancel').addEventListener('click', () => {
        temp2FAToken = null;
        showView('login-view');
    });

    // 2.1 Submit 2FA Setup Form
    document.getElementById('totp-setup-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const code = document.getElementById('setup-code').value.trim();
        
        try {
            const response = await fetch(`${API_BASE}/api/auth/login/2fa-enable`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${temp2FAToken}`
                },
                body: JSON.stringify({ code })
            });
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Código incorrecto.');
            }
            
            temp2FAToken = null;
            saveSession(data.token, data.user.email);
        } catch (error) {
            showToast(error.message, 'danger');
            document.getElementById('setup-code').value = '';
        }
    });

    document.getElementById('totp-setup-cancel').addEventListener('click', () => {
        temp2FAToken = null;
        showView('login-view');
    });

    // 3. Save Credential Form
    document.getElementById('save-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const name = document.getElementById('save-name').value.trim();
        const username = document.getElementById('save-username').value.trim();
        const password = document.getElementById('save-password').value;
        const url = document.getElementById('save-url').value.trim();
        
        try {
            const response = await fetch(`${API_BASE}/api/vault`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ name, username, password, url, notes: 'Guardado desde la extensión de Chrome.' })
            });
            const data = await response.json();
            
            if (!response.ok) {
                if (response.status === 401) {
                    // Session expired or single session kicked out
                    logout();
                    throw new Error('Sesión expirada o cerrada en otro dispositivo.');
                }
                throw new Error(data.message || 'Error al guardar.');
            }
            
            showToast('Credencial guardada en la Bóveda.', 'success');
            chrome.storage.local.set({ last_activity_time: Date.now() });
            
            // Clear inputs
            document.getElementById('save-username').value = '';
            document.getElementById('save-password').value = '';
        } catch (error) {
            showToast(error.message, 'danger');
        }
    });

    // Generate password click
    document.getElementById('gen-password-btn').addEventListener('click', () => {
        const field = document.getElementById('save-password');
        const length = 16;
        const chars = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*_-+=";
        let password = "";
        const randomArray = new Uint32Array(length);
        window.crypto.getRandomValues(randomArray);
        
        for (let i = 0; i < length; i++) {
            password += chars[randomArray[i] % chars.length];
        }
        
        field.value = password;
        field.type = 'text'; // Make it visible
        showToast('Clave segura generada.', 'success');
    });

    // Logout button click
    document.getElementById('logout-btn').addEventListener('click', () => {
        logout();
    });

    // Tabs Switcher bindings
    document.getElementById('ext-tab-save').addEventListener('click', () => {
        document.getElementById('ext-tab-save').classList.add('active');
        document.getElementById('ext-tab-pull').classList.remove('active');
        document.getElementById('ext-tab-save-content').style.display = 'block';
        document.getElementById('ext-tab-pull-content').style.display = 'none';
    });
    
    document.getElementById('ext-tab-pull').addEventListener('click', () => {
        document.getElementById('ext-tab-save').classList.remove('active');
        document.getElementById('ext-tab-pull').classList.add('active');
        document.getElementById('ext-tab-save-content').style.display = 'none';
        document.getElementById('ext-tab-pull-content').style.display = 'block';
        loadVaultItems();
    });

    document.getElementById('logout-btn-pull').addEventListener('click', () => {
        logout();
    });
}

function saveSession(jwtToken, userEmail) {
    token = jwtToken;
    email = userEmail;
    chrome.storage.local.set({ 
        vault_token: jwtToken, 
        vault_email: userEmail,
        last_activity_time: Date.now(),
        idle_timeout_minutes: 15
    }, () => {
        showSaveView();
        showToast('Sesión iniciada.', 'success');
        syncIdleTimeout();
    });
}

function logout() {
    token = null;
    email = null;
    chrome.storage.local.remove(['vault_token', 'vault_email', 'last_activity_time', 'idle_timeout_minutes'], () => {
        showView('login-view');
        document.getElementById('login-form').reset();
        showToast('Sesión cerrada.', 'info');
    });
}

function logoutDueToInactivity() {
    token = null;
    email = null;
    chrome.storage.local.remove(['vault_token', 'vault_email', 'last_activity_time', 'idle_timeout_minutes'], () => {
        showView('login-view');
        document.getElementById('login-form').reset();
        showToast('Sesión cerrada por inactividad.', 'warning');
    });
}

async function syncIdleTimeout() {
    if (!token) return;
    try {
        const response = await fetch(`${API_BASE}/api/settings/timeout`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        if (response.ok) {
            const data = await response.json();
            chrome.storage.local.set({ idle_timeout_minutes: parseInt(data.idle_timeout_minutes) || 15 });
        }
    } catch (e) {
        console.error("Error al sincronizar timeout:", e);
    }
}

// Prepare and show the Save Credential view
async function showSaveView() {
    document.getElementById('user-email-display').textContent = email;
    showView('save-view');
    
    // Auto-detect current active tab URL and title
    try {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs && tabs[0]) {
                const tab = tabs[0];
                const url = new URL(tab.url);
                
                // Prefill fields
                document.getElementById('save-url').value = tab.url;
                
                // Get a friendly title (e.g. Gmail instead of Google Login)
                let name = tab.title || url.hostname;
                if (name.length > 25) {
                    name = url.hostname;
                }
                document.getElementById('save-name').value = name;
                
                // Clear username/password fields
                document.getElementById('save-username').value = '';
                document.getElementById('save-password').value = '';
                document.getElementById('save-password').type = 'password';
            }
        });
    } catch (e) {
        console.error("Tab reading permissions error:", e);
    }
}

async function loadExtension2FASetup() {
    try {
        const response = await fetch(`${API_BASE}/api/auth/login/2fa-setup`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${temp2FAToken}`
            }
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message);
        
        document.getElementById('setup-qr-img').src = data.qr_code;
        document.getElementById('setup-secret-txt').textContent = data.secret;
        document.getElementById('setup-code').value = '';
        document.getElementById('setup-code').focus();
    } catch (e) {
        showToast(e.message, 'danger');
    }
}

// --- EXTENSION PULL CREDENTIALS LOGIC ---
async function loadVaultItems() {
    const resultsContainer = document.getElementById('ext-search-results');
    resultsContainer.innerHTML = '<div style="text-align:center; font-size:11px; padding:10px; color:var(--text-muted);"><i class="fa-solid fa-spinner fa-spin"></i> Cargando...</div>';
    
    try {
        const response = await fetch(`${API_BASE}/api/vault`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (!response.ok) {
            throw new Error('Error al cargar credenciales de la bóveda.');
        }
        
        const data = await response.json();
        allCredentials = data;
        renderCredentials(allCredentials);
    } catch (error) {
        resultsContainer.innerHTML = `<div style="color:var(--color-danger); text-align:center; font-size:11px; padding:10px;">${error.message}</div>`;
    }
}

function renderCredentials(list) {
    const resultsContainer = document.getElementById('ext-search-results');
    resultsContainer.innerHTML = '';
    
    if (list.length === 0) {
        resultsContainer.innerHTML = '<div style="text-align:center; font-size:11px; padding:10px; color:var(--text-muted);">No se encontraron credenciales.</div>';
        return;
    }
    
    list.forEach(item => {
        const row = document.createElement('div');
        row.className = 'ext-cred-row';
        row.innerHTML = `
            <div class="ext-cred-info">
                <div class="ext-cred-title" title="${escapeHtml(item.name)}">${escapeHtml(item.name)}</div>
                <div class="ext-cred-user" title="${escapeHtml(item.username)}">${escapeHtml(item.username)}</div>
            </div>
            <div class="ext-cred-actions">
                <button type="button" class="btn-ext-action" title="Copiar Usuario" onclick="copyValue('${escapeJs(item.username)}', 'Usuario')">
                    <i class="fa-regular fa-user"></i>
                </button>
                <button type="button" class="btn-ext-action" title="Copiar Contraseña" onclick="copyValue('${escapeJs(item.password)}', 'Contraseña')">
                    <i class="fa-solid fa-key"></i>
                </button>
            </div>
        `;
        resultsContainer.appendChild(row);
    });
}

// Bind search input typing
document.getElementById('ext-search-input').addEventListener('input', (e) => {
    const q = e.target.value.toLowerCase().trim();
    if (!q) {
        renderCredentials(allCredentials);
        return;
    }
    const filtered = allCredentials.filter(item => 
        item.name.toLowerCase().includes(q) || 
        item.username.toLowerCase().includes(q)
    );
    renderCredentials(filtered);
});

function copyValue(value, label) {
    navigator.clipboard.writeText(value).then(() => {
        showToast(`${label} copiado al portapapeles.`, 'success');
    }).catch(() => {
        showToast('Error al copiar.', 'danger');
    });
}

function escapeHtml(unsafe) {
    if (!unsafe) return '';
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

function escapeJs(unsafe) {
    if (!unsafe) return '';
    return unsafe
         .replace(/\\/g, '\\\\')
         .replace(/'/g, "\\'")
         .replace(/"/g, '\\"')
         .replace(/\n/g, '\\n')
         .replace(/\r/g, '\\r');
}
