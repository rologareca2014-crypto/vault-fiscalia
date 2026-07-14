/* ==========================================
   FRONTEND LOGIC - APP.JS (VaultFiscalia)
   FISCALÍA DEPARTAMENTAL DE SANTA CRUZ
   ========================================== */

// --- STATE MANAGEMENT ---
let token = localStorage.getItem('vault_token') || null;
let currentUser = null;
let vaultItems = [];
let temp2FAToken = null; // For 2FA login steps
let idleTimeoutMinutes = 15; // Global idle timeout in minutes (from server)
let lastActivityTime = Date.now();
let isSuspended = false;

// --- ON LOAD INITIALIZATION ---
document.addEventListener('DOMContentLoaded', () => {
    initializeTheme();
    setupNavigationEvents();
    setupFormSubmissions();
    checkInviteToken();
    checkExistingSession();
    setupActivityMonitor();
});

// --- NAVIGATION & UI STATE ---

function checkExistingSession() {
    if (token) {
        fetchUserInfo();
    } else {
        showScreen('auth-screen');
        showAuthForm('login-form');
    }
}

// Check for registration invite token in URL
async function checkInviteToken() {
    const urlParams = new URLSearchParams(window.location.search);
    const inviteToken = urlParams.get('invite');
    const resetToken = urlParams.get('reset');
    
    if (inviteToken) {
        try {
            const data = await apiRequest(`/api/auth/invite/verify?token=${inviteToken}`);
            if (data.valid) {
                showScreen('auth-screen');
                showAuthForm('register-form');
                
                const emailInput = document.getElementById('register-email');
                emailInput.value = data.email;
                const emailText = document.getElementById('register-email-display-text');
                if (emailText) emailText.textContent = data.email;
                
                document.getElementById('register-invite-token').value = inviteToken;
                
                passwordModes.reg.generated = '';
                selectPasswordMode('reg', 'custom');
                
                const fullName = `${data.nombres} ${data.apellido_paterno || ''} ${data.apellido_materno || ''}`.replace(/\s+/g, ' ').trim();
                document.getElementById('register-flow-desc').innerHTML = `
                    <div style="margin-bottom: 0.5rem;"><span class="badge badge-primary"><i class="fa-solid fa-envelope-open-text"></i> Invitación Activa</span></div>
                    <p style="font-size: 0.9rem; color: var(--text-secondary); line-height: 1.4;">
                        Bienvenido/a, <strong>${escapeHtml(fullName)}</strong> (CI: ${escapeHtml(data.ci)}). Establezca su contraseña maestra para unirse al sistema.
                    </p>
                `;
                showToast('Invitación válida detectada.', 'success');
            } else {
                showToast(data.message || 'El enlace de invitación es inválido o ya expiró.', 'danger');
                window.history.replaceState({}, document.title, window.location.pathname);
            }
        } catch (error) {
            showToast('Error al verificar la invitación.', 'danger');
        }
    } else if (resetToken) {
        try {
            const data = await apiRequest(`/api/auth/reset/verify?token=${resetToken}`);
            showScreen('auth-screen');
            showAuthForm('reset-password-form');
            
            document.getElementById('reset-email').value = data.email;
            const resetEmailText = document.getElementById('reset-email-display-text');
            if (resetEmailText) resetEmailText.textContent = data.email;
            document.getElementById('reset-token-holder').value = resetToken;
            
            passwordModes.reset.generated = '';
            selectPasswordMode('reset', 'custom');
            
            showToast('Token de restablecimiento verificado con éxito.', 'success');
        } catch (error) {
            showToast(error.message || 'Token de restablecimiento inválido o expirado.', 'danger');
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    }
}

function showScreen(screenId) {
    document.querySelectorAll('.app-container > section').forEach(section => {
        section.classList.add('hidden');
    });
    const target = document.getElementById(screenId);
    if (target) target.classList.remove('hidden');
}

function showAuthForm(formId) {
    document.querySelectorAll('.auth-form').forEach(form => {
        form.classList.remove('active');
    });
    const target = document.getElementById(formId);
    if (target) target.classList.add('active');
}

function setupNavigationEvents() {
    // Auth Switch Buttons
    document.getElementById('to-register-btn').addEventListener('click', (e) => {
        e.preventDefault();
        // Warn if no invitation token is set
        const tokenVal = document.getElementById('register-invite-token').value;
        if (!tokenVal) {
            showToast('El registro está restringido. Requiere un enlace de invitación oficial del Administrador.', 'warning');
        }
        showAuthForm('register-form');
    });
    document.getElementById('to-login-btn').addEventListener('click', (e) => {
        e.preventDefault();
        showAuthForm('login-form');
    });
    document.getElementById('totp-cancel-btn').addEventListener('click', () => {
        temp2FAToken = null;
        showAuthForm('login-form');
    });

    // Dashboard Sidebar Navigation
    document.querySelectorAll('.menu-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            document.querySelectorAll('.menu-item').forEach(mi => mi.classList.remove('active'));
            item.classList.add('active');
            
            const targetSection = item.getAttribute('data-target');
            document.querySelectorAll('.content-section').forEach(section => {
                section.classList.remove('active');
            });
            document.getElementById(targetSection).classList.add('active');
            
            // Section-specific loads
            if (targetSection === 'vault-section') {
                loadVault();
            } else if (targetSection === 'favorites-section') {
                loadFavorites();
            } else if (targetSection === 'admin-users-section') {
                selectAdminTab('users');
            } else if (targetSection === 'admin-logs-section') {
                loadAdminLogs();
            } else if (targetSection === 'settings-section') {
                update2FAUI();
                passwordModes.settings.generated = '';
                selectPasswordMode('settings', 'custom');
                if (currentUser && currentUser.is_admin === 1) {
                    loadIdleTimeout();
                    loadSMTPSettings();
                }
            }
        });
    });

    // Search Box Filtering
    document.getElementById('vault-search-input').addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase().trim();
        filterCredentials(query);
    });

    // Theme Toggle Click Listener
    const themeBtn = document.getElementById('theme-toggle-btn');
    if (themeBtn) {
        themeBtn.addEventListener('click', toggleTheme);
    }
}

// Helper to show/hide passwords
function togglePasswordVisibility(fieldId) {
    const input = document.getElementById(fieldId);
    const icon = input.nextElementSibling.querySelector('i');
    if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
    } else {
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    }
}


// --- TOAST NOTIFICATIONS HELPER ---
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;
    
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    let iconClass = 'fa-circle-info';
    if (type === 'success') iconClass = 'fa-circle-check';
    if (type === 'danger') iconClass = 'fa-circle-exclamation';
    if (type === 'warning') iconClass = 'fa-triangle-exclamation';
    
    toast.innerHTML = `
        <i class="fa-solid ${iconClass} toast-icon"></i>
        <div class="toast-message">${message}</div>
        <button type="button" class="toast-close">&times;</button>
    `;
    
    container.appendChild(toast);
    
    const timer = setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
    }, 4500);
    
    toast.querySelector('.toast-close').addEventListener('click', () => {
        clearTimeout(timer);
        toast.remove();
    });
}


// --- API CLIENT CALLS ---

async function apiRequest(path, method = 'GET', body = null, useTempToken = false) {
    const headers = { 'Content-Type': 'application/json' };
    
    const tokenToUse = useTempToken ? temp2FAToken : token;
    if (tokenToUse) {
        headers['Authorization'] = `Bearer ${tokenToUse}`;
    }
    
    const config = { method, headers };
    if (body) {
        config.body = JSON.stringify(body);
    }
    
    try {
        const response = await fetch(path, config);
        const data = await response.json();
        
        if (!response.ok) {
            // Check for session termination or token expiry (401)
            if (response.status === 401) {
                showToast(data.message || 'Su sesión de Vault expiró o fue cerrada en otro dispositivo.', 'danger');
                logoutSilently();
                throw new Error('session_expired');
            }
            throw new Error(data.message || 'Error en la petición del sistema.');
        }
        return data;
    } catch (error) {
        if (error.message === 'session_terminated' || error.message === 'session_expired') {
            throw error;
        }
        console.error("API error:", error.message);
        throw error;
    }
}

// Fetch Logged in User Profile
async function fetchUserInfo() {
    try {
        const data = await apiRequest('/api/auth/user-info');
        currentUser = data;
        
        // Show display info
        document.getElementById('user-email-display').textContent = currentUser.email;
        document.getElementById('user-role-display').textContent = currentUser.is_superuser ? 'Superusuario' : (currentUser.is_admin ? 'Administrador' : 'Funcionario');
        
        // Load inactivity timeout
        loadIdleTimeout();

        // Admin visibility toggles
        document.querySelectorAll('.admin-only').forEach(el => {
            if (currentUser.is_admin) {
                el.classList.remove('hidden');
            } else {
                el.classList.add('hidden');
            }
        });
        
        // Force master password change check
        if (currentUser.force_password_change === 1) {
            passwordModes.force.generated = '';
            selectPasswordMode('force', 'custom');
            showScreen('force-change-screen');
        } else {
            showScreen('dashboard-screen');
            loadVault();
        }
    } catch (error) {
        if (error.message !== 'session_terminated') {
            showToast('Debe iniciar sesión para ingresar a la bóveda.', 'warning');
            logoutSilently();
        }
    }
}


// --- AUTHENTICATION FLOWS ---

function setupFormSubmissions() {
    // 1. Login Form Submit
    document.getElementById('login-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('login-email').value.trim();
        const password = document.getElementById('login-password').value;
        
        // Strict domain validation on client side
        if (!email.endsWith('@fiscalia.gob.bo')) {
            showToast('El usuario debe ser una cuenta del Ministerio Público (@fiscalia.gob.bo).', 'danger');
            return;
        }
        
        try {
            const data = await apiRequest('/api/auth/login', 'POST', { email, password });
            
            if (data.totp_setup_required) {
                temp2FAToken = data.token;
                showAuthForm('totp-setup-form');
                startForced2FASetup();
                showToast(data.message, 'warning');
            } else if (data.totp_required) {
                temp2FAToken = data.token;
                showAuthForm('totp-form');
                document.getElementById('totp-code').focus();
                showToast(data.message, 'warning');
            } else {
                token = data.token;
                localStorage.setItem('vault_token', token);
                showToast('Acceso autorizado.', 'success');
                fetchUserInfo();
            }
        } catch (error) {
            showToast(error.message, 'danger');
        }
    });

    // 2. 2FA Form Submit
    document.getElementById('totp-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const code = document.getElementById('totp-code').value.trim();
        
        try {
            const data = await apiRequest('/api/auth/login/2fa', 'POST', { code }, true);
            token = data.token;
            temp2FAToken = null;
            localStorage.setItem('vault_token', token);
            showToast('Verificación de doble factor exitosa.', 'success');
            fetchUserInfo();
        } catch (error) {
            showToast(error.message, 'danger');
            document.getElementById('totp-code').value = '';
        }
    });

    // 2.1 Forced 2FA Setup Form Submit
    document.getElementById('totp-setup-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const code = document.getElementById('login-totp-setup-code').value.trim();
        
        try {
            const data = await apiRequest('/api/auth/login/2fa-enable', 'POST', { code }, true);
            token = data.token;
            temp2FAToken = null;
            localStorage.setItem('vault_token', token);
            showToast('Activación de doble factor exitosa.', 'success');
            
            // Clean up
            document.getElementById('login-totp-setup-code').value = '';
            
            fetchUserInfo();
        } catch (error) {
            showToast(error.message, 'danger');
            document.getElementById('login-totp-setup-code').value = '';
        }
    });

    document.getElementById('totp-setup-cancel-btn').addEventListener('click', () => {
        temp2FAToken = null;
        showAuthForm('login-form');
    });

    // 3. Register Form Submit
    document.getElementById('register-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('register-email').value.trim();
        const password = document.getElementById('register-password').value;
        const confirmPassword = document.getElementById('register-confirm-password').value;
        const invite_token = document.getElementById('register-invite-token').value;
        const password_hint = document.getElementById('register-hint').value.trim();
        
        if (!email.endsWith('@fiscalia.gob.bo')) {
            showToast('El correo debe pertenecer al dominio @fiscalia.gob.bo.', 'danger');
            return;
        }
        if (password.length < 8) {
            showToast('La contraseña maestra debe tener al menos 8 caracteres.', 'danger');
            return;
        }
        if (password !== confirmPassword) {
            showToast('Las contraseñas maestras no coinciden.', 'danger');
            return;
        }
        
        try {
            const data = await apiRequest('/api/auth/register', 'POST', { email, password, invite_token, password_hint });
            showToast(data.message, 'success');
            
            // Clean up invite parameters and return to login
            document.getElementById('register-invite-token').value = '';
            document.getElementById('register-email').value = '';
            const emailText = document.getElementById('register-email-display-text');
            if (emailText) emailText.textContent = '...';
            document.getElementById('register-password').value = '';
            document.getElementById('register-confirm-password').value = '';
            document.getElementById('register-hint').value = '';
            document.getElementById('register-flow-desc').textContent = '';
            
            window.history.replaceState({}, document.title, window.location.pathname);
            
            showAuthForm('login-form');
            document.getElementById('login-email').value = email;
        } catch (error) {
            showToast(error.message, 'danger');
        }
    });

    // 4. Force Change Password Submit
    document.getElementById('force-change-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const newPassword = document.getElementById('force-new-password').value;
        const confirmPassword = document.getElementById('force-confirm-password').value;
        
        if (newPassword !== confirmPassword) {
            showToast('Las contraseñas no coinciden.', 'danger');
            return;
        }
        
        try {
            const data = await apiRequest('/api/auth/change-password', 'POST', { new_password: newPassword });
            showToast(data.message, 'success');
            logoutSilently();
            showToast('Contraseña maestra configurada. Inicie sesión de nuevo.', 'success');
        } catch (error) {
            showToast(error.message, 'danger');
        }
    });

    // 5. Change Password Form (Settings Section)
    document.getElementById('change-password-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const oldPassword = document.getElementById('settings-old-password').value;
        const newPassword = document.getElementById('settings-new-password').value;
        const confirmPassword = document.getElementById('settings-confirm-password').value;
        
        if (newPassword !== confirmPassword) {
            showToast('Las contraseñas nuevas no coinciden.', 'danger');
            return;
        }
        
        try {
            const data = await apiRequest('/api/auth/change-password', 'POST', { 
                old_password: oldPassword, 
                new_password: newPassword 
            });
            showToast(data.message, 'success');
            logoutSilently();
            showToast('Contraseña cambiada. Por favor, re-ingrese sus credenciales.', 'info');
        } catch (error) {
            showToast(error.message, 'danger');
        }
    });

    // 5b. Reset Password Form (via Admin Token) Submit
    document.getElementById('reset-password-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const token = document.getElementById('reset-token-holder').value;
        const password = document.getElementById('reset-password').value;
        
        try {
            const data = await apiRequest('/api/auth/reset/confirm', 'POST', { token, password });
            showToast(data.message, 'success');
            document.getElementById('reset-password-form').reset();
            window.history.replaceState({}, document.title, window.location.pathname);
            showAuthForm('login-form');
        } catch (error) {
            showToast(error.message, 'danger');
        }
    });

    // 6. Credential Add/Edit Form Submit
    document.getElementById('credential-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const id = document.getElementById('cred-id').value;
        const name = document.getElementById('cred-name').value;
        const username = document.getElementById('cred-username').value;
        const password = document.getElementById('cred-password').value;
        const url = document.getElementById('cred-url').value;
        const notes = document.getElementById('cred-notes').value;
        const is_favorite = document.getElementById('cred-favorite').checked;
        
        const payload = { name, username, password, url, notes, is_favorite };
        
        try {
            let data;
            if (id) {
                data = await apiRequest(`/api/vault/${id}`, 'PUT', payload);
                showToast(data.message, 'success');
            } else {
                data = await apiRequest('/api/vault', 'POST', payload);
                showToast(data.message, 'success');
            }
            closeCredentialModal();
            loadVault();
        } catch (error) {
            showToast(error.message, 'danger');
        }
    });

    // 7. Admin Edit User Email Submit
    document.getElementById('admin-email-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const userId = document.getElementById('admin-email-userid').value;
        const email = document.getElementById('admin-new-email').value.trim();
        
        if (!email.endsWith('@fiscalia.gob.bo')) {
            showToast('El correo debe pertenecer al dominio @fiscalia.gob.bo.', 'danger');
            return;
        }
        
        try {
            const data = await apiRequest(`/api/admin/users/${userId}/email`, 'PUT', { email });
            showToast(data.message, 'success');
            closeAdminEmailModal();
            loadAdminUsers();
        } catch (error) {
            showToast(error.message, 'danger');
        }
    });

    // 8. Admin Invite Form Submit
    document.getElementById('admin-invite-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const nombres = document.getElementById('admin-invite-nombres').value.trim();
        const apellido_paterno = document.getElementById('admin-invite-paterno').value.trim();
        const apellido_materno = document.getElementById('admin-invite-materno').value.trim();
        const ci = document.getElementById('admin-invite-ci').value.trim();
        const email = document.getElementById('admin-invite-email').value.trim();
        
        if (!email.endsWith('@fiscalia.gob.bo')) {
            showToast('El correo debe pertenecer a @fiscalia.gob.bo.', 'danger');
            return;
        }
        
        try {
            const data = await apiRequest('/api/admin/invite', 'POST', { 
                nombres,
                apellido_paterno,
                apellido_materno,
                ci,
                email 
            });
            
            if (data.email_sent) {
                showToast(data.message, 'success');
            } else {
                showToast(`${data.message} (Nota: Enlace generado. Correo no enviado: ${data.email_status})`, 'warning');
            }
            
            document.getElementById('admin-invite-form').reset();
            loadAdminInvitations();
        } catch (error) {
            showToast(error.message, 'danger');
        }
    });

    // 10. Global Inactivity Timeout Form Submit
    document.getElementById('global-timeout-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const minutes = parseInt(document.getElementById('global-idle-timeout-select').value);
        try {
            const data = await apiRequest('/api/admin/settings/timeout', 'PUT', { idle_timeout_minutes: minutes });
            idleTimeoutMinutes = minutes;
            showToast(data.message, 'success');
        } catch (error) {
            showToast(error.message, 'danger');
        }
    });

    // 11. Global SMTP Settings Form Submit
    document.getElementById('global-smtp-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const smtp_host = document.getElementById('smtp-host-input').value.trim();
        const smtp_port = document.getElementById('smtp-port-input').value.trim();
        const smtp_user = document.getElementById('smtp-user-input').value.trim();
        const smtp_pass = document.getElementById('smtp-pass-input').value;
        const smtp_from = document.getElementById('smtp-from-input').value.trim();
        
        try {
            const data = await apiRequest('/api/admin/settings/smtp', 'PUT', { smtp_host, smtp_port, smtp_user, smtp_pass, smtp_from });
            showToast(data.message, 'success');
            document.getElementById('smtp-pass-input').value = '';
        } catch (error) {
            showToast(error.message, 'danger');
        }
    });

    // 12. Request Password Hint Link & Form Submit
    const requestHintLink = document.getElementById('request-hint-link');
    if (requestHintLink) {
        requestHintLink.addEventListener('click', (e) => {
            e.preventDefault();
            openRequestHintModal();
        });
    }

    document.getElementById('request-hint-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('hint-email').value.trim();
        
        try {
            const data = await apiRequest('/api/auth/password-hint', 'POST', { email }, true);
            showToast(data.message, 'success');
            closeRequestHintModal();
        } catch (error) {
            showToast(error.message, 'danger');
        }
    });
}

function logout() {
    logoutSilently();
    showToast('Sesión cerrada.', 'info');
}
window.logout = logout;

function logoutSilently() {
    token = null;
    currentUser = null;
    vaultItems = [];
    localStorage.removeItem('vault_token');
    
    // Hide suspension overlay if visible
    const overlay = document.getElementById('suspension-overlay');
    if (overlay) {
        overlay.classList.add('hidden');
    }
    isSuspended = false;
    
    showScreen('auth-screen');
    showAuthForm('login-form');
    // Reset forms
    document.getElementById('login-form').reset();
    document.getElementById('register-form').reset();
    document.getElementById('totp-form').reset();
}


// --- VAULT CREDENTIALS RENDER & CRUD ---

async function loadVault() {
    const grid = document.getElementById('credentials-grid');
    grid.innerHTML = '<div class="empty-state"><i class="fa-solid fa-spinner fa-spin empty-state-icon"></i><p>Cargando contraseñas...</p></div>';
    
    try {
        vaultItems = await apiRequest('/api/vault');
        renderCredentials(vaultItems, 'credentials-grid');
    } catch (error) {
        if (error.message !== 'session_terminated') {
            showToast(error.message, 'danger');
        }
    }
}

async function loadFavorites() {
    const grid = document.getElementById('favorites-grid');
    grid.innerHTML = '<div class="empty-state"><i class="fa-solid fa-spinner fa-spin empty-state-icon"></i><p>Cargando favoritos...</p></div>';
    
    try {
        const items = await apiRequest('/api/vault');
        const favorites = items.filter(i => i.is_favorite === 1);
        renderCredentials(favorites, 'favorites-grid');
    } catch (error) {
        if (error.message !== 'session_terminated') {
            showToast(error.message, 'danger');
        }
    }
}

function renderCredentials(items, gridId) {
    const grid = document.getElementById(gridId);
    grid.innerHTML = '';
    
    if (items.length === 0) {
        grid.innerHTML = `
            <div class="empty-state">
                <i class="fa-solid fa-folder-open empty-state-icon"></i>
                <h3>Bóveda Vacía</h3>
                <p>No se encontraron credenciales en esta sección.</p>
            </div>
        `;
        return;
    }
    
    items.forEach(item => {
        const card = document.createElement('div');
        card.className = 'credential-card glass-panel';
        
        const isFavoriteClass = item.is_favorite === 1 ? 'active' : '';
        const displayUrl = item.url || 'Sin dirección URL';
        
        card.innerHTML = `
            <div class="card-top">
                <div class="card-header-main">
                    <div class="card-icon-box">
                        <i class="fa-solid fa-globe"></i>
                    </div>
                    <div class="card-title-area">
                        <span class="card-title" title="${escapeHtml(item.name)}">${escapeHtml(item.name)}</span>
                        <span class="card-url" title="${escapeHtml(displayUrl)}">${escapeHtml(displayUrl)}</span>
                    </div>
                </div>
                <button type="button" class="card-star-btn ${isFavoriteClass}" onclick="toggleItemFavorite(${item.id}, ${item.is_favorite})">
                    <i class="fa-solid fa-star"></i>
                </button>
            </div>
            
            <div class="card-body">
                <div class="info-row">
                    <span class="info-label">Usuario</span>
                    <span class="info-val" title="${escapeHtml(item.username)}">${escapeHtml(item.username)}</span>
                    <button type="button" class="btn-icon-copy" title="Copiar Usuario" onclick="copyToClipboard('${escapeJs(item.username)}', 'Usuario copiado')">
                        <i class="fa-regular fa-copy"></i>
                    </button>
                </div>
                <div class="info-row">
                    <span class="info-label">Clave</span>
                    <span class="info-val" id="pass-val-${item.id}" style="letter-spacing: 2px;">••••••••</span>
                    <div style="display: flex; gap: 4px;">
                        <button type="button" class="btn-icon-copy" id="pass-toggle-${item.id}" title="Mostrar Contraseña" onclick="togglePassVisibility(${item.id}, '${escapeJs(item.password)}')">
                            <i class="fa-regular fa-eye" id="eye-icon-${item.id}"></i>
                        </button>
                        <button type="button" class="btn-icon-copy" title="Copiar Contraseña" onclick="copyToClipboard('${escapeJs(item.password)}', 'Contraseña copiada')">
                            <i class="fa-regular fa-copy"></i>
                        </button>
                    </div>
                </div>
            </div>
            
            <div class="card-footer">
                <button type="button" class="card-action-btn card-action-btn-edit" title="Editar Credencial" onclick="editCredentialItem(${item.id})">
                    <i class="fa-solid fa-pen-to-square"></i>
                </button>
                <button type="button" class="card-action-btn card-action-btn-delete" title="Eliminar Credencial de la Bóveda" onclick="deleteCredentialItem(${item.id})">
                    <i class="fa-solid fa-trash-can"></i>
                </button>
            </div>
        `;
        grid.appendChild(card);
    });
}

function togglePassVisibility(id, rawPassword) {
    const valSpan = document.getElementById(`pass-val-${id}`);
    const eyeIcon = document.getElementById(`eye-icon-${id}`);
    const btn = document.getElementById(`pass-toggle-${id}`);
    if (valSpan.textContent === '••••••••') {
        valSpan.textContent = rawPassword;
        valSpan.style.letterSpacing = 'normal';
        eyeIcon.className = 'fa-regular fa-eye-slash';
        btn.title = 'Ocultar Contraseña';
    } else {
        valSpan.textContent = '••••••••';
        valSpan.style.letterSpacing = '2px';
        eyeIcon.className = 'fa-regular fa-eye';
        btn.title = 'Mostrar Contraseña';
    }
}
window.togglePassVisibility = togglePassVisibility;

function filterCredentials(query) {
    if (!query) {
        renderCredentials(vaultItems, 'credentials-grid');
        return;
    }
    
    const filtered = vaultItems.filter(item => {
        return item.name.toLowerCase().includes(query) ||
               item.username.toLowerCase().includes(query) ||
               (item.url && item.url.toLowerCase().includes(query)) ||
               (item.notes && item.notes.toLowerCase().includes(query));
    });
    
    renderCredentials(filtered, 'credentials-grid');
}

async function toggleItemFavorite(id, currentStatus) {
    const item = vaultItems.find(i => i.id === id);
    if (!item) return;
    
    const newStatus = currentStatus === 1 ? 0 : 1;
    const payload = {
        name: item.name,
        username: item.username,
        password: item.password,
        url: item.url,
        notes: item.notes,
        is_favorite: newStatus
    };
    
    try {
        await apiRequest(`/api/vault/${id}`, 'PUT', payload);
        
        const activeItem = document.querySelector('.menu-item.active');
        const activeSection = activeItem.getAttribute('data-target');
        if (activeSection === 'vault-section') {
            loadVault();
        } else if (activeSection === 'favorites-section') {
            loadFavorites();
        }
    } catch (error) {
        showToast(error.message, 'danger');
    }
}

function openCredentialModal(title = 'Nueva Credencial', id = '', name = '', username = '', password = '', url = '', notes = '', favorite = false) {
    document.getElementById('modal-title').textContent = title;
    document.getElementById('cred-id').value = id;
    document.getElementById('cred-name').value = name;
    document.getElementById('cred-username').value = username;
    document.getElementById('cred-password').value = password;
    document.getElementById('cred-url').value = url;
    document.getElementById('cred-notes').value = notes;
    document.getElementById('cred-favorite').checked = favorite;
    document.getElementById('cred-password').type = 'password';
    document.getElementById('credential-modal').classList.remove('hidden');
}

function closeCredentialModal() {
    document.getElementById('credential-modal').classList.add('hidden');
    document.getElementById('credential-form').reset();
}

function editCredentialItem(id) {
    const item = vaultItems.find(i => i.id === id);
    if (!item) return;
    
    openCredentialModal(
        'Editar Credencial',
        item.id,
        item.name,
        item.username,
        item.password,
        item.url,
        item.notes,
        item.is_favorite === 1
    );
}

async function deleteCredentialItem(id) {
    if (!confirm('¿Está seguro de eliminar esta credencial permanentemente de la bóveda?')) {
        return;
    }
    
    try {
        const data = await apiRequest(`/api/vault/${id}`, 'DELETE');
        showToast(data.message, 'success');
        
        const activeItem = document.querySelector('.menu-item.active');
        const activeSection = activeItem.getAttribute('data-target');
        if (activeSection === 'vault-section') {
            loadVault();
        } else if (activeSection === 'favorites-section') {
            loadFavorites();
        }
    } catch (error) {
        showToast(error.message, 'danger');
    }
}

function generatePasswordIntoField() {
    const field = document.getElementById('cred-password');
    const length = 16;
    const chars = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*_-+=";
    let password = "";
    const randomArray = new Uint32Array(length);
    window.crypto.getRandomValues(randomArray);
    
    for (let i = 0; i < length; i++) {
        password += chars[randomArray[i] % chars.length];
    }
    
    field.value = password;
    field.type = 'text';
    showToast('Contraseña robusta generada.', 'success');
}


// --- 2FA GOOGLE AUTHENTICATOR SETTINGS FLOW ---

async function update2FAUI() {
    try {
        const data = await apiRequest('/api/auth/user-info');
        currentUser = data;
        
        const statusInactive = document.getElementById('2fa-status-inactive');
        const setupWizard = document.getElementById('2fa-setup-wizard');
        const statusActive = document.getElementById('2fa-status-active');
        
        statusInactive.classList.add('hidden');
        setupWizard.classList.add('hidden');
        statusActive.classList.add('hidden');
        
        if (currentUser.totp_enabled === 1) {
            statusActive.classList.remove('hidden');
            document.getElementById('2fa-disable-password').value = '';
        } else {
            statusInactive.classList.remove('hidden');
        }
    } catch (error) {
        if (error.message !== 'session_terminated') {
            showToast(error.message, 'danger');
        }
    }
}

async function start2FASetup() {
    try {
        const data = await apiRequest('/api/auth/2fa/setup');
        
        document.getElementById('2fa-qr-code-img').src = data.qr_code;
        document.getElementById('2fa-secret-text').textContent = data.secret;
        document.getElementById('2fa-verification-code').value = '';
        
        document.getElementById('2fa-status-inactive').classList.add('hidden');
        document.getElementById('2fa-setup-wizard').classList.remove('hidden');
    } catch (error) {
        showToast(error.message, 'danger');
    }
}

function cancel2FASetup() {
    update2FAUI();
}

async function confirm2FA() {
    const code = document.getElementById('2fa-verification-code').value.trim();
    if (!code) {
        showToast('Ingrese el código de 6 dígitos.', 'warning');
        return;
    }
    
    try {
        const data = await apiRequest('/api/auth/2fa/enable', 'POST', { code });
        showToast(data.message, 'success');
        update2FAUI();
    } catch (error) {
        showToast(error.message, 'danger');
    }
}

async function disable2FA() {
    const password = document.getElementById('2fa-disable-password').value;
    if (!password) {
        showToast('Ingrese su contraseña maestra para autorizar desvinculación.', 'warning');
        return;
    }
    
    try {
        const data = await apiRequest('/api/auth/2fa/disable', 'POST', { password });
        showToast(data.message, 'success');
        update2FAUI();
    } catch (error) {
        showToast(error.message, 'danger');
    }
}


// --- SELF ACCOUNT DELETION ---
async function deleteOwnAccount() {
    const password = document.getElementById('delete-account-password').value;
    if (!password) {
        showToast('Ingrese su contraseña maestra para confirmar.', 'warning');
        return;
    }
    
    const doubleConfirm = confirm('¿Confirmar baja permanente de cuenta? Se eliminarán todas sus contraseñas.');
    if (!doubleConfirm) return;
    
    try {
        const data = await apiRequest('/api/auth/delete-account', 'POST', { password });
        showToast(data.message, 'success');
        logoutSilently();
    } catch (error) {
        showToast(error.message, 'danger');
    }
}


// --- ADMINISTRATOR MANAGEMENT PORTAL ---

let allActiveUsers = [];

// --- Pagination Variables for Active Users ---
let activeUsersCurrentPage = 1;
let activeUsersPageSize = 10;

async function loadAdminUsers() {
    const tbody = document.getElementById('admin-users-table-body');
    tbody.innerHTML = '<tr><td colspan="4" class="text-center"><i class="fa-solid fa-spinner fa-spin"></i> Cargando usuarios...</td></tr>';
    
    try {
        const users = await apiRequest('/api/admin/users');
        allActiveUsers = users.filter(u => u.status === 'active');
        document.getElementById('admin-search-users').value = '';
        activeUsersCurrentPage = 1;
        renderActiveUsers(allActiveUsers);
    } catch (error) {
        if (error.message !== 'session_terminated') {
            showToast(error.message, 'danger');
        }
    }
}

function renderActiveUsers(usersList) {
    const tbody = document.getElementById('admin-users-table-body');
    tbody.innerHTML = '';
    
    if (usersList.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No se encontraron usuarios activos.</td></tr>';
        updateUsersPagination(0);
        return;
    }
    
    // Paginate usersList
    const totalItems = usersList.length;
    const totalPages = Math.ceil(totalItems / activeUsersPageSize) || 1;
    if (activeUsersCurrentPage > totalPages) activeUsersCurrentPage = Math.max(1, totalPages);
    
    const startIndex = (activeUsersCurrentPage - 1) * activeUsersPageSize;
    const endIndex = Math.min(startIndex + activeUsersPageSize, totalItems);
    const paginatedList = usersList.slice(startIndex, endIndex);
    
    paginatedList.forEach(user => {
        const tr = document.createElement('tr');
        
        const roleBadge = user.is_superuser === 1 
            ? '<span class="badge badge-warning" style="padding: 2px 6px; font-size: 10px;"><i class="fa-solid fa-crown"></i> Superuser</span>'
            : (user.is_admin === 1 
                ? '<span class="badge badge-primary" style="padding: 2px 6px; font-size: 10px;"><i class="fa-solid fa-shield-halved"></i> Admin</span>' 
                : '<span class="badge badge-success" style="padding: 2px 6px; font-size: 10px;"><i class="fa-solid fa-user-tie"></i> Funcionario</span>');
            
        const totpBadge = user.totp_enabled === 1 
            ? '<span class="badge badge-success" style="padding: 2px 6px; font-size: 10px;"><i class="fa-solid fa-circle-check"></i> 2FA Activo</span>' 
            : '<span class="badge badge-danger" style="padding: 2px 6px; font-size: 10px;"><i class="fa-solid fa-circle-xmark"></i> 2FA Inactivo</span>';
            
        const statusBadge = user.status === 'active' 
            ? '<span class="badge badge-success" style="padding: 2px 6px; font-size: 10px;">Habilitado</span>' 
            : '<span class="badge badge-danger" style="padding: 2px 6px; font-size: 10px;">Inhabilitado</span>';
            
        const isSelf = user.id === currentUser.id;
        
        let actionButtons = `
            <button type="button" class="btn-table-action" title="Editar Correo MP" onclick="openAdminEmailModal(${user.id}, '${escapeJs(user.email)}')">
                <i class="fa-solid fa-envelope"></i>
            </button>
            <button type="button" class="btn-table-action" title="Restablecer Contraseña (Enviar Enlace de Correo)" onclick="adminResetUserPassword(${user.id})">
                <i class="fa-solid fa-key"></i>
            </button>
        `;
        
        if (user.totp_enabled === 1) {
            actionButtons += `
                <button type="button" class="btn-table-action" title="Desvincular Google Authenticator (2FA)" onclick="adminResetUser2FA(${user.id})">
                    <svg viewBox="0 0 512 512" width="16" height="16" style="display:block;">
                        <path fill="#1A73E8" d="M440,255.99997v0.00006C440,273.12085,426.12085,287,409.00003,287H302l-46-93.01001l49.6507-85.9951c8.56021-14.82629,27.51834-19.9065,42.34518-11.34724l0.00586,0.0034c14.82776,8.55979,19.90875,27.51928,11.34857,42.34682L309.70001,225h99.30002C426.12085,225,440,238.87917,440,255.99997z"/>
                        <path fill="#EA4335" d="M348.00174,415.34897l-0.00586,0.00339c-14.82684,8.55927-33.78497,3.47903-42.34518-11.34723L256,318.01001l-49.65065,85.99509c-8.5602,14.82629-27.51834,19.90652-42.34517,11.34729l-0.00591-0.00342c-14.82777-8.55978-19.90875-27.51929-11.34859-42.34683L202.29999,287L256,285l53.70001,2l49.6503,86.00214C367.91049,387.82968,362.8295,406.78918,348.00174,415.34897z"/>
                        <path fill="#FBBC04" d="M256,193.98999L242,232l-39.70001-7l-49.6503-86.00212c-8.56017-14.82755-3.47919-33.78705,11.34859-42.34684l0.00591-0.00341c14.82683-8.55925,33.78497-3.47903,42.34517,11.34726L256,193.98999z"/>
                        <path fill="#34A853" d="M248,225l-36,62H102.99997C85.87916,287,72,273.12085,72,256.00003v-0.00006C72,238.87917,85.87916,225,102.99997,225H248z"/>
                        <polygon fill="#185DB7" points="309.70001,287 202.29999,287 256,193.98999 "/>
                    </svg>
                </button>
            `;
        }
        
        if (!isSelf) {
            const statusLabel = user.status === 'active' ? 'Inhabilitar Funcionario' : 'Habilitar Funcionario';
            const statusIcon = user.status === 'active' ? 'fa-user-slash' : 'fa-user-check';
            const toggleStatus = user.status === 'active' ? 'suspended' : 'active';
            
            actionButtons += `
                <button type="button" class="btn-table-action" title="${statusLabel}" onclick="adminToggleUserStatus(${user.id}, '${toggleStatus}')">
                    <i class="fa-solid ${statusIcon}"></i>
                </button>
            `;
            
            if (currentUser && (currentUser.is_superuser == 1 || currentUser.is_superuser === true) && (user.is_superuser != 1 && user.is_superuser !== true)) {
                const currentRole = user.is_superuser === 1 ? 'superuser' : (user.is_admin === 1 ? 'admin' : 'funcionario');
                actionButtons += `
                    <button type="button" class="btn-table-action" title="Cambiar Rol de Seguridad" onclick="openEditRoleModal(${user.id}, '${currentRole}')">
                        <i class="fa-solid fa-user-gear"></i>
                    </button>
                `;
            }
            
            actionButtons += `
                <button type="button" class="btn-table-action btn-table-action-danger" title="Dar de Baja (Eliminar Funcionario de forma permanente)" onclick="adminDeleteUser(${user.id})">
                    <i class="fa-solid fa-trash-can"></i>
                </button>
            `;
        } else {
            actionButtons += `<span class="text-xs text-muted font-600" style="padding: 4px 6px;">Mi Cuenta</span>`;
        }
        
        const fullName = user.nombres 
            ? `${user.nombres} ${user.apellido_paterno || ''} ${user.apellido_materno || ''}`.replace(/\s+/g, ' ').trim() 
            : 'Administrador Principal';
        const ciVal = user.ci || '0000000';
        
        tr.innerHTML = `
            <td>
                <div style="font-weight: 600; color: var(--text-primary); font-size: 13px;">#${user.id} - ${escapeHtml(fullName)}</div>
                <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">${escapeHtml(user.email)}</div>
            </td>
            <td style="font-size: 13px;">${escapeHtml(ciVal)}</td>
            <td>
                <div style="margin-bottom: 4px;">${roleBadge}</div>
                <div style="display: flex; gap: 4px; flex-wrap: wrap;">
                    ${totpBadge}
                    ${statusBadge}
                </div>
            </td>
            <td>
                <div class="data-table-actions">
                    ${actionButtons}
                </div>
            </td>
        `;
        tbody.appendChild(tr);
    });
    
    updateUsersPagination(totalItems);
}

function filterActiveUsersTable() {
    activeUsersCurrentPage = 1;
    const q = document.getElementById('admin-search-users').value.trim().toLowerCase();
    if (!q) {
        renderActiveUsers(allActiveUsers);
        return;
    }
    
    const filtered = allActiveUsers.filter(u => {
        const nombres = (u.nombres || '').toLowerCase();
        const paterno = (u.apellido_paterno || '').toLowerCase();
        const materno = (u.apellido_materno || '').toLowerCase();
        const ci = (u.ci || '').toLowerCase();
        const email = (u.email || '').toLowerCase();
        
        return nombres.includes(q) || paterno.includes(q) || materno.includes(q) || ci.includes(q) || email.includes(q);
    });
    
    renderActiveUsers(filtered);
}

// --- Pagination helper functions for active users ---
function changeUsersPageSize(size) {
    activeUsersPageSize = parseInt(size) || 10;
    activeUsersCurrentPage = 1;
    filterActiveUsersTable();
}
window.changeUsersPageSize = changeUsersPageSize;

function prevUsersPage() {
    if (activeUsersCurrentPage > 1) {
        activeUsersCurrentPage--;
        filterActiveUsersTable();
    }
}
window.prevUsersPage = prevUsersPage;

function nextUsersPage() {
    const q = document.getElementById('admin-search-users').value.trim().toLowerCase();
    const filtered = q ? allActiveUsers.filter(u => {
        const nombres = (u.nombres || '').toLowerCase();
        const paterno = (u.apellido_paterno || '').toLowerCase();
        const materno = (u.apellido_materno || '').toLowerCase();
        const ci = (u.ci || '').toLowerCase();
        const email = (u.email || '').toLowerCase();
        return nombres.includes(q) || paterno.includes(q) || materno.includes(q) || ci.includes(q) || email.includes(q);
    }) : allActiveUsers;
    
    const totalPages = Math.ceil(filtered.length / activeUsersPageSize);
    if (activeUsersCurrentPage < totalPages) {
        activeUsersCurrentPage++;
        filterActiveUsersTable();
    }
}
window.nextUsersPage = nextUsersPage;

function updateUsersPagination(totalItems) {
    const totalPages = Math.ceil(totalItems / activeUsersPageSize) || 1;
    const pageInfo = document.getElementById('users-page-info');
    if (pageInfo) pageInfo.textContent = `Página ${activeUsersCurrentPage} de ${totalPages}`;
    
    const btnPrev = document.getElementById('btn-users-prev');
    const btnNext = document.getElementById('btn-users-next');
    
    if (btnPrev) btnPrev.disabled = (activeUsersCurrentPage === 1);
    if (btnNext) btnNext.disabled = (activeUsersCurrentPage === totalPages);
}

// --- Pagination Variables for Invitations ---
let invitesCurrentPage = 1;
let invitesPageSize = 10;
let allAdminInvitations = [];

async function loadAdminInvitations() {
    const tbody = document.getElementById('admin-invites-table-body');
    tbody.innerHTML = '<tr><td colspan="4" class="text-center"><i class="fa-solid fa-spinner fa-spin"></i> Cargando invitaciones...</td></tr>';
    
    try {
        const invites = await apiRequest('/api/admin/invitations');
        allAdminInvitations = invites;
        invitesCurrentPage = 1;
        renderAdminInvitations(allAdminInvitations);
    } catch (error) {
        if (error.message !== 'session_terminated') {
            showToast(error.message, 'danger');
        }
    }
}

function renderAdminInvitations(invitesList) {
    const tbody = document.getElementById('admin-invites-table-body');
    tbody.innerHTML = '';
    
    if (invitesList.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No se registran invitaciones.</td></tr>';
        updateInvitesPagination(0);
        return;
    }
    
    // Paginate invitesList
    const totalItems = invitesList.length;
    const totalPages = Math.ceil(totalItems / invitesPageSize) || 1;
    if (invitesCurrentPage > totalPages) invitesCurrentPage = Math.max(1, totalPages);
    
    const startIndex = (invitesCurrentPage - 1) * invitesPageSize;
    const endIndex = Math.min(startIndex + invitesPageSize, totalItems);
    const paginatedList = invitesList.slice(startIndex, endIndex);
    
    paginatedList.forEach(invite => {
        const tr = document.createElement('tr');
        
        const statusBadge = invite.status === 'inhabilitado' 
            ? '<span class="badge badge-danger">Inhabilitado</span>' 
            : '<span class="badge badge-warning">Pendiente</span>';
            
        const rawDate = invite.last_sent_at || invite.created_at;
        const dateStr = rawDate ? new Date(rawDate + " UTC").toLocaleString() : 'Sin Registro';
        
        const host = window.location.host;
        const protocol = window.location.protocol;
        const inviteUrl = invite.type === 'invitation' 
            ? `${protocol}//${host}/?invite=${invite.token}`
            : `${protocol}//${host}/?reset=${invite.token}`;
        
        let actionHtml = '';
        if (invite.status === 'pending') {
            if (invite.type === 'invitation') {
                actionHtml = `
                    <button type="button" class="btn-table-action" title="Copiar Enlace de Registro" onclick="copyToClipboard('${escapeJs(inviteUrl)}', 'Enlace de invitación copiado')">
                        <i class="fa-regular fa-copy"></i>
                    </button>
                    <button type="button" class="btn-table-action btn-table-action-success" style="margin-left: 5px;" title="Reenviar Enlace de Invitación por Correo" onclick="adminResendInvite(${invite.id})">
                        <i class="fa-solid fa-paper-plane"></i>
                    </button>
                `;
            } else {
                actionHtml = `
                    <button type="button" class="btn-table-action" title="Copiar Enlace de Restablecimiento" onclick="copyToClipboard('${escapeJs(inviteUrl)}', 'Enlace de restablecimiento copiado')">
                        <i class="fa-regular fa-copy"></i>
                    </button>
                    <button type="button" class="btn-table-action btn-table-action-success" style="margin-left: 5px;" title="Reenviar Enlace de Invitación por Correo" onclick="adminResetUserPasswordDirect(${invite.id})">
                        <i class="fa-solid fa-paper-plane"></i>
                    </button>
                `;
            }
        } else if (invite.status === 'inhabilitado') {
            actionHtml = `
                <button type="button" class="btn-table-action btn-table-action-success" title="Reenviar Enlace de Invitación por Correo" onclick="adminResetUserPasswordDirect(${invite.id})">
                    <i class="fa-solid fa-paper-plane"></i>
                </button>
            `;
        }
        
        const fullName = invite.nombres 
            ? `${invite.nombres} ${invite.apellido_paterno || ''} ${invite.apellido_materno || ''}`.replace(/\s+/g, ' ').trim() 
            : 'Sin Asignar';
        const ciVal = invite.ci || 'Sin Asignar';
        
        tr.innerHTML = `
            <td>
                <div style="font-weight: 600; color: var(--text-primary); font-size: 13px;">#${invite.id} - ${escapeHtml(fullName)}</div>
                <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">${escapeHtml(invite.email)}</div>
            </td>
            <td style="font-size: 13px;">${escapeHtml(ciVal)}</td>
            <td>
                <div>${statusBadge}</div>
                <div style="font-size: 10px; color: var(--text-muted); margin-top: 4px;">Envío: ${dateStr}</div>
            </td>
            <td>
                <div class="data-table-actions">
                    ${actionHtml}
                </div>
            </td>
        `;
        tbody.appendChild(tr);
    });
    
    updateInvitesPagination(totalItems);
}

// --- Pagination helper functions for invitations ---
function changeInvitesPageSize(size) {
    invitesPageSize = parseInt(size) || 10;
    invitesCurrentPage = 1;
    renderAdminInvitations(allAdminInvitations);
}
window.changeInvitesPageSize = changeInvitesPageSize;

function prevInvitesPage() {
    if (invitesCurrentPage > 1) {
        invitesCurrentPage--;
        renderAdminInvitations(allAdminInvitations);
    }
}
window.prevInvitesPage = prevInvitesPage;

function nextInvitesPage() {
    const totalPages = Math.ceil(allAdminInvitations.length / invitesPageSize);
    if (invitesCurrentPage < totalPages) {
        invitesCurrentPage++;
        renderAdminInvitations(allAdminInvitations);
    }
}
window.nextInvitesPage = nextInvitesPage;

function updateInvitesPagination(totalItems) {
    const totalPages = Math.ceil(totalItems / invitesPageSize) || 1;
    const pageInfo = document.getElementById('invites-page-info');
    if (pageInfo) pageInfo.textContent = `Página ${invitesCurrentPage} de ${totalPages}`;
    
    const btnPrev = document.getElementById('btn-invites-prev');
    const btnNext = document.getElementById('btn-invites-next');
    
    if (btnPrev) btnPrev.disabled = (invitesCurrentPage === 1);
    if (btnNext) btnNext.disabled = (invitesCurrentPage === totalPages);
}


// --- ADMIN TABS NAVIGATION ---
function selectAdminTab(tabName) {
    document.querySelectorAll('.admin-tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.admin-tab-content').forEach(content => content.classList.remove('active'));
    
    if (tabName === 'users') {
        const btn = document.getElementById('admin-tab-users-btn');
        const content = document.getElementById('admin-tab-users-content');
        if (btn) btn.classList.add('active');
        if (content) content.classList.add('active');
        loadAdminUsers();
    } else if (tabName === 'invites') {
        const btn = document.getElementById('admin-tab-invites-btn');
        const content = document.getElementById('admin-tab-invites-content');
        if (btn) btn.classList.add('active');
        if (content) content.classList.add('active');
        loadAdminInvitations();
        setupDragAndDrop();
    }
}

// --- ADMIN RESET PASSWORD ACTION ---
async function adminResetUserPassword(userId) {
    if (!confirm('¿Está seguro de que desea restablecer la contraseña maestra de este funcionario? Se le enviará un correo electrónico para que asigne una nueva clave y sus credenciales guardadas permanecerán intactas.')) {
        return;
    }
    try {
        const data = await apiRequest(`/api/admin/users/${userId}/reset-password`, 'POST');
        if (data.email_sent) {
            showToast(data.message, 'success');
        } else {
            showToast(`${data.message} (Nota: Correo SMTP no enviado: ${data.email_status})`, 'warning');
        }
        loadAdminUsers();
    } catch (error) {
        showToast(error.message, 'danger');
    }
}

async function adminResetUserPasswordDirect(userId) {
    try {
        const data = await apiRequest(`/api/admin/users/${userId}/reset-password`, 'POST');
        if (data.email_sent) {
            showToast(data.message, 'success');
        } else {
            showToast(`${data.message} (Nota: Correo SMTP no enviado: ${data.email_status})`, 'warning');
        }
        loadAdminInvitations();
    } catch (error) {
        showToast(error.message, 'danger');
    }
}


// --- EXCEL / CSV BULK IMPORT ---
let selectedBulkFile = null;

function triggerExcelFileInput() {
    document.getElementById('excel-file-input').click();
}

function handleExcelFileSelect(e) {
    const files = e.target.files || e.dataTransfer.files;
    if (files.length === 0) return;
    
    const file = files[0];
    const extension = file.name.split('.').pop().toLowerCase();
    if (extension !== 'xlsx' && extension !== 'csv') {
        showToast('Solo se admiten archivos Excel (.xlsx) y CSV.', 'danger');
        return;
    }
    
    selectedBulkFile = file;
    document.getElementById('selected-file-name').textContent = file.name;
    document.getElementById('selected-file-badge').classList.remove('hidden');
    document.getElementById('btn-upload-bulk').removeAttribute('disabled');
}

function setupDragAndDrop() {
    const dropZone = document.getElementById('excel-drop-zone');
    if (!dropZone) return;
    
    // Prevent default drag behaviors
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, e => {
            e.preventDefault();
            e.stopPropagation();
        }, false);
    });
    
    // Highlight drop zone when item dragged over it
    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => {
            dropZone.classList.add('drag-over');
        }, false);
    });
    
    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => {
            dropZone.classList.remove('drag-over');
        }, false);
    });
    
    // Handle dropped files
    dropZone.addEventListener('drop', e => {
        handleExcelFileSelect(e);
    }, false);
}

async function uploadBulkFile() {
    if (!selectedBulkFile) return;
    
    const btn = document.getElementById('btn-upload-bulk');
    btn.setAttribute('disabled', 'true');
    btn.innerHTML = 'Procesando carga... <i class="fa-solid fa-spinner fa-spin"></i>';
    
    const formData = new FormData();
    formData.append('file', selectedBulkFile);
    
    try {
        const token = localStorage.getItem('token');
        const response = await fetch('/api/admin/invite/bulk', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            },
            body: formData
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'Error al procesar el lote masivo.');
        }
        
        document.getElementById('bulk-stat-success').textContent = data.success_count;
        document.getElementById('bulk-stat-skipped').textContent = data.skipped_count;
        document.getElementById('bulk-stat-errors').textContent = data.errors.length;
        
        const errorsList = document.getElementById('bulk-errors-list');
        errorsList.innerHTML = '';
        if (data.errors.length > 0) {
            data.errors.forEach(err => {
                const li = document.createElement('li');
                li.textContent = err;
                errorsList.appendChild(li);
            });
            errorsList.classList.remove('hidden');
            document.getElementById('bulk-result-card').classList.add('has-errors');
        } else {
            errorsList.classList.add('hidden');
            document.getElementById('bulk-result-card').classList.remove('has-errors');
        }
        
        document.getElementById('bulk-result-card').classList.remove('hidden');
        showToast('Importación masiva completada.', 'success');
        
        selectedBulkFile = null;
        document.getElementById('excel-file-input').value = '';
        document.getElementById('selected-file-badge').classList.add('hidden');
        
        loadAdminInvitations();
    } catch (error) {
        showToast(error.message, 'danger');
    } finally {
        btn.innerHTML = 'Procesar Importación <i class="fa-solid fa-upload"></i>';
    }
}

function downloadExcelTemplate(e) {
    e.preventDefault();
    const csvContent = "Nombres;Apellido Paterno;Apellido Materno;Nro Ci;Correo institucional\nJuan Carlos;Perez;Gomez;1234567;funcionario1@fiscalia.gob.bo\nMaria Elena;;Justiniano;7654321;funcionario2@fiscalia.gob.bo";
    const blob = new Blob([new Uint8Array([0xEF, 0xBB, 0xBF]), csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", "planilla_alta_funcionarios.csv");
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}


async function loadAdminLogs() {
    const tbody = document.getElementById('admin-logs-table-body');
    tbody.innerHTML = '<tr><td colspan="5" class="text-center"><i class="fa-solid fa-spinner fa-spin"></i> Cargando logs...</td></tr>';
    
    try {
        const logs = await apiRequest('/api/admin/logs');
        tbody.innerHTML = '';
        
        if (logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No se registran eventos de auditoría.</td></tr>';
            return;
        }
        
        logs.forEach(log => {
            const tr = document.createElement('tr');
            const userDisplay = log.user_email ? escapeHtml(log.user_email) : 'Sistema / Cuenta Eliminada';
            
            let actionBadge = `<span class="badge">${log.action}</span>`;
            if (log.action.includes('REGISTER')) actionBadge = `<span class="badge badge-primary">${log.action}</span>`;
            else if (log.action.includes('RESET')) actionBadge = `<span class="badge badge-warning">${log.action}</span>`;
            else if (log.action.includes('DELETE')) actionBadge = `<span class="badge badge-danger">${log.action}</span>`;
            else if (log.action.includes('ENABLE') || log.action.includes('ACTIVE') || log.action.includes('INVITE')) actionBadge = `<span class="badge badge-success">${log.action}</span>`;
            
            const dateStr = new Date(log.timestamp + " UTC").toLocaleString();
            
            tr.innerHTML = `
                <td>${log.id}</td>
                <td><strong>${userDisplay}</strong></td>
                <td>${actionBadge}</td>
                <td>${escapeHtml(log.details)}</td>
                <td><span class="text-xs text-muted">${dateStr}</span></td>
            `;
            tbody.appendChild(tr);
        });
    } catch (error) {
        if (error.message !== 'session_terminated') {
            showToast(error.message, 'danger');
        }
    }
}

// Admin Actions
async function adminToggleUserStatus(userId, status) {
    try {
        const data = await apiRequest(`/api/admin/users/${userId}/status`, 'PUT', { status });
        showToast(data.message, 'success');
        loadAdminUsers();
    } catch (error) {
        showToast(error.message, 'danger');
    }
}

function openEditRoleModal(userId, currentRole) {
    document.getElementById('edit-role-user-id').value = userId;
    document.getElementById('edit-role-select').value = currentRole;
    document.getElementById('edit-role-modal').classList.remove('hidden');
}

function closeEditRoleModal() {
    document.getElementById('edit-role-modal').classList.add('hidden');
    document.getElementById('edit-role-form').reset();
}

async function saveUserRole(e) {
    if (e) e.preventDefault();
    const userId = document.getElementById('edit-role-user-id').value;
    const role = document.getElementById('edit-role-select').value;
    
    try {
        const data = await apiRequest(`/api/admin/users/${userId}/role`, 'PUT', { role });
        showToast(data.message, 'success');
        closeEditRoleModal();
        loadAdminUsers();
    } catch (error) {
        showToast(error.message, 'danger');
    }
}

window.openEditRoleModal = openEditRoleModal;
window.closeEditRoleModal = closeEditRoleModal;
window.saveUserRole = saveUserRole;

async function adminResetUser2FA(userId) {
    if (!confirm('¿Desvincular Google Authenticator (2FA) para este funcionario? Se cerrará su sesión activa.')) {
        return;
    }
    
    try {
        const data = await apiRequest(`/api/admin/users/${userId}/reset-2fa`, 'PUT');
        showToast(data.message, 'success');
        loadAdminUsers();
    } catch (error) {
        showToast(error.message, 'danger');
    }
}

async function adminResetUserPassword(userId) {
    if (!confirm('¿Restablecer la contraseña maestra de este funcionario por requerimiento de ticket? Se forzará el cambio al ingresar.')) {
        return;
    }
    
    try {
        const data = await apiRequest(`/api/admin/users/${userId}/reset-password`, 'POST');
        showToast(data.message, 'success');
        
        document.getElementById('temp-password-text').textContent = data.temp_password;
        document.getElementById('admin-temp-password-modal').classList.remove('hidden');
        
        loadAdminUsers();
    } catch (error) {
        showToast(error.message, 'danger');
    }
}

async function adminDeleteUser(userId) {
    if (!confirm('¡ADVERTENCIA CRÍTICA!\n¿Eliminar definitivamente a este funcionario? Se borrará su cuenta y bóveda.')) {
        return;
    }
    
    try {
        const data = await apiRequest(`/api/admin/users/${userId}`, 'DELETE');
        showToast(data.message, 'success');
        loadAdminUsers();
    } catch (error) {
        showToast(error.message, 'danger');
    }
}

// Modal actions
function openAdminEmailModal(userId, currentEmail) {
    document.getElementById('admin-email-userid').value = userId;
    document.getElementById('admin-new-email').value = currentEmail;
    document.getElementById('admin-email-modal').classList.remove('hidden');
}

function closeAdminEmailModal() {
    document.getElementById('admin-email-modal').classList.add('hidden');
    document.getElementById('admin-email-form').reset();
}

function closeAdminTempPasswordModal() {
    document.getElementById('admin-temp-password-modal').classList.add('hidden');
    document.getElementById('temp-password-text').textContent = '';
}

function copyTempPasswordToClipboard() {
    const text = document.getElementById('temp-password-text').textContent;
    copyToClipboard(text, 'Contraseña temporal copiada al portapapeles');
}


// --- CLIPBOARD & STRING UTILITIES ---

function copyToClipboard(text, successMessage) {
    navigator.clipboard.writeText(text).then(() => {
        showToast(successMessage, 'success');
    }).catch(err => {
        showToast('Error al copiar al portapapeles.', 'danger');
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

async function startForced2FASetup() {
    try {
        const data = await apiRequest('/api/auth/login/2fa-setup', 'GET', null, true);
        document.getElementById('login-2fa-qr-img').src = data.qr_code;
        document.getElementById('login-2fa-secret-text').textContent = data.secret;
        document.getElementById('login-totp-setup-code').value = '';
        document.getElementById('login-totp-setup-code').focus();
    } catch (error) {
        showToast(error.message, 'danger');
    }
}



async function loadIdleTimeout() {
    try {
        const config = await apiRequest('/api/settings/timeout');
        idleTimeoutMinutes = parseInt(config.idle_timeout_minutes) || 15;
        const select = document.getElementById('global-idle-timeout-select');
        if (select) {
            select.value = idleTimeoutMinutes.toString();
        }
    } catch (e) {
        console.error("Error al cargar timeout de inactividad:", e);
    }
}

function setupActivityMonitor() {
    const events = ['mousemove', 'keydown', 'mousedown', 'touchstart', 'scroll'];
    events.forEach(eventName => {
        window.addEventListener(eventName, resetActivityTimer, { passive: true });
    });
    setInterval(checkActivityInactivity, 10000);
}

function resetActivityTimer() {
    if (isSuspended) return;
    lastActivityTime = Date.now();
}

function checkActivityInactivity() {
    if (!token) return;
    if (isSuspended) return;
    
    const elapsedMs = Date.now() - lastActivityTime;
    const limitMs = 5 * 60 * 1000; // 5 minutes inactivity suspension hardcoded
    
    if (elapsedMs > limitMs) {
        isSuspended = true;
        document.getElementById('suspension-totp-code').value = '';
        document.getElementById('suspension-error').classList.add('hidden');
        document.getElementById('suspension-overlay').classList.remove('hidden');
        document.getElementById('suspension-totp-code').focus();
    }
}

async function unlockSuspension(e) {
    if (e) e.preventDefault();
    const codeField = document.getElementById('suspension-totp-code');
    const code = codeField.value.trim();
    const errDiv = document.getElementById('suspension-error');
    
    if (!code) {
        errDiv.textContent = 'Ingrese el código de doble factor.';
        errDiv.classList.remove('hidden');
        return;
    }
    
    try {
        const data = await apiRequest('/api/auth/verify-totp', 'POST', { code });
        if (data.valid) {
            isSuspended = false;
            document.getElementById('suspension-overlay').classList.add('hidden');
            resetActivityTimer();
            showToast('Bóveda desbloqueada con éxito.', 'success');
        } else {
            throw new Error(data.message || 'Código incorrecto.');
        }
    } catch (err) {
        errDiv.textContent = err.message || 'Código incorrecto o expirado.';
        errDiv.classList.remove('hidden');
        codeField.value = '';
        codeField.focus();
    }
}

window.unlockSuspension = unlockSuspension;

function initializeTheme() {
    const savedTheme = localStorage.getItem('vault_theme') || 'light';
    if (savedTheme === 'light') {
        document.body.classList.add('light-theme');
        updateThemeUI(true);
    } else {
        document.body.classList.remove('light-theme');
        updateThemeUI(false);
    }
}

function toggleTheme() {
    const isLight = document.body.classList.toggle('light-theme');
    localStorage.setItem('vault_theme', isLight ? 'light' : 'dark');
    updateThemeUI(isLight);
}

function updateThemeUI(isLight) {
    const sunIcon = document.querySelector('.icon-sun');
    const moonIcon = document.querySelector('.icon-moon');
    const themeBtnText = document.getElementById('theme-btn-text');
    
    if (!sunIcon || !moonIcon || !themeBtnText) return;
    
    if (isLight) {
        sunIcon.classList.remove('hidden');
        moonIcon.classList.add('hidden');
        themeBtnText.textContent = "Modo Oscuro";
    } else {
        sunIcon.classList.add('hidden');
        moonIcon.classList.remove('hidden');
        themeBtnText.textContent = "Modo Claro";
    }
}

async function loadSMTPSettings() {
    try {
        const config = await apiRequest('/api/admin/settings/smtp');
        document.getElementById('smtp-host-input').value = config.smtp_host || '';
        document.getElementById('smtp-port-input').value = config.smtp_port || '';
        document.getElementById('smtp-user-input').value = config.smtp_user || '';
        document.getElementById('smtp-from-input').value = config.smtp_from || '';
    } catch (e) {
        console.error("Error al cargar configuración SMTP:", e);
    }
}

function openRequestHintModal() {
    document.getElementById('request-hint-modal').classList.remove('hidden');
    document.getElementById('hint-email').value = '';
    document.getElementById('hint-email').focus();
}

function closeRequestHintModal() {
    document.getElementById('request-hint-modal').classList.add('hidden');
}

async function adminResendInvite(inviteId) {
    try {
        const data = await apiRequest(`/api/admin/invite/${inviteId}/resend`, 'POST');
        if (data.email_sent) {
            showToast('Invitación reenviada con éxito al correo del funcionario.', 'success');
        } else {
            showToast(`Enlace regenerado pero correo no enviado: ${data.email_status}`, 'warning');
        }
        loadAdminInvitations();
    } catch (error) {
        showToast(error.message, 'danger');
    }
}


// --- PASSWORD STRENGTH METER LOGIC ---

function checkPasswordStrength(password) {
    if (!password) {
        return { score: 0, text: 'Contraseña vacía', color: 'transparent', width: '0%', isStrong: false };
    }
    
    let score = 0;
    
    // Check 1: Length >= 8
    if (password.length >= 8) score++;
    
    // Check 2: Lowercase letter
    if (/[a-z]/.test(password)) score++;
    
    // Check 3: Uppercase letter
    if (/[A-Z]/.test(password)) score++;
    
    // Check 4: Number
    if (/\d/.test(password)) score++;
    
    // Check 5: Special character
    if (/[!@#\$%\^&\*\(\),\.\?\":\{\}\|<>\_\+\-\=\[\]/\\\s]/.test(password)) score++;
    
    // If length is less than 8, force it to be weak
    if (password.length < 8) {
        return {
            score: Math.min(2, score),
            text: 'Débil (Debe tener mínimo 8 caracteres)',
            color: '#ef4444',
            width: '33%',
            isStrong: false
        };
    }
    
    if (score < 3) {
        return { score, text: 'Débil', color: '#ef4444', width: '33%', isStrong: false };
    } else if (score < 5) {
        return { score, text: 'Regular', color: '#f59e0b', width: '66%', isStrong: false };
    } else {
        return { score, text: 'Fuerte (Segura)', color: '#10b981', width: '100%', isStrong: true };
    }
}

// Helper function to update Kaspersky-like checklist icons and text validity
function updateChecklist(prefix, password) {
    const rules = {
        length: password.length >= 8,
        upper: /[A-Z]/.test(password),
        lower: /[a-z]/.test(password),
        digit: /\d/.test(password),
        special: /[!@#\$%\^&\*\(\),\.\?\":\{\}\|<>\_\+\-\=\[\]/\\\s]/.test(password)
    };
    
    for (const [key, met] of Object.entries(rules)) {
        const item = document.getElementById(`${prefix}-req-${key}`);
        if (!item) continue;
        
        const icon = item.querySelector('i');
        if (met) {
            item.classList.add('valid');
            if (icon) {
                icon.className = 'fa-solid fa-circle-check';
                icon.style.color = '#10b981';
            }
        } else {
            item.classList.remove('valid');
            if (icon) {
                icon.className = 'fa-solid fa-circle-xmark';
                icon.style.color = '#ef4444';
            }
        }
    }
}

// 1. Registration Form Password Strength Event Listeners
const regPassword = document.getElementById('register-password');
const regConfirm = document.getElementById('register-confirm-password');
const regSubmit = document.querySelector('#register-form button[type="submit"]');
const regBar = document.getElementById('register-password-strength-bar');
const regText = document.getElementById('register-password-strength-text');

function updateRegFormValidity() {
    if (!regPassword) return;
    const strength = checkPasswordStrength(regPassword.value);
    
    if (regBar) regBar.style.width = strength.width;
    if (regBar) regBar.style.backgroundColor = strength.color;
    if (regText) regText.textContent = strength.text;
    if (regText) regText.style.color = strength.color;
    
    updateChecklist('reg', regPassword.value);
    
    const passwordsMatch = regPassword.value === regConfirm.value;
    
    if (strength.isStrong && passwordsMatch && regPassword.value.length >= 8) {
        if (regSubmit) regSubmit.disabled = false;
    } else {
        if (regSubmit) regSubmit.disabled = true;
    }
}

if (regPassword) {
    regPassword.addEventListener('input', updateRegFormValidity);
    if (regConfirm) regConfirm.addEventListener('input', updateRegFormValidity);
}

// 2. Forced Password Change Form Strength Event Listeners
const forcePassword = document.getElementById('force-new-password');
const forceConfirm = document.getElementById('force-confirm-password');
const forceSubmit = document.querySelector('#force-change-form button[type="submit"]');
const forceBar = document.getElementById('force-password-strength-bar');
const forceText = document.getElementById('force-password-strength-text');

function updateForceFormValidity() {
    if (!forcePassword) return;
    const strength = checkPasswordStrength(forcePassword.value);
    
    if (forceBar) forceBar.style.width = strength.width;
    if (forceBar) forceBar.style.backgroundColor = strength.color;
    if (forceText) forceText.textContent = strength.text;
    if (forceText) forceText.style.color = strength.color;
    
    updateChecklist('force', forcePassword.value);
    
    const passwordsMatch = forcePassword.value === forceConfirm.value;
    
    if (strength.isStrong && passwordsMatch && forcePassword.value.length >= 8) {
        if (forceSubmit) forceSubmit.disabled = false;
    } else {
        if (forceSubmit) forceSubmit.disabled = true;
    }
}

if (forcePassword) {
    forcePassword.addEventListener('input', updateForceFormValidity);
    if (forceConfirm) forceConfirm.addEventListener('input', updateForceFormValidity);
}

// 3. User Settings Change Password Form Event Listeners
const settingsNewPass = document.getElementById('settings-new-password');
const settingsConfirmPass = document.getElementById('settings-confirm-password');
const settingsSubmit = document.querySelector('#change-password-form button[type="submit"]');
const settingsBar = document.getElementById('settings-password-strength-bar');
const settingsText = document.getElementById('settings-password-strength-text');

function updateSettingsFormValidity() {
    if (!settingsNewPass) return;
    const strength = checkPasswordStrength(settingsNewPass.value);
    
    if (settingsBar) settingsBar.style.width = strength.width;
    if (settingsBar) settingsBar.style.backgroundColor = strength.color;
    if (settingsText) settingsText.textContent = strength.text;
    if (settingsText) settingsText.style.color = strength.color;
    
    updateChecklist('settings', settingsNewPass.value);
    
    const passwordsMatch = settingsNewPass.value === settingsConfirmPass.value;
    
    if (strength.isStrong && passwordsMatch && settingsNewPass.value.length >= 8) {
        if (settingsSubmit) settingsSubmit.disabled = false;
    } else {
        if (settingsSubmit) settingsSubmit.disabled = true;
    }
}

if (settingsNewPass) {
    settingsNewPass.addEventListener('input', updateSettingsFormValidity);
    if (settingsConfirmPass) settingsConfirmPass.addEventListener('input', updateSettingsFormValidity);
}

// 4. Reset Password Form (via Admin Token) Event Listeners
const resetPasswordInput = document.getElementById('reset-password');
const resetSubmit = document.querySelector('#reset-password-form button[type="submit"]');
const resetBar = document.getElementById('reset-password-strength-bar');
const resetText = document.getElementById('reset-password-strength-text');

function updateResetFormValidity() {
    if (!resetPasswordInput) return;
    const strength = checkPasswordStrength(resetPasswordInput.value);
    
    if (resetBar) resetBar.style.width = strength.width;
    if (resetBar) resetBar.style.backgroundColor = strength.color;
    if (resetText) resetText.textContent = strength.text;
    if (resetText) resetText.style.color = strength.color;
    
    updateChecklist('reset', resetPasswordInput.value);
    
    if (strength.isStrong && resetPasswordInput.value.length >= 8) {
        if (resetSubmit) resetSubmit.disabled = false;
    } else {
        if (resetSubmit) resetSubmit.disabled = true;
    }
}

if (resetPasswordInput) {
    resetPasswordInput.addEventListener('input', updateResetFormValidity);
}

// Disable submit buttons by default until "Fuerte" is achieved
const rSub = document.querySelector('#register-form button[type="submit"]');
if (rSub) rSub.disabled = true;
const fSub = document.querySelector('#force-change-form button[type="submit"]');
if (fSub) fSub.disabled = true;
const sSub = document.querySelector('#change-password-form button[type="submit"]');
if (sSub) sSub.disabled = true;
const rstSub = document.querySelector('#reset-password-form button[type="submit"]');
if (rstSub) rstSub.disabled = true;


// --- SUGGESTED PASSWORD GENERATION LOGIC ---

const passwordModes = {
    reg: { mode: 'custom', generated: '' },
    force: { mode: 'custom', generated: '' },
    settings: { mode: 'custom', generated: '' },
    reset: { mode: 'custom', generated: '' }
};

function generateSecurePassword() {
    const length = 16;
    const charsetUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const charsetLower = "abcdefghijklmnopqrstuvwxyz";
    const charsetDigits = "0123456789";
    const charsetSpecial = "!@#$%^&*()_+~`|}{[]:;?><,./-=";
    
    let password = "";
    // Ensure at least one of each to fulfill Kaspersky checklist instantly
    password += charsetUpper[Math.floor(Math.random() * charsetUpper.length)];
    password += charsetLower[Math.floor(Math.random() * charsetLower.length)];
    password += charsetDigits[Math.floor(Math.random() * charsetDigits.length)];
    password += charsetSpecial[Math.floor(Math.random() * charsetSpecial.length)];
    
    const allCharsets = charsetUpper + charsetLower + charsetDigits + charsetSpecial;
    for (let i = 4; i < length; i++) {
        password += allCharsets[Math.floor(Math.random() * allCharsets.length)];
    }
    
    // Shuffle the password
    return password.split('').sort(() => 0.5 - Math.random()).join('');
}

function selectPasswordMode(prefix, mode) {
    if (!passwordModes[prefix]) return;
    passwordModes[prefix].mode = mode;
    
    const tabSuggested = document.getElementById(`tab-suggested-${prefix}`);
    const tabCustom = document.getElementById(`tab-custom-${prefix}`);
    const boxSuggested = document.getElementById(`suggested-box-${prefix}`);
    const boxCustom = document.getElementById(`custom-box-${prefix}`);
    
    if (mode === 'suggested') {
        if (tabSuggested) tabSuggested.classList.add('active');
        if (tabCustom) tabCustom.classList.remove('active');
        if (boxSuggested) boxSuggested.classList.remove('hidden');
        if (boxCustom) boxCustom.classList.add('hidden');
        
        if (!passwordModes[prefix].generated) {
            passwordModes[prefix].generated = generateSecurePassword();
        }
        
        const previewSpan = document.getElementById(`suggested-pw-${prefix}`);
        if (previewSpan) previewSpan.textContent = passwordModes[prefix].generated;
        
        fillInputsWithSuggested(prefix, passwordModes[prefix].generated);
    } else {
        if (tabSuggested) tabSuggested.classList.remove('active');
        if (tabCustom) tabCustom.classList.add('active');
        if (boxSuggested) boxSuggested.classList.add('hidden');
        if (boxCustom) boxCustom.classList.remove('hidden');
        
        clearInputs(prefix);
    }
}

function fillInputsWithSuggested(prefix, val) {
    if (prefix === 'reg') {
        const p = document.getElementById('register-password');
        const pc = document.getElementById('register-confirm-password');
        if (p) p.value = val;
        if (pc) pc.value = val;
        updateRegFormValidity();
    } else if (prefix === 'force') {
        const p = document.getElementById('force-new-password');
        const pc = document.getElementById('force-confirm-password');
        if (p) p.value = val;
        if (pc) pc.value = val;
        updateForceFormValidity();
    } else if (prefix === 'settings') {
        const p = document.getElementById('settings-new-password');
        const pc = document.getElementById('settings-confirm-password');
        if (p) p.value = val;
        if (pc) pc.value = val;
        updateSettingsFormValidity();
    } else if (prefix === 'reset') {
        const p = document.getElementById('reset-password');
        if (p) p.value = val;
        updateResetFormValidity();
    }
}

function clearInputs(prefix) {
    if (prefix === 'reg') {
        const p = document.getElementById('register-password');
        const pc = document.getElementById('register-confirm-password');
        if (p) p.value = '';
        if (pc) pc.value = '';
        updateRegFormValidity();
    } else if (prefix === 'force') {
        const p = document.getElementById('force-new-password');
        const pc = document.getElementById('force-confirm-password');
        if (p) p.value = '';
        if (pc) pc.value = '';
        updateForceFormValidity();
    } else if (prefix === 'settings') {
        const p = document.getElementById('settings-new-password');
        const pc = document.getElementById('settings-confirm-password');
        if (p) p.value = '';
        if (pc) pc.value = '';
        updateSettingsFormValidity();
    } else if (prefix === 'reset') {
        const p = document.getElementById('reset-password');
        if (p) p.value = '';
        updateResetFormValidity();
    }
}

function copySuggestedPassword(prefix) {
    const val = passwordModes[prefix].generated;
    if (!val) return;
    navigator.clipboard.writeText(val).then(() => {
        showToast('Contraseña copiada al portapapeles.', 'success');
    }).catch(() => {
        showToast('No se pudo copiar la contraseña.', 'danger');
    });
}

