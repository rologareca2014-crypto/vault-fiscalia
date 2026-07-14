// content.js - Intercept password forms and display VaultFiscalia save prompt
(function() {
    // URL de producción de la Web de la Bóveda (Cambiar por tu URL de Netlify al publicar)
    const VAULT_WEB_URL = "http://127.0.0.1:5000";
    
    // Extracción de dominio para exclusión
    let isVaultDomain = false;
    try {
        const vaultUrlObj = new URL(VAULT_WEB_URL);
        isVaultDomain = window.location.host === vaultUrlObj.host || 
                        window.location.hostname === vaultUrlObj.hostname || 
                        window.location.host === '127.0.0.1:5000' || 
                        window.location.hostname === 'localhost';
    } catch (e) {
        isVaultDomain = window.location.host === '127.0.0.1:5000' || window.location.hostname === 'localhost';
    }

    if (isVaultDomain) {
        function syncToken() {
            const pageToken = localStorage.getItem('vault_token');
            chrome.runtime.sendMessage({
                action: "sync_session",
                token: pageToken
            });
        }
        
        // Sync on load
        syncToken();
        
        // Sync on storage change or clicks inside page (e.g. login/logout redirects)
        window.addEventListener('storage', syncToken);
        document.addEventListener('click', () => {
            setTimeout(syncToken, 500);
        });
        
        // CRITICAL: Exit immediately to never capture credentials (like Master Password) on the Vault itself!
        return;
    }

    let lastCaptured = null;
    let spaTimeout = null;

    // Helper to capture inputs from a password field
    function captureInputs(passwordInput) {
        if (!passwordInput) return null;
        const form = passwordInput.closest('form') || document;
        
        const inputs = Array.from(form.querySelectorAll('input'));
        const passwordIdx = inputs.indexOf(passwordInput);
        
        let usernameInput = null;
        for (let i = passwordIdx - 1; i >= 0; i--) {
            const type = inputs[i].type;
            if (type === 'text' || type === 'email' || type === 'username') {
                usernameInput = inputs[i];
                break;
            }
        }

        const username = usernameInput ? usernameInput.value.trim() : '';
        const password = passwordInput.value;
        const url = window.location.origin;
        let name = document.title.split('-')[0].trim() || window.location.hostname;
        if (name.length > 25) {
            name = window.location.hostname;
        }

        if (username && password) {
            return { name, username, password, url, timestamp: Date.now() };
        }
        return null;
    }

    // Capture on input blur (pre-save to memory)
    document.addEventListener('blur', (e) => {
        if (e.target.type === 'password') {
            const data = captureInputs(e.target);
            if (data) {
                lastCaptured = data;
            }
        }
    }, true);

    function triggerSPATimeout() {
        if (spaTimeout) clearTimeout(spaTimeout);
        spaTimeout = setTimeout(() => {
            chrome.storage.local.get(['pending_save', 'vault_email'], (result) => {
                const pending = result.pending_save;
                if (pending) {
                    chrome.storage.local.remove('pending_save');
                    evaluateAndPrompt(pending, result.vault_email || '');
                }
            });
        }, 1500);
    }

    // Capture on submit button click (pre-navigation write)
    document.addEventListener('click', (e) => {
        if (e.target.closest('#vf-prompt-wrapper')) return;
        const btn = e.target.closest('button, input[type="submit"]');
        if (!btn) return;
        
        const context = btn.closest('form') || document;
        const passwordInput = context.querySelector('input[type="password"]');
        if (!passwordInput) return;
        
        const data = captureInputs(passwordInput);
        if (data) {
            chrome.storage.local.set({ pending_save: data }, triggerSPATimeout);
        } else if (lastCaptured) {
            chrome.storage.local.set({ pending_save: lastCaptured }, triggerSPATimeout);
        }
    }, true);

    // Capture on Enter key press (pre-navigation write)
    document.addEventListener('keydown', (e) => {
        if (e.target.closest('#vf-prompt-wrapper')) return;
        if (e.key === 'Enter') {
            const target = e.target;
            if (target.tagName === 'INPUT' && (target.type === 'password' || target.type === 'text' || target.type === 'email')) {
                const form = target.closest('form') || document;
                const passwordInput = form.querySelector('input[type="password"]');
                if (passwordInput) {
                    const data = captureInputs(passwordInput);
                    if (data) {
                        chrome.storage.local.set({ pending_save: data }, triggerSPATimeout);
                    }
                }
            }
        }
    }, true);

    // Fallback standard submit listener
    document.addEventListener('submit', (e) => {
        if (e.target.closest('#vf-prompt-wrapper')) return;
        const form = e.target;
        const passwordInput = form.querySelector('input[type="password"]');
        if (!passwordInput) return;
        
        const data = captureInputs(passwordInput);
        if (data) {
            chrome.storage.local.set({ pending_save: data });
        }
    });

    // 2. Check for pending saves on page load
    chrome.storage.local.get(['pending_save', 'vault_email', 'ignored_hosts'], (result) => {
        const pending = result.pending_save;
        const ignored = result.ignored_hosts || [];
        const currentHost = window.location.hostname;
        
        if (ignored.includes(currentHost)) {
            chrome.storage.local.remove('pending_save');
            return;
        }
        
        if (pending && (Date.now() - pending.timestamp < 60000)) {
            chrome.storage.local.remove('pending_save');
            evaluateAndPrompt(pending, result.vault_email || '');
        }
    });

    // Evaluate duplicate state and prompt the user accordingly
    function evaluateAndPrompt(pending, defaultEmail) {
        chrome.storage.local.get(['ignored_hosts'], (res) => {
            const ignored = res.ignored_hosts || [];
            const currentHost = window.location.hostname;
            if (ignored.includes(currentHost)) {
                return;
            }
            
            chrome.runtime.sendMessage({ action: "check_session" }, (session) => {
                const loggedIn = session && session.loggedIn;
                const activeEmail = loggedIn ? session.email : defaultEmail;
                
                if (loggedIn) {
                    // If Vault is open, check duplicates
                    chrome.runtime.sendMessage({
                        action: "check_duplicate",
                        username: pending.username,
                        url: pending.url
                    }, (dup) => {
                        const exists = dup && dup.exists;
                        const isUpdate = exists && (dup.savedPassword !== pending.password);
                        
                        // Ignore prompt if credential exists with the same password
                        if (exists && !isUpdate) {
                            return;
                        }
                        
                        showSavePrompt(pending, activeEmail, loggedIn, exists, isUpdate, dup ? dup.itemId : null);
                    });
                } else {
                    // If Vault is closed, show prompt telling them to log in first
                    showSavePrompt(pending, activeEmail, false, false, false, null);
                }
            });
        });
    }

    // 3. Inject and show the float modal
    function showSavePrompt(pending, emailAddress, loggedIn, exists, isUpdate, itemId) {
        if (document.getElementById('vf-prompt-wrapper')) return;

        // Create style elements
        const style = document.createElement('style');
        style.innerHTML = `
            #vf-prompt-wrapper {
                position: fixed;
                top: 20px;
                right: 20px;
                width: 290px;
                background: rgba(255, 255, 255, 0.98);
                border: 1px solid rgba(11, 94, 40, 0.2);
                border-radius: 12px;
                box-shadow: 0 8px 30px rgba(0, 0, 0, 0.15);
                z-index: 2147483647;
                font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                color: #2D3748;
                padding: 12px 14px;
                backdrop-filter: blur(10px);
                transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
                animation: vfSlideIn 0.4s ease-out;
            }
            @keyframes vfSlideIn {
                from { transform: translateX(120%) scale(0.9); opacity: 0; }
                to { transform: translateX(0) scale(1); opacity: 1; }
            }
            .vf-header {
                display: flex;
                align-items: center;
                gap: 8px;
                margin-bottom: 8px;
                border-bottom: 1px solid rgba(0, 0, 0, 0.05);
                padding-bottom: 6px;
            }
            .vf-title {
                font-size: 13px;
                font-weight: 700;
                color: #0b5e28;
                margin: 0;
            }
            .vf-field-group {
                margin-bottom: 6px;
            }
            .vf-input {
                width: 100%;
                box-sizing: border-box;
                padding: 6px 10px;
                font-size: 12px;
                border: 1px solid #CBD5E0;
                border-radius: 6px;
                outline: none;
                background: #FFFFFF;
                color: #2D3748;
                transition: border 0.2s;
            }
            .vf-input:focus {
                border-color: #0b5e28;
            }
            .vf-footer {
                display: flex;
                gap: 6px;
                margin-top: 10px;
            }
            .vf-btn {
                flex: 1;
                padding: 6px 12px;
                font-size: 11px;
                font-weight: 600;
                border: none;
                border-radius: 6px;
                cursor: pointer;
                transition: all 0.2s;
                text-align: center;
            }
            .vf-btn-primary {
                background: #0b5e28;
                color: #FFFFFF;
            }
            .vf-btn-primary:hover {
                background: #08431c;
            }
            .vf-btn-secondary {
                background: #E2E8F0;
                color: #4A5568;
            }
            .vf-btn-secondary:hover {
                background: #CBD5E0;
            }
            .vf-toast-err {
                font-size: 10px;
                color: #E53E3E;
                margin-top: 4px;
                display: none;
                text-align: center;
                font-weight: 500;
            }
            .vf-success-check {
                display: none;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                gap: 6px;
                padding: 15px 0;
                color: #0b5e28;
                font-weight: 700;
                font-size: 13px;
            }
            .vf-badge-alert {
                font-size: 9px;
                background-color: #FEFCBF;
                color: #B7791F;
                border: 1px solid #F6E05E;
                padding: 3px 6px;
                border-radius: 4px;
                font-weight: 600;
                text-align: center;
                margin-bottom: 6px;
            }
            .vf-link-action {
                font-size: 10px;
                color: #718096;
                text-decoration: none;
                display: inline-block;
                margin-top: 6px;
            }
            .vf-link-action:hover {
                color: #0b5e28;
                text-decoration: underline;
            }
            .vf-hidden {
                display: none !important;
            }
        `;
        document.head.appendChild(style);

        const prompt = document.createElement('div');
        prompt.id = 'vf-prompt-wrapper';
        
        let titleText = isUpdate ? "Actualizar Contraseña" : "Guardar en VaultFiscalia";
        let badgeHtml = isUpdate ? `<div class="vf-badge-alert">🔑 Actualización disponible (Nueva clave)</div>` : '';
        
        prompt.innerHTML = `
            <div id="vf-prompt-form">
                <div class="vf-header">
                    <svg viewBox="0 0 24 24" width="16" height="16" style="display:block;">
                        <path fill="#0b5e28" d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.5a1.5 1.5 0 110-3 1.5 1.5 0 010 3z"/>
                    </svg>
                    <span class="vf-title">${titleText}</span>
                </div>
                ${badgeHtml}
                
                ${loggedIn ? `
                    <!-- STEP 1: Confirm save -->
                    <div id="vf-step-1">
                        <p style="font-size: 11px; color: #4A5568; margin: 0 0 10px 0; line-height: 1.4;">
                            ¿Guardar clave de <strong>${escapeHtml(pending.username)}</strong> en su bóveda?
                        </p>
                        <div class="vf-footer">
                            <button id="vf-btn-no" class="vf-btn vf-btn-secondary">Descartar</button>
                            <button id="vf-btn-next" class="vf-btn vf-btn-primary">Guardar</button>
                        </div>
                        <div style="text-align: center;">
                            <a href="#" id="vf-link-ignore" class="vf-link-action">No preguntar en este sitio</a>
                        </div>
                    </div>
                    
                    <!-- STEP 2: 2FA Confirmation (Hidden initially) -->
                    <div id="vf-step-2" class="vf-hidden">
                        <p style="font-size: 11px; color: #4A5568; margin: 0 0 8px 0; line-height: 1.3;">
                            Ingrese su código 2FA para confirmar:
                        </p>
                        <div class="vf-field-group">
                            <input type="text" id="vf-totp-code" class="vf-input" placeholder="000000" maxlength="6" style="text-align:center; font-size: 16px; letter-spacing: 4px; font-family: monospace;" autocomplete="one-time-code">
                        </div>
                        <div id="vf-err-box" class="vf-toast-err"></div>
                        <div class="vf-footer">
                            <button id="vf-btn-back" class="vf-btn vf-btn-secondary">Atrás</button>
                            <button id="vf-btn-yes" class="vf-btn vf-btn-primary">${isUpdate ? 'Actualizar' : 'Confirmar'}</button>
                        </div>
                    </div>
                ` : `
                    <!-- Vault is Closed -->
                    <p style="font-size: 11px; color: #4A5568; margin: 0 0 10px 0; line-height: 1.4;">
                        Sesión cerrada. Inicie sesión en la extensión para guardar la contraseña.
                    </p>
                    <div class="vf-footer">
                        <button id="vf-btn-no" class="vf-btn vf-btn-secondary">Descartar</button>
                        <button id="vf-btn-open-vault" class="vf-btn vf-btn-primary">Iniciar Vault</button>
                    </div>
                    <div style="text-align: center;">
                        <a href="#" id="vf-link-ignore" class="vf-link-action">No preguntar en este sitio</a>
                    </div>
                `}
            </div>
            <div id="vf-prompt-success" class="vf-success-check">
                <svg viewBox="0 0 24 24" width="30" height="30" style="display:block; margin-bottom: 4px;">
                    <circle cx="12" cy="12" r="10" fill="none" stroke="#0b5e28" stroke-width="2"/>
                    <path fill="none" stroke="#0b5e28" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" d="M8 12l3 3 5-6"/>
                </svg>
                <span>¡Guardado con éxito!</span>
            </div>
        `;
        document.body.appendChild(prompt);

        // --- TIMER AUTO-HIDE LOGIC ---
        let autoHideTimer = null;
        function startAutoHide() {
            autoHideTimer = setTimeout(() => {
                removePrompt();
            }, 5000); // Auto-hide after 5 seconds
        }
        function cancelAutoHide() {
            if (autoHideTimer) {
                clearTimeout(autoHideTimer);
                autoHideTimer = null;
            }
        }

        prompt.addEventListener('mouseenter', cancelAutoHide);
        prompt.addEventListener('mouseleave', () => {
            const step2 = document.getElementById('vf-step-2');
            // Only resume auto-hide if we are NOT on the 2FA step
            if (!step2 || step2.classList.contains('vf-hidden')) {
                startAutoHide();
            }
        });

        // Start countdown immediately on render
        startAutoHide();

        if (loggedIn) {
            // Step 1 -> Step 2
            document.getElementById('vf-btn-next').addEventListener('click', () => {
                cancelAutoHide(); // Cancel auto-hide forever once they interact
                document.getElementById('vf-step-1').classList.add('vf-hidden');
                const step2 = document.getElementById('vf-step-2');
                step2.classList.remove('vf-hidden');
                const codeField = document.getElementById('vf-totp-code');
                if (codeField) codeField.focus();
            });

            // Step 2 -> Step 1
            document.getElementById('vf-btn-back').addEventListener('click', () => {
                document.getElementById('vf-step-2').classList.add('vf-hidden');
                document.getElementById('vf-step-1').classList.remove('vf-hidden');
            });

            // Confirm save/update click
            document.getElementById('vf-btn-yes').addEventListener('click', () => {
                saveCredential();
            });

            // Listen for Enter key on inputs
            prompt.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    // Only save if step 2 is active
                    const step2 = document.getElementById('vf-step-2');
                    if (step2 && !step2.classList.contains('vf-hidden')) {
                        saveCredential();
                    } else {
                        // Trigger next step
                        document.getElementById('vf-btn-next').click();
                    }
                }
            });
        } else {
            document.getElementById('vf-btn-open-vault').addEventListener('click', () => {
                window.open(VAULT_WEB_URL, '_blank');
                removePrompt();
            });
        }

        // Close prompt click
        document.getElementById('vf-btn-no').addEventListener('click', () => {
            removePrompt();
        });

        // Ignore Host / Don't ask again click
        const ignoreLink = document.getElementById('vf-link-ignore');
        if (ignoreLink) {
            ignoreLink.addEventListener('click', (e) => {
                e.preventDefault();
                const currentHost = window.location.hostname;
                chrome.storage.local.get(['ignored_hosts'], (res) => {
                    const list = res.ignored_hosts || [];
                    if (!list.includes(currentHost)) {
                        list.push(currentHost);
                        chrome.storage.local.set({ ignored_hosts: list }, () => {
                            removePrompt();
                        });
                    } else {
                        removePrompt();
                    }
                });
            });
        }

        function removePrompt() {
            cancelAutoHide();
            prompt.style.transform = 'translateX(120%) scale(0.9)';
            prompt.style.opacity = '0';
            setTimeout(() => {
                prompt.remove();
                style.remove();
            }, 300);
        }

        function saveCredential() {
            const errBox = document.getElementById('vf-err-box');
            if (errBox) errBox.style.display = "none";
            
            const btnYes = document.getElementById('vf-btn-yes');
            const totpField = document.getElementById('vf-totp-code');
            const totpVal = totpField ? totpField.value.trim() : '';

            if (!totpVal) {
                if (errBox) {
                    errBox.textContent = "Ingrese el código de doble factor (2FA) para confirmar.";
                    errBox.style.display = "block";
                }
                return;
            }

            btnYes.setAttribute('disabled', 'true');
            btnYes.textContent = "Verificando...";

            chrome.runtime.sendMessage({
                action: "verify_and_save",
                totp_code: totpVal,
                name: pending.name,
                username: pending.username,
                cred_password: pending.password,
                url: pending.url,
                is_update: isUpdate,
                item_id: itemId
            }, (response) => {
                if (response && response.success) {
                    document.getElementById('vf-prompt-form').style.display = 'none';
                    document.getElementById('vf-prompt-success').style.display = 'flex';
                    setTimeout(() => {
                        removePrompt();
                    }, 2000);
                } else {
                    btnYes.removeAttribute('disabled');
                    btnYes.textContent = isUpdate ? 'Actualizar' : 'Confirmar';
                    if (errBox) {
                        errBox.textContent = (response && response.message) ? response.message : "Error al conectar con VaultFiscalia.";
                        errBox.style.display = "block";
                    }
                }
            });
        }
    }
})();
