// background.js - VaultFiscalia Chrome Extension Background Worker
const API_BASE = "http://127.0.0.1:5000";

// Helper to extract domain/hostname for comparison
function cleanHostname(urlStr) {
    try {
        const u = new URL(urlStr.startsWith('http') ? urlStr : 'http://' + urlStr);
        return u.hostname.replace('www.', '').toLowerCase();
    } catch (e) {
        return urlStr.replace('www.', '').toLowerCase();
    }
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "check_session") {
        chrome.storage.local.get(['vault_token', 'vault_email'], (result) => {
            if (result.vault_token) {
                sendResponse({ loggedIn: true, email: result.vault_email });
            } else {
                sendResponse({ loggedIn: false });
            }
        });
        return true;
    }
    
    if (request.action === "sync_session") {
        handleSyncSession(request.token)
            .then(res => sendResponse(res))
            .catch(() => sendResponse({ success: false }));
        return true;
    }
    
    if (request.action === "check_duplicate") {
        handleCheckDuplicate(request)
            .then(res => sendResponse(res))
            .catch(err => sendResponse({ exists: false, error: err.message }));
        return true;
    }

    if (request.action === "verify_and_save") {
        handleVerifyAndSave(request)
            .then(res => sendResponse({ success: true, message: res.message }))
            .catch(err => sendResponse({ success: false, message: err.message }));
        return true;
    }
});

async function handleSyncSession(pageToken) {
    const store = await chrome.storage.local.get(['vault_token']);
    
    if (!pageToken) {
        if (store.vault_token) {
            await chrome.storage.local.remove(['vault_token', 'vault_email']);
        }
        return { success: true, cleared: true };
    }
    
    if (store.vault_token === pageToken) {
        return { success: true, verified: true };
    }
    
    try {
        const response = await fetch(`${API_BASE}/api/auth/user-info`, {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${pageToken}` }
        });
        
        if (response.ok) {
            const data = await response.json();
            await chrome.storage.local.set({
                vault_token: pageToken,
                vault_email: data.email,
                last_activity_time: Date.now()
            });
            return { success: true, synced: true };
        } else {
            if (store.vault_token) {
                await chrome.storage.local.remove(['vault_token', 'vault_email']);
            }
            return { success: false };
        }
    } catch (e) {
        return { success: false, error: e.message };
    }
}

async function handleCheckDuplicate(data) {
    const { username, url } = data;
    
    const store = await chrome.storage.local.get(['vault_token']);
    if (!store.vault_token) {
        return { exists: false };
    }
    
    const response = await fetch(`${API_BASE}/api/vault`, {
        method: 'GET',
        headers: { 'Authorization': `Bearer ${store.vault_token}` }
    });
    
    if (!response.ok) {
        return { exists: false };
    }
    
    const items = await response.json();
    const targetHost = cleanHostname(url);
    
    // Find matching item
    const match = items.find(item => {
        const itemHost = cleanHostname(item.url || '');
        return (itemHost === targetHost || item.url.includes(targetHost) || targetHost.includes(itemHost)) &&
               item.username.toLowerCase() === username.toLowerCase();
    });
    
    if (match) {
        return { exists: true, itemId: match.id, savedPassword: match.password };
    }
    return { exists: false };
}

async function handleVerifyAndSave(data) {
    const { 
        totp_code,
        name, username, cred_password, url, 
        is_update, item_id 
    } = data;
    
    const store = await chrome.storage.local.get(['vault_token']);
    if (!store.vault_token) {
        throw new Error('Su sesión de Vault no está activa. Inicie sesión en la extensión primero.');
    }
    
    const jwtToken = store.vault_token;
    
    // 1. Verify TOTP code for active session
    const verifyRes = await fetch(`${API_BASE}/api/auth/verify-totp`, {
        method: 'POST',
        headers: { 
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${jwtToken}`
        },
        body: JSON.stringify({ code: totp_code })
    });
    
    const verifyData = await verifyRes.json();
    if (!verifyRes.ok) {
        if (verifyRes.status === 401 || verifyRes.status === 403) {
            await chrome.storage.local.remove(['vault_token', 'vault_email']);
            throw new Error('Su sesión de Vault expiró. Inicie sesión nuevamente en la extensión.');
        }
        throw new Error(verifyData.message || 'Código de Doble Factor incorrecto.');
    }
    
    // 2. Save or Update Credential
    let saveRes;
    if (is_update && item_id) {
        // PUT update
        saveRes = await fetch(`${API_BASE}/api/vault/${item_id}`, {
            method: 'PUT',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${jwtToken}`
            },
            body: JSON.stringify({ 
                name, 
                username, 
                password: cred_password, 
                url, 
                notes: 'Actualizado automáticamente vía Extensión de Chrome.' 
            })
        });
    } else {
        // POST create new
        saveRes = await fetch(`${API_BASE}/api/vault`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${jwtToken}`
            },
            body: JSON.stringify({ 
                name, 
                username, 
                password: cred_password, 
                url, 
                notes: 'Guardado automáticamente vía Extensión de Chrome.' 
            })
        });
    }
    
    const saveData = await saveRes.json();
    if (!saveRes.ok) {
        throw new Error(saveData.message || 'Error al guardar la credencial en la Bóveda.');
    }
    
    return { message: 'Operación realizada con éxito.' };
}
