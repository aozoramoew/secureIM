/**
 * auth.js — Registration, Login, and 2FA UI Logic
 */

const API = '/api/auth';

// ── Device Identity ─────────────────────────────────────────────

function getOrCreateDeviceId() {
  let id = SecureStorage.getDeviceId();
  if (!id) {
    id = crypto.randomUUID();
    SecureStorage.saveDeviceId(id);
  }
  return id;
}

function getDeviceName() {
  const ua = navigator.userAgent;
  if (/iPhone|iPad/.test(ua)) return 'Safari on iOS';
  if (/Android/.test(ua)) return 'Chrome on Android';
  if (/Firefox/.test(ua)) return 'Firefox';
  if (/Edg/.test(ua)) return 'Edge';
  if (/Chrome/.test(ua)) return 'Chrome';
  if (/Safari/.test(ua)) return 'Safari';
  return 'Browser';
}

// ── UI Helpers ──────────────────────────────────────────────────

function setStatus(elementId, message, type = 'info') {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.textContent = message;
  el.className = `status-msg status-${type}`;
  el.style.display = message ? 'block' : 'none';
}

function setLoading(btnId, loading, defaultText = 'Submit') {
  const btn = document.getElementById(btnId);
  if (!btn) return;
  btn.disabled = loading;
  btn.textContent = loading ? 'Please wait…' : defaultText;
}

// ── Registration ────────────────────────────────────────────────

async function handleRegister(e) {
  e.preventDefault();
  const username = document.getElementById('reg-username').value.trim();
  const email    = document.getElementById('reg-email').value.trim();
  const password = document.getElementById('reg-password').value;
  const confirm  = document.getElementById('reg-confirm').value;

  if (password !== confirm) {
    return setStatus('reg-status', 'Passwords do not match.', 'error');
  }
  if (password.length < 8) {
    return setStatus('reg-status', 'Password must be at least 8 characters.', 'error');
  }

  setLoading('reg-btn', true, 'Create Account');
  setStatus('reg-status', '🔑 Generating your cryptographic identity keys…', 'info');

  try {
    // 1. Generate identity key pairs on-device
    const identityKP  = await SecureCrypto.generateIdentityKeyPair();   // ECDSA P-384
    const ecdhKP      = await SecureCrypto.generateEphemeralKeyPair();   // ECDH P-256 (static)

    const ecdsaPubJwk = await SecureCrypto.exportKeyJWK(identityKP.publicKey);
    const ecdhPubJwk  = await SecureCrypto.exportKeyJWK(ecdhKP.publicKey);
    const ecdsaPrivJwk= await SecureCrypto.exportKeyJWK(identityKP.privateKey);
    const ecdhPrivJwk = await SecureCrypto.exportKeyJWK(ecdhKP.privateKey);

    const deviceId   = getOrCreateDeviceId();
    const deviceName = getDeviceName();

    setStatus('reg-status', '🔒 Encrypting private keys with your password…', 'info');

    // 2. Encrypt private keys with password — never sent to server
    await SecureStorage.saveIdentityKeys(password, ecdsaPrivJwk, ecdhPrivJwk);

    setStatus('reg-status', '📡 Registering with server…', 'info');

    // 3. Send public keys + credentials to server
    const res = await fetch(`${API}/register`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        email,
        password,
        ecdsa_public_key: ecdsaPubJwk,
        ecdh_public_key:  ecdhPubJwk,
        device_id:        deviceId,
        device_name:      deviceName,
      }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Registration failed');

    // Store email for resend flow
    sessionStorage.setItem('pending_verify_email', email);

    setStatus('reg-status', '✅ ' + data.message, 'success');

    // Show dev email link button if available (dev mode only)
    await checkAndShowDevLink('reg-status');

    setTimeout(() => { window.location.href = '/login?registered=1'; }, 3000);

  } catch (err) {
    setStatus('reg-status', '❌ ' + err.message, 'error');
  } finally {
    setLoading('reg-btn', false, 'Create Account');
  }
}

// ── Login ────────────────────────────────────────────────────────

let _2faPollInterval = null;

async function handleLogin(e) {
  e.preventDefault();
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;

  setLoading('login-btn', true, 'Sign In');
  setStatus('login-status', '🔑 Loading your identity keys…', 'info');

  try {
    let ecdsaPubJwk = null;
    let ecdhPubJwk  = null;
    const hasKeys = SecureStorage.hasIdentityKeys();

    if (hasKeys) {
      // Decrypt stored private keys and re-derive public keys
      const keys = await SecureStorage.loadIdentityKeys(password);
      if (!keys) {
        throw new Error('Wrong password or keys not found on this device.');
      }

      // Import private keys and re-export the public JWK from them
      try {
        const ecdsaPrivKey = await crypto.subtle.importKey(
          'jwk', JSON.parse(keys.ecdsaPrivJwk),
          { name: 'ECDSA', namedCurve: 'P-384' },
          true, ['sign']
        );
        const ecdhPrivKey = await crypto.subtle.importKey(
          'jwk', JSON.parse(keys.ecdhPrivJwk),
          { name: 'ECDH', namedCurve: 'P-256' },
          true, ['deriveKey', 'deriveBits']
        );

        // Extract public key from private key
        const ecdsaPubKey = await crypto.subtle.exportKey('jwk', ecdsaPrivKey);
        const ecdhPubKey  = await crypto.subtle.exportKey('jwk', ecdhPrivKey);

        // Build public-only JWK (remove private 'd' field)
        const ecdsaPubOnly = { ...ecdsaPubKey };
        delete ecdsaPubOnly.d;
        delete ecdsaPubOnly.key_ops;
        ecdsaPubOnly.key_ops = ['verify'];

        const ecdhPubOnly = { ...ecdhPubKey };
        delete ecdhPubOnly.d;
        delete ecdhPubOnly.key_ops;
        ecdhPubOnly.key_ops = [];

        ecdsaPubJwk = JSON.stringify(ecdsaPubOnly);
        ecdhPubJwk  = JSON.stringify(ecdhPubOnly);
      } catch (keyErr) {
        // If key extraction fails, regenerate keys for this device
        console.warn('Key extraction failed, regenerating:', keyErr);
        ecdsaPubJwk = null;
        ecdhPubJwk  = null;
      }
    }

    // If this is a fresh device (no stored keys), generate new ones
    if (!hasKeys || (!ecdsaPubJwk && !ecdhPubJwk)) {
      setStatus('login-status', '🔑 Generating device keys for new device…', 'info');
      const identityKP = await SecureCrypto.generateIdentityKeyPair();
      const ecdhKP     = await SecureCrypto.generateEphemeralKeyPair();

      ecdsaPubJwk = await SecureCrypto.exportKeyJWK(identityKP.publicKey);
      ecdhPubJwk  = await SecureCrypto.exportKeyJWK(ecdhKP.publicKey);
      const ecdsaPrivJwk = await SecureCrypto.exportKeyJWK(identityKP.privateKey);
      const ecdhPrivJwk  = await SecureCrypto.exportKeyJWK(ecdhKP.privateKey);
      await SecureStorage.saveIdentityKeys(password, ecdsaPrivJwk, ecdhPrivJwk);
    }

    const deviceId   = getOrCreateDeviceId();
    const deviceName = getDeviceName();

    setStatus('login-status', '📡 Authenticating…', 'info');

    const res = await fetch(`${API}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username, password,
        device_id:        deviceId,
        device_name:      deviceName,
        ecdsa_public_key: ecdsaPubJwk,
        ecdh_public_key:  ecdhPubJwk,
      }),
    });

    const data = await res.json();

    if (res.status === 200 && data.status === 'ok') {
      // Known device — direct login
      SecureStorage.saveAuthToken(data.token);
      SecureStorage.saveUser(data.user);
      SecureStorage.saveSettings(data.user.settings || {});
      window.location.href = '/chat';

    } else if (res.status === 202 && data.status === '2fa_required') {
      // New device — show 2FA waiting screen
      show2FAWaiting(deviceId);

    } else if (res.status === 403 && data.error && data.error.includes('verify your email')) {
      // Email not verified — show resend option
      showResendVerification(username);

    } else {
      throw new Error(data.error || 'Login failed');
    }

  } catch (err) {
    setStatus('login-status', '❌ ' + err.message, 'error');
    setLoading('login-btn', false, 'Sign In');
  }
}

function show2FAWaiting(deviceId) {
  const form = document.getElementById('login-form');
  if (form) form.style.display = 'none';

  const waiting = document.getElementById('2fa-waiting');
  if (waiting) waiting.style.display = 'flex';

  setStatus('login-status', '📧 Check your email and click the authorization link.', 'info');

  // Poll for authorization every 3 seconds
  _2faPollInterval = setInterval(async () => {
    try {
      const res  = await fetch(`${API}/2fa-status?device_id=${deviceId}`);
      const data = await res.json();
      if (data.status === 'authorized') {
        clearInterval(_2faPollInterval);
        SecureStorage.saveAuthToken(data.token);
        SecureStorage.saveUser(data.user);
        SecureStorage.saveSettings(data.user.settings || {});
        window.location.href = '/chat';
      }
    } catch { /* ignore network errors during polling */ }
  }, 3000);
}

// ── Resend Verification Email ────────────────────────────────────

function showResendVerification(username) {
  const resendSection = document.getElementById('resend-verification');
  if (resendSection) {
    resendSection.style.display = 'flex';
    // Pre-fill with username hint
    const emailInput = document.getElementById('resend-email');
    if (emailInput) emailInput.focus();
  }
  setStatus('login-status', '⚠️ Your email is not verified yet. Please check your inbox or request a new link below.', 'error');
  setLoading('login-btn', false, 'Sign In');
}

async function handleResendVerification(e) {
  e.preventDefault();
  const email = document.getElementById('resend-email').value.trim();
  if (!email) {
    return setStatus('resend-status', 'Please enter your email address.', 'error');
  }

  const btn = document.getElementById('resend-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Sending…'; }
  setStatus('resend-status', '📡 Sending verification email…', 'info');

  try {
    const res  = await fetch(`${API}/resend-verification`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ email }),
    });
    const data = await res.json();

    if (!res.ok) {
      setStatus('resend-status', '❌ ' + (data.error || 'Failed to send email'), 'error');
    } else {
      setStatus('resend-status', '✅ ' + data.message, 'success');
      // Show dev link if in dev mode
      await checkAndShowDevLink('resend-status');
      if (btn) { btn.textContent = 'Sent!'; }
    }
  } catch (err) {
    setStatus('resend-status', '❌ Network error. Please try again.', 'error');
  } finally {
    setTimeout(() => {
      if (btn) { btn.disabled = false; btn.textContent = 'Resend Email'; }
    }, 5000);
  }
}

// ── Dev Mode: Show Email Links ───────────────────────────────────

async function checkAndShowDevLink(nearElementId) {
  try {
    const res  = await fetch(`${API}/dev-links`);
    if (!res.ok) return;  // Not in dev mode
    const data = await res.json();
    if (data.links && data.links.length > 0) {
      const latest = data.links[0];
      showDevEmailModal(latest);
    }
  } catch { /* production — dev-links not available */ }
}

function showDevEmailModal(entry) {
  // Remove existing modal if any
  const old = document.getElementById('dev-email-modal');
  if (old) old.remove();

  const modal = document.createElement('div');
  modal.id = 'dev-email-modal';
  modal.style.cssText = `
    position: fixed; top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.85); z-index: 9999;
    display: flex; align-items: center; justify-content: center;
    padding: 20px; box-sizing: border-box;
  `;

  modal.innerHTML = `
    <div style="
      background: #111827; border: 2px solid #00d4ff; border-radius: 16px;
      padding: 32px; max-width: 560px; width: 100%; box-shadow: 0 0 40px rgba(0,212,255,0.3);
      font-family: sans-serif; color: #e2e8f0; box-sizing: border-box;
    ">
      <div style="display:flex; align-items:center; gap:12px; margin-bottom:20px;">
        <span style="font-size:28px;">🛠️</span>
        <div>
          <h2 style="margin:0; color:#00d4ff; font-size:18px;">Dev Mode — Email Suppressed</h2>
          <p style="margin:4px 0 0; color:#64748b; font-size:13px;">
            MAIL_SUPPRESS_SEND=true · Email was not actually sent
          </p>
        </div>
      </div>
      <div style="background:#0a0e1a; border-radius:8px; padding:16px; margin-bottom:16px;">
        <p style="margin:0 0 4px; font-size:12px; color:#64748b;">To: <span style="color:#e2e8f0;">${entry.to}</span></p>
        <p style="margin:0 0 12px; font-size:12px; color:#64748b;">Subject: <span style="color:#e2e8f0;">${entry.subject}</span></p>
        <p style="margin:0 0 8px; font-size:12px; color:#94a3b8;">Click the link below to complete the action:</p>
        <a href="${entry.link}" target="_blank" style="
          display: block; word-break: break-all; font-size: 13px;
          color: #00d4ff; text-decoration: underline; line-height: 1.5;
        ">${entry.link}</a>
      </div>
      <div style="display:flex; gap:12px; flex-wrap:wrap;">
        <a href="${entry.link}" target="_blank" style="
          display: inline-flex; align-items: center; gap: 8px;
          padding: 10px 20px; background: #00d4ff; color: #0a0e1a;
          border-radius: 8px; text-decoration: none; font-weight: 700; font-size: 14px;
        ">✅ Open Link</a>
        <button onclick="
          navigator.clipboard.writeText('${entry.link}');
          this.textContent = '✓ Copied!';
          setTimeout(() => this.textContent = '📋 Copy Link', 1500);
        " style="
          padding: 10px 20px; background: #1e293b; color: #e2e8f0;
          border: 1px solid #334155; border-radius: 8px; cursor: pointer;
          font-size: 14px;
        ">📋 Copy Link</button>
        <button onclick="
          fetch('/api/auth/dev-links').then(r => r.json()).then(d => showAllDevLinks(d.links));
        " style="
          padding: 10px 20px; background: #1e293b; color: #94a3b8;
          border: 1px solid #334155; border-radius: 8px; cursor: pointer;
          font-size: 14px;
        ">📬 All Dev Links</button>
        <button onclick="document.getElementById('dev-email-modal').remove();" style="
          padding: 10px 20px; background: transparent; color: #64748b;
          border: 1px solid #334155; border-radius: 8px; cursor: pointer;
          font-size: 14px; margin-left: auto;
        ">✕ Close</button>
      </div>
    </div>
  `;

  modal.addEventListener('click', (e) => {
    if (e.target === modal) modal.remove();
  });

  document.body.appendChild(modal);
}

function showAllDevLinks(links) {
  const old = document.getElementById('dev-email-modal');
  if (old) old.remove();

  const modal = document.createElement('div');
  modal.id = 'dev-email-modal';
  modal.style.cssText = `
    position: fixed; top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.85); z-index: 9999;
    display: flex; align-items: center; justify-content: center;
    padding: 20px; box-sizing: border-box; overflow-y: auto;
  `;

  const rows = links.map((entry, i) => `
    <div style="background:#0a0e1a; border-radius:8px; padding:16px; margin-bottom:12px;">
      <div style="display:flex; justify-content:space-between; align-items:start; flex-wrap:wrap; gap:8px; margin-bottom:8px;">
        <div>
          <span style="font-size:11px; color:#64748b;">To: ${entry.to}</span><br>
          <span style="font-size:11px; color:#64748b;">${entry.subject}</span>
        </div>
        <a href="${entry.link}" target="_blank" style="
          padding: 6px 14px; background: #00d4ff; color: #0a0e1a;
          border-radius: 6px; text-decoration: none; font-weight: 700; font-size: 12px; white-space: nowrap;
        ">Open →</a>
      </div>
      <div style="font-size:12px; color:#00d4ff; word-break:break-all; line-height:1.5;">${entry.link}</div>
    </div>
  `).join('');

  modal.innerHTML = `
    <div style="
      background: #111827; border: 2px solid #00d4ff; border-radius: 16px;
      padding: 32px; max-width: 640px; width: 100%; box-shadow: 0 0 40px rgba(0,212,255,0.3);
      font-family: sans-serif; color: #e2e8f0; box-sizing: border-box; max-height: 90vh; overflow-y: auto;
    ">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:24px;">
        <h2 style="margin:0; color:#00d4ff; font-size:18px;">🛠️ Dev Email Links (Last ${links.length})</h2>
        <button onclick="document.getElementById('dev-email-modal').remove();" style="
          background: transparent; border: 1px solid #334155; color: #64748b;
          padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 13px;
        ">✕ Close</button>
      </div>
      ${links.length === 0 ? '<p style="color:#64748b; text-align:center;">No emails suppressed yet.</p>' : rows}
    </div>
  `;

  modal.addEventListener('click', (e) => {
    if (e.target === modal) modal.remove();
  });

  document.body.appendChild(modal);
}

// ── Cancel 2FA ───────────────────────────────────────────────────

function cancel2FA() {
  if (_2faPollInterval) clearInterval(_2faPollInterval);
  const form = document.getElementById('login-form');
  const waiting = document.getElementById('2fa-waiting');
  if (form) form.style.display = 'block';
  if (waiting) waiting.style.display = 'none';
  setStatus('login-status', '', 'info');
  setLoading('login-btn', false, 'Sign In');
}

// ── Dev Link button on demand ────────────────────────────────────

async function openDevLinks() {
  try {
    const res  = await fetch(`${API}/dev-links`);
    if (!res.ok) {
      alert('Dev links are only available in development mode (MAIL_SUPPRESS_SEND=true).');
      return;
    }
    const data = await res.json();
    showAllDevLinks(data.links || []);
  } catch {
    alert('Could not fetch dev links.');
  }
}

// ── Page Init ───────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  // Redirect to chat if already logged in
  if (SecureStorage.getAuthToken() && SecureStorage.getUser()) {
    if (window.location.pathname === '/login' || window.location.pathname === '/register') {
      window.location.href = '/chat';
    }
  }

  const regForm   = document.getElementById('register-form');
  const loginForm = document.getElementById('login-form');

  if (regForm)   regForm.addEventListener('submit', handleRegister);
  if (loginForm) loginForm.addEventListener('submit', handleLogin);

  const cancelBtn = document.getElementById('cancel-2fa-btn');
  if (cancelBtn) cancelBtn.addEventListener('click', cancel2FA);

  // Resend verification form
  const resendForm = document.getElementById('resend-verification-form');
  if (resendForm) resendForm.addEventListener('submit', handleResendVerification);

  // Dev links button
  const devLinksBtn = document.getElementById('dev-links-btn');
  if (devLinksBtn) devLinksBtn.addEventListener('click', openDevLinks);

  // Show query string messages
  const params = new URLSearchParams(window.location.search);
  if (params.get('verified') === '1') {
    setStatus('login-status', '✅ Email verified! You can now sign in.', 'success');
  }
  if (params.get('registered') === '1') {
    setStatus('login-status', '📧 Registration successful! Check your email to verify your account before signing in.', 'success');
    // Show resend option immediately after registration
    const resendSection = document.getElementById('resend-verification');
    if (resendSection) resendSection.style.display = 'flex';

    // In dev mode, auto-show the email link modal
    setTimeout(() => checkAndShowDevLink('login-status'), 500);
  }
  if (params.get('error') === 'invalid_or_expired_link') {
    setStatus('login-status', '❌ That verification link is invalid or has expired. Please request a new one below.', 'error');
    const resendSection = document.getElementById('resend-verification');
    if (resendSection) resendSection.style.display = 'flex';
  }
});
