/**
 * auth.js — Registration, Login, and 2FA UI Logic
 * Updated for FastAPI backend + real email verification flow.
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

function setBtnLoading(btnId, loading, defaultText = 'Submit') {
  const btn = document.getElementById(btnId);
  if (!btn) return;
  btn.disabled = loading;
  const spinner = btn.querySelector('.spinner');
  const text    = btn.querySelector('.btn-text');
  if (spinner) spinner.style.display = loading ? 'block' : 'none';
  if (text)    text.textContent = loading ? 'Please wait…' : defaultText;
  if (loading) btn.classList.add('loading');
  else btn.classList.remove('loading');
}

// Password strength
function updateStrengthBar(password) {
  const bar = document.getElementById('strength-bar');
  if (!bar) return;
  let score = 0;
  if (password.length >= 8)  score++;
  if (password.length >= 12) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;
  const pct = (score / 5) * 100;
  const colors = ['#ef4444','#f97316','#eab308','#22c55e','#00d4ff'];
  bar.style.width  = pct + '%';
  bar.style.background = colors[score - 1] || '#334155';
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

  setBtnLoading('reg-btn', true, 'Create Account');
  setStatus('reg-status', '🔑 Generating cryptographic identity keys…', 'info');

  try {
    // 1. Generate identity key pairs on-device
    const identityKP  = await SecureCrypto.generateIdentityKeyPair();   // ECDSA P-384
    const ecdhKP      = await SecureCrypto.generateEphemeralKeyPair();   // ECDH P-256

    const ecdsaPubJwk  = await SecureCrypto.exportKeyJWK(identityKP.publicKey);
    const ecdhPubJwk   = await SecureCrypto.exportKeyJWK(ecdhKP.publicKey);
    const ecdsaPrivJwk = await SecureCrypto.exportKeyJWK(identityKP.privateKey);
    const ecdhPrivJwk  = await SecureCrypto.exportKeyJWK(ecdhKP.privateKey);

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
        username, email, password,
        ecdsa_public_key: ecdsaPubJwk,
        ecdh_public_key:  ecdhPubJwk,
        device_id:        deviceId,
        device_name:      deviceName,
      }),
    });

    let data = {};
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      data = await res.json();
    } else {
      await res.text();
      throw new Error(`Server error (HTTP ${res.status}). Check server logs.`);
    }

    if (!res.ok) {
      throw new Error(data.detail || data.error || 'Registration failed');
    }

    // ── Email verification required ────────────────────────────
    // Server returns {status:'verification_sent', email:'...'}
    // Show "check your email" panel on THIS page (register.html)
    if (data.status === 'verification_sent') {
      showEmailCheckPanel(data.email || email);
      // In dev mode, auto-show the dev link modal
      await checkAndShowDevLink('reg-status');
    } else {
      setStatus('reg-status', '✅ ' + (data.message || 'Done!'), 'success');
    }

  } catch (err) {
    setStatus('reg-status', '❌ ' + err.message, 'error');
  } finally {
    setBtnLoading('reg-btn', false, 'Create Account');
  }
}

function showEmailCheckPanel(email) {
  const formWrap = document.getElementById('register-form-wrap');
  const panel    = document.getElementById('email-check-panel');
  const emailDisplay = document.getElementById('reg-email-display');

  if (formWrap) formWrap.style.display = 'none';
  if (panel)    panel.style.display    = 'block';
  if (emailDisplay) emailDisplay.textContent = email;

  // Pre-fill resend email input
  const resendInput = document.getElementById('resend-email');
  if (resendInput) resendInput.value = email;
}

// ── Login ────────────────────────────────────────────────────────

let _2faPollInterval = null;

async function handleLogin(e) {
  e.preventDefault();
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;

  setBtnLoading('login-btn', true, 'Sign In');
  setStatus('login-status', '🔑 Loading your identity keys…', 'info');

  try {
    let ecdsaPubJwk = null;
    let ecdhPubJwk  = null;
    const hasKeys   = SecureStorage.hasIdentityKeys();

    if (hasKeys) {
      const keys = await SecureStorage.loadIdentityKeys(password);
      if (!keys) {
        throw new Error('Wrong password or keys not found on this device.');
      }
      try {
        const ecdsaPrivKey = await crypto.subtle.importKey(
          'jwk', JSON.parse(keys.ecdsaPrivJwk),
          { name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign']
        );
        const ecdhPrivKey = await crypto.subtle.importKey(
          'jwk', JSON.parse(keys.ecdhPrivJwk),
          { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
        );
        const ecdsaPubKey = await crypto.subtle.exportKey('jwk', ecdsaPrivKey);
        const ecdhPubKey  = await crypto.subtle.exportKey('jwk', ecdhPrivKey);

        const ecdsaPubOnly = { ...ecdsaPubKey };
        delete ecdsaPubOnly.d; delete ecdsaPubOnly.key_ops;
        ecdsaPubOnly.key_ops = ['verify'];

        const ecdhPubOnly = { ...ecdhPubKey };
        delete ecdhPubOnly.d; delete ecdhPubOnly.key_ops;
        ecdhPubOnly.key_ops = [];

        ecdsaPubJwk = JSON.stringify(ecdsaPubOnly);
        ecdhPubJwk  = JSON.stringify(ecdhPubOnly);
      } catch (keyErr) {
        console.warn('Key extraction failed, regenerating:', keyErr);
        ecdsaPubJwk = null; ecdhPubJwk = null;
      }
    }

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
        username, password, device_id: deviceId, device_name: deviceName,
        ecdsa_public_key: ecdsaPubJwk, ecdh_public_key: ecdhPubJwk,
      }),
    });

    let data = {};
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      data = await res.json();
    } else {
      await res.text();
      throw new Error(`Server error (HTTP ${res.status}). Check server logs.`);
    }

    if (res.status === 200 && data.status === 'ok') {
      // Known device — direct login
      SecureStorage.saveAuthToken(data.token);
      SecureStorage.saveUser(data.user);
      SecureStorage.saveSettings(data.user.settings || {});
      window.location.href = '/chat';

    } else if ((res.status === 202 || res.status === 200) && data.status === '2fa_required') {
      // New device — show 2FA waiting screen + dev link if available
      show2FAWaiting(deviceId);
      await checkAndShowDevLink('login-status');

    } else if (res.status === 403) {
      // Email not verified
      const errorCode = res.headers.get('X-Error-Code') || '';
      if (errorCode === 'email_not_verified' || (data.detail || '').toLowerCase().includes('not verified')) {
        showResendSection();
        setStatus('login-status',
          '⚠️ Your email is not verified. Check your inbox or request a new link below.',
          'warning');
      } else {
        throw new Error(data.detail || 'Access denied');
      }
      setBtnLoading('login-btn', false, 'Sign In');

    } else {
      throw new Error(data.detail || data.error || 'Login failed');
    }

  } catch (err) {
    setStatus('login-status', '❌ ' + err.message, 'error');
    setBtnLoading('login-btn', false, 'Sign In');
  }
}

function show2FAWaiting(deviceId) {
  const formWrap = document.getElementById('login-form-wrap');
  const waiting  = document.getElementById('two-fa-waiting');
  if (formWrap) formWrap.style.display = 'none';
  if (waiting)  waiting.style.display  = 'block';

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

function cancel2FA() {
  if (_2faPollInterval) clearInterval(_2faPollInterval);
  const formWrap = document.getElementById('login-form-wrap');
  const waiting  = document.getElementById('two-fa-waiting');
  if (formWrap) formWrap.style.display = 'block';
  if (waiting)  waiting.style.display  = 'none';
  setStatus('login-status', '', 'info');
  setBtnLoading('login-btn', false, 'Sign In');
}

function showResendSection() {
  const section = document.getElementById('resend-section');
  if (section) section.classList.add('visible');
}

// ── Resend Verification Email ────────────────────────────────────

async function handleResendVerification(e) {
  e.preventDefault();
  const email = document.getElementById('resend-email').value.trim();
  if (!email) {
    return setStatus('resend-status', 'Please enter your email address.', 'error');
  }

  const btn = document.getElementById('resend-btn');
  if (btn) { btn.disabled = true; btn.querySelector('.btn-text').textContent = 'Sending…'; }
  setStatus('resend-status', '📡 Sending verification email…', 'info');

  try {
    const res  = await fetch(`${API}/resend-verification`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ email }),
    });
    const data = await res.json();

    if (!res.ok) {
      setStatus('resend-status', '❌ ' + (data.detail || data.error || 'Failed to send'), 'error');
    } else {
      setStatus('resend-status', '✅ ' + data.message, 'success');
      // In dev mode, auto-show the dev link modal
      await checkAndShowDevLink('resend-status');
    }
  } catch {
    setStatus('resend-status', '❌ Network error. Please try again.', 'error');
  } finally {
    setTimeout(() => {
      if (btn) {
        btn.disabled = false;
        btn.querySelector('.btn-text').textContent = 'Resend Verification Email';
      }
    }, 5000);
  }
}

// ── Dev Mode: Show Email Links ───────────────────────────────────

async function checkAndShowDevLink(nearElementId) {
  try {
    const res = await fetch(`${API}/dev-links`);
    if (!res.ok) return;  // Not in dev mode
    const data = await res.json();
    if (data.links && data.links.length > 0) {
      showDevEmailModal(data.links[0]);
    }
  } catch { /* production — dev-links not available */ }
}

function showDevEmailModal(entry) {
  const old = document.getElementById('dev-email-modal');
  if (old) old.remove();

  const modal = document.createElement('div');
  modal.id = 'dev-email-modal';
  modal.className = 'dev-modal-backdrop';

  modal.innerHTML = `
    <div class="dev-modal">
      <div class="dev-modal-header">
        <span style="font-size:24px;">🛠️</span>
        <div>
          <h2>Dev Mode — Email Suppressed</h2>
          <p style="color:var(--text-3);font-size:12px;margin:2px 0 0;">
            MAIL_SUPPRESS_SEND=true · Email was not actually sent
          </p>
        </div>
      </div>
      <div class="dev-link-box">
        <p style="margin:0 0 4px;font-size:12px;color:var(--text-3);">To: <strong style="color:var(--text);">${entry.to}</strong></p>
        <p style="margin:0 0 10px;font-size:12px;color:var(--text-3);">Subject: ${entry.subject}</p>
        <p style="margin:0 0 8px;font-size:12px;color:var(--text-2);">Click the link to complete the action:</p>
        <a href="${entry.link}" target="_blank">${entry.link}</a>
      </div>
      <div class="dev-modal-actions">
        <a href="${entry.link}" target="_blank" class="btn btn-primary btn-sm"
           style="width:auto;text-decoration:none;">✅ Open Link</a>
        <button id="dev-copy-btn" class="btn btn-secondary btn-sm" style="width:auto;"
          onclick="navigator.clipboard.writeText('${entry.link}');this.textContent='✓ Copied!';setTimeout(()=>this.textContent='📋 Copy',1500);">
          📋 Copy
        </button>
        <button class="btn btn-ghost btn-sm" style="width:auto;"
          onclick="openDevLinks();">
          📬 All links
        </button>
        <button class="btn btn-ghost btn-sm" style="width:auto; margin-left:auto;"
          onclick="document.getElementById('dev-email-modal').remove();">
          ✕ Close
        </button>
      </div>
    </div>
  `;

  modal.addEventListener('click', (e) => { if (e.target === modal) modal.remove(); });
  document.body.appendChild(modal);
}

async function openDevLinks() {
  try {
    const res  = await fetch(`${API}/dev-links`);
    if (!res.ok) {
      alert('Dev links only available with MAIL_SUPPRESS_SEND=true.');
      return;
    }
    const data = await res.json();
    const old  = document.getElementById('dev-email-modal');
    if (old) old.remove();

    const modal = document.createElement('div');
    modal.id = 'dev-email-modal';
    modal.className = 'dev-modal-backdrop';

    const links = data.links || [];
    const rows  = links.map(entry => `
      <div class="dev-link-box" style="margin-bottom:10px;">
        <div style="display:flex;justify-content:space-between;align-items:start;flex-wrap:wrap;gap:8px;margin-bottom:8px;">
          <div>
            <span style="font-size:11px;color:var(--text-3);">To: ${entry.to}</span><br>
            <span style="font-size:11px;color:var(--text-3);">${entry.subject}</span>
          </div>
          <a href="${entry.link}" target="_blank"
             style="padding:5px 12px;background:var(--cyan);color:#0a0e1a;
                    border-radius:6px;text-decoration:none;font-weight:700;font-size:12px;white-space:nowrap;">
            Open →
          </a>
        </div>
        <a href="${entry.link}" target="_blank"
           style="font-size:12px;color:var(--cyan);word-break:break-all;line-height:1.5;">
          ${entry.link}
        </a>
      </div>
    `).join('');

    modal.innerHTML = `
      <div class="dev-modal" style="max-width:640px;">
        <div class="dev-modal-header">
          <h2>🛠️ Dev Email Links (${links.length})</h2>
          <button onclick="document.getElementById('dev-email-modal').remove();"
                  class="btn btn-ghost btn-sm" style="width:auto;">✕ Close</button>
        </div>
        <div style="max-height:60vh;overflow-y:auto;">
          ${links.length === 0
            ? '<p style="color:var(--text-3);text-align:center;padding:20px;">No emails suppressed yet.</p>'
            : rows}
        </div>
      </div>
    `;
    modal.addEventListener('click', (e) => { if (e.target === modal) modal.remove(); });
    document.body.appendChild(modal);
  } catch {
    alert('Could not fetch dev links.');
  }
}

// ── Page Init ───────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  // Redirect to chat if already logged in
  if (SecureStorage.getAuthToken() && SecureStorage.getUser()) {
    const path = window.location.pathname;
    if (path === '/login' || path === '/register') {
      window.location.href = '/chat';
      return;
    }
  }

  // ── Register page ──────────────────────────────────────────
  const regForm = document.getElementById('register-form');
  if (regForm) regForm.addEventListener('submit', handleRegister);

  // Password strength meter
  const pwInput = document.getElementById('reg-password');
  if (pwInput) pwInput.addEventListener('input', () => updateStrengthBar(pwInput.value));

  // ── Login page ─────────────────────────────────────────────
  const loginForm = document.getElementById('login-form');
  if (loginForm) loginForm.addEventListener('submit', handleLogin);

  // Cancel 2FA
  const cancelBtn = document.getElementById('cancel-2fa-btn');
  if (cancelBtn) cancelBtn.addEventListener('click', cancel2FA);

  // Resend verification forms (exist on both login + register pages in check-email state)
  const resendForms = document.querySelectorAll('#resend-form');
  resendForms.forEach(f => f.addEventListener('submit', handleResendVerification));

  // Dev links button (visible on login page in dev mode)
  const devLinksBtn = document.getElementById('dev-links-btn');
  if (devLinksBtn) {
    // Show the button itself only if dev mode
    fetch(`${API}/dev-links`).then(r => {
      if (r.ok) devLinksBtn.style.display = 'inline-flex';
    }).catch(() => {});
    devLinksBtn.addEventListener('click', openDevLinks);
  }

  // ── Query-string feedback ──────────────────────────────────
  const params = new URLSearchParams(window.location.search);
  if (params.get('verified') === '1') {
    setStatus('login-status', '✅ Email verified! You can now sign in.', 'success');
  }
  if (params.get('error') === 'invalid_or_expired_link') {
    setStatus('login-status',
      '❌ That link is invalid or has expired. Request a new one below.', 'error');
    showResendSection();
  }
  if (params.get('error') === 'invalid_or_expired_2fa') {
    setStatus('login-status', '❌ 2FA link expired. Please log in again.', 'error');
  }
});
