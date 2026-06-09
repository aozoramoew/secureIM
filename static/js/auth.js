/**
 * auth.js — Registration and Login UI Logic
 *
 * JWT is stored in an HttpOnly cookie set by the server — not in JS.
 * Client code never reads or writes the JWT token directly.
 */

const API = '/api/auth';

// ── Device Identity ─────────────────────────────────────────────
// Before login we have no password → store device ID temporarily in
// a separate unencrypted key.  After login succeeds we encrypt it
// under the user's password and remove the temp key.

const _TMP_DEVICE_KEY = 'sim_tmp_device_id';

function getOrCreateDeviceId() {
  let id = localStorage.getItem(_TMP_DEVICE_KEY);
  if (!id) {
    id = crypto.randomUUID();
    localStorage.setItem(_TMP_DEVICE_KEY, id);
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
    const identityKP = await SecureCrypto.generateIdentityKeyPair();
    const ecdhKP     = await SecureCrypto.generateEphemeralKeyPair();

    const ecdsaPubJwk  = await SecureCrypto.exportKeyJWK(identityKP.publicKey);
    const ecdhPubJwk   = await SecureCrypto.exportKeyJWK(ecdhKP.publicKey);
    const ecdsaPrivJwk = await SecureCrypto.exportKeyJWK(identityKP.privateKey);
    const ecdhPrivJwk  = await SecureCrypto.exportKeyJWK(ecdhKP.privateKey);

    const deviceId   = getOrCreateDeviceId();
    const deviceName = getDeviceName();

    setStatus('reg-status', '🔒 Encrypting private keys with your password…', 'info');

    // Initialise per-user salt before saving any encrypted data
    SecureStorage.initSalt(username);

    // Encrypt and persist private keys
    await SecureStorage.saveIdentityKeys(password, ecdsaPrivJwk, ecdhPrivJwk, username);

    setStatus('reg-status', '📡 Registering with server…', 'info');

    const res = await fetch(`${API}/register`, {
      method:      'POST',
      headers:     { 'Content-Type': 'application/json' },
      credentials: 'include',   // receive HttpOnly cookie
      body: JSON.stringify({
        username, password,
        ecdsa_public_key: ecdsaPubJwk,
        ecdh_public_key:  ecdhPubJwk,
        device_id:        deviceId,
        device_name:      deviceName,
      }),
    });

    const ct = res.headers.get('content-type') || '';
    let data = {};
    let rawText = '';
    if (ct.includes('application/json')) {
      data = await res.json();
    } else {
      rawText = await res.text();
    }

    if (!res.ok) {
      const detail = data.detail || data.error || rawText || `HTTP ${res.status}`;
      throw new Error(detail.length > 200 ? detail.slice(0, 200) + '…' : detail);
    }

    // Encrypt and store all sensitive client-side data under the user's password
    await SecureStorage.saveDeviceId(password, deviceId);
    await SecureStorage.saveUser(password, data.user);
    await SecureStorage.saveSettings(password, data.user.settings || {});
    localStorage.removeItem(_TMP_DEVICE_KEY);

    setStatus('reg-status', '✅ Account created! Redirecting…', 'success');
    window.location.href = '/chat';

  } catch (err) {
    setStatus('reg-status', '❌ ' + err.message, 'error');
  } finally {
    setBtnLoading('reg-btn', false, 'Create Account');
  }
}

// ── Login ────────────────────────────────────────────────────────

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

      SecureStorage.initSalt(username);
      await SecureStorage.saveIdentityKeys(password, ecdsaPrivJwk, ecdhPrivJwk, username);
    }

    const deviceId   = getOrCreateDeviceId();
    const deviceName = getDeviceName();

    setStatus('login-status', '📡 Authenticating…', 'info');

    const res = await fetch(`${API}/login`, {
      method:      'POST',
      headers:     { 'Content-Type': 'application/json' },
      credentials: 'include',   // receive HttpOnly cookie
      body: JSON.stringify({
        username, password, device_id: deviceId, device_name: deviceName,
        ecdsa_public_key: ecdsaPubJwk, ecdh_public_key: ecdhPubJwk,
      }),
    });

    const ct = res.headers.get('content-type') || '';
    let data = {};
    let rawText = '';
    if (ct.includes('application/json')) {
      data = await res.json();
    } else {
      rawText = await res.text();
    }

    if (res.status === 200 && data.status === 'ok') {
      // Ensure salt is initialised for this username (idempotent)
      SecureStorage.initSalt(username);
      await SecureStorage.saveDeviceId(password, deviceId);
      await SecureStorage.saveUser(password, data.user);
      await SecureStorage.saveSettings(password, data.user.settings || {});
      localStorage.removeItem(_TMP_DEVICE_KEY);
      window.location.href = '/chat';
    } else {
      const detail = data.detail || data.error || rawText || `HTTP ${res.status}`;
      throw new Error(detail.length > 200 ? detail.slice(0, 200) + '…' : detail);
    }

  } catch (err) {
    setStatus('login-status', '❌ ' + err.message, 'error');
    setBtnLoading('login-btn', false, 'Sign In');
  }
}

// ── Page Init ───────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
  // Check if already authenticated by probing /api/auth/me (cookie-based)
  const path = window.location.pathname;
  if (path === '/login' || path === '/register') {
    if (SecureStorage.hasIdentityKeys()) {
      try {
        const r = await fetch(`${API}/me`, { credentials: 'include' });
        if (r.ok) {
          window.location.href = '/chat';
          return;
        }
      } catch { /* not logged in */ }
    }
  }

  const regForm = document.getElementById('register-form');
  if (regForm) regForm.addEventListener('submit', handleRegister);

  const pwInput = document.getElementById('reg-password');
  if (pwInput) pwInput.addEventListener('input', () => updateStrengthBar(pwInput.value));

  const loginForm = document.getElementById('login-form');
  if (loginForm) loginForm.addEventListener('submit', handleLogin);
});
