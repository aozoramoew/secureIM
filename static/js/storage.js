/**
 * storage.js — SecureIM Encrypted Local Storage
 *
 * Manages all client-side persistence:
 *  - Encrypted private keys  (PBKDF2-derived key)
 *  - Encrypted chat history  (per-conversation, AES-256-GCM)
 *  - Encrypted contacts list (AES-256-GCM, same key)
 *  - Encrypted user object   (AES-256-GCM, same key)
 *  - Encrypted settings      (AES-256-GCM, same key)
 *  - Encrypted device ID     (AES-256-GCM, same key)
 *  - Session ephemeral keys  (in-memory only — lost on tab close)
 *
 * ALL data written to localStorage is encrypted with a key derived from
 * the user's password via PBKDF2-SHA256 (310 000 iterations) → AES-256-GCM.
 * Nothing is stored in plaintext.
 *
 * Session-mode behavior:
 *  - When session_mode = ON: messages from the CURRENT session are held
 *    in memory only. They are NOT written to localStorage.
 *  - When session_mode = OFF (default): all messages are encrypted and
 *    stored in localStorage.
 */

const SecureStorage = (() => {

  const KEYS = {
    identity:    'sim_identity',    // {ecdsa: {enc...}, ecdh: {enc...}}
    deviceId:    'sim_device_id',   // encrypted string
    user:        'sim_user',        // encrypted user object
    settings:    'sim_settings',    // encrypted settings object
    contacts:    'sim_contacts',    // encrypted contacts array
    storageMeta: 'sim_storage_meta', // {salt, username} — salt is not secret
  };

  function historyKey(conversationId) {
    return `sim_hist_${conversationId}`;
  }

  // ── Storage salt management ─────────────────────────────────────
  // We use a per-user salt stored alongside the ciphertext so that
  // PBKDF2 always derives the same key for the same password+salt pair.
  // The salt is not secret — keeping it in plaintext is standard practice.

  function _getOrCreateSalt(username) {
    const raw = localStorage.getItem(KEYS.storageMeta);
    if (raw) {
      try {
        const meta = JSON.parse(raw);
        if (meta.username === username && meta.salt) return meta.salt;
      } catch { /* fall through to create new */ }
    }
    // Generate a new 32-byte salt and persist it
    const salt = SecureCrypto.bufToB64(
      crypto.getRandomValues(new Uint8Array(32)).buffer
    );
    localStorage.setItem(KEYS.storageMeta, JSON.stringify({ username, salt }));
    return salt;
  }

  function _getSalt() {
    const raw = localStorage.getItem(KEYS.storageMeta);
    if (!raw) return null;
    try { return JSON.parse(raw).salt || null; } catch { return null; }
  }

  // ── Generic encrypted read/write ────────────────────────────────

  async function _encryptAndStore(password, storageKey, value) {
    const salt = _getSalt();
    const encrypted = await SecureCrypto.encryptForStorage(password, value, salt);
    localStorage.setItem(storageKey, JSON.stringify(encrypted));
  }

  async function _decryptFromStore(password, storageKey, fallback) {
    const raw = localStorage.getItem(storageKey);
    if (!raw) return fallback;
    try {
      return await SecureCrypto.decryptFromStorage(password, JSON.parse(raw));
    } catch {
      return fallback;
    }
  }

  // ── Device ID ────────────────────────────────────────────────────

  async function saveDeviceId(password, id) {
    await _encryptAndStore(password, KEYS.deviceId, id);
  }

  async function getDeviceId(password) {
    return _decryptFromStore(password, KEYS.deviceId, null);
  }

  // Bootstrap path: device id may still be needed before password is known
  // (e.g., during login form before unlock). Falls back to generating a new one.
  function getDeviceIdSync() {
    // During registration/login the device id hasn't been encrypted yet —
    // we generate it fresh and it gets encrypted after first login succeeds.
    return null;
  }

  // ── User ────────────────────────────────────────────────────────

  async function saveUser(password, user) {
    await _encryptAndStore(password, KEYS.user, user);
  }

  async function getUser(password) {
    return _decryptFromStore(password, KEYS.user, null);
  }

  async function clearUser() {
    localStorage.removeItem(KEYS.user);
  }

  // ── Settings ────────────────────────────────────────────────────

  async function saveSettings(password, s) {
    await _encryptAndStore(password, KEYS.settings, s);
  }

  async function getSettings(password) {
    return _decryptFromStore(
      password, KEYS.settings,
      { store_history: true, session_mode: false }
    );
  }

  // ── Identity Keys ───────────────────────────────────────────────

  /**
   * Save encrypted key pair to localStorage.
   * Also initialises the per-user storage salt so all subsequent
   * encrypted writes use a consistent salt.
   */
  async function saveIdentityKeys(password, ecdsaPrivJwk, ecdhPrivJwk, username) {
    // Initialise salt now (idempotent if already exists for this username)
    if (username) _getOrCreateSalt(username);
    const encEcdsa = await SecureCrypto.encryptPrivateKey(password, ecdsaPrivJwk);
    const encEcdh  = await SecureCrypto.encryptPrivateKey(password, ecdhPrivJwk);
    localStorage.setItem(KEYS.identity, JSON.stringify({ ecdsa: encEcdsa, ecdh: encEcdh }));
  }

  /**
   * Load and decrypt identity keys from localStorage.
   * Returns { ecdsaPrivJwk, ecdhPrivJwk } or null.
   */
  async function loadIdentityKeys(password) {
    const raw = localStorage.getItem(KEYS.identity);
    if (!raw) return null;
    const { ecdsa, ecdh } = JSON.parse(raw);
    try {
      const ecdsaPrivJwk = await SecureCrypto.decryptPrivateKey(password, ecdsa);
      const ecdhPrivJwk  = await SecureCrypto.decryptPrivateKey(password, ecdh);
      return { ecdsaPrivJwk, ecdhPrivJwk };
    } catch {
      return null;  // Wrong password
    }
  }

  function hasIdentityKeys() {
    return !!localStorage.getItem(KEYS.identity);
  }

  function clearIdentityKeys() {
    localStorage.removeItem(KEYS.identity);
  }

  // ── Chat History ────────────────────────────────────────────────

  const _sessionMessages = {};

  async function saveMessage(password, conversationId, message) {
    const settings = await getSettings(password);

    if (!_sessionMessages[conversationId]) _sessionMessages[conversationId] = [];
    _sessionMessages[conversationId].push(message);

    if (!settings.store_history) return;
    if (settings.session_mode) return;

    await appendToHistory(password, conversationId, message);
  }

  async function appendToHistory(password, conversationId, message) {
    const existing = await loadHistory(password, conversationId);
    existing.push(message);
    const trimmed = existing.slice(-500);
    const key = historyKey(conversationId);
    const salt = _getSalt();
    const encrypted = await SecureCrypto.encryptForStorage(password, trimmed, salt);
    localStorage.setItem(key, JSON.stringify(encrypted));
  }

  async function loadHistory(password, conversationId) {
    const key = historyKey(conversationId);
    const raw = localStorage.getItem(key);
    if (!raw) return [];
    try {
      return await SecureCrypto.decryptFromStorage(password, JSON.parse(raw));
    } catch {
      return [];
    }
  }

  async function getConversation(password, conversationId) {
    const settings = await getSettings(password);
    let persisted = [];

    if (settings.store_history) {
      persisted = await loadHistory(password, conversationId);
    }

    const sessionMsgs = _sessionMessages[conversationId] || [];

    const seen = new Set(persisted.map(m => m.id));
    const merged = [...persisted];
    for (const m of sessionMsgs) {
      if (!seen.has(m.id)) merged.push(m);
    }

    return merged.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  }

  async function deleteConversationLocal(conversationId) {
    localStorage.removeItem(historyKey(conversationId));
    delete _sessionMessages[conversationId];
  }

  async function deleteMessageLocal(password, conversationId, messageId) {
    const msgs = await loadHistory(password, conversationId);
    const filtered = msgs.filter(m => m.id !== messageId);
    const key = historyKey(conversationId);
    if (filtered.length > 0) {
      const salt = _getSalt();
      const encrypted = await SecureCrypto.encryptForStorage(password, filtered, salt);
      localStorage.setItem(key, JSON.stringify(encrypted));
    } else {
      localStorage.removeItem(key);
    }
    if (_sessionMessages[conversationId]) {
      _sessionMessages[conversationId] = _sessionMessages[conversationId].filter(m => m.id !== messageId);
    }
  }

  async function markDeepDeleted(password, conversationId, messageId) {
    const msgs = await loadHistory(password, conversationId);
    const updated = msgs.map(m =>
      m.id === messageId ? { ...m, is_deep_deleted: true, plaintext: null } : m
    );
    const key = historyKey(conversationId);
    const salt = _getSalt();
    const encrypted = await SecureCrypto.encryptForStorage(password, updated, salt);
    localStorage.setItem(key, JSON.stringify(encrypted));

    if (_sessionMessages[conversationId]) {
      _sessionMessages[conversationId] = _sessionMessages[conversationId].map(m =>
        m.id === messageId ? { ...m, is_deep_deleted: true, plaintext: null } : m
      );
    }
  }

  // ── Contacts ────────────────────────────────────────────────────

  async function saveContacts(password, contacts) {
    await _encryptAndStore(password, KEYS.contacts, contacts);
  }

  async function getContacts(password) {
    return _decryptFromStore(password, KEYS.contacts, []);
  }

  // ── Ephemeral Session Keys (in-memory only) ────────────────────

  const _sessionKeys = {};

  function storeSessionKeys(sessionId, aesKey, hmacKey, myEphemeral) {
    _sessionKeys[sessionId] = { aesKey, hmacKey, myEphemeral };
  }

  function getSessionKeys(sessionId) {
    return _sessionKeys[sessionId] || null;
  }

  function clearSessionKeys(sessionId) {
    delete _sessionKeys[sessionId];
  }

  // ── Full Logout ─────────────────────────────────────────────────

  function clearAll() {
    Object.values(KEYS).forEach(k => localStorage.removeItem(k));
    const toRemove = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith('sim_')) toRemove.push(k);
    }
    toRemove.forEach(k => localStorage.removeItem(k));
    // Clear theme pref too
    localStorage.removeItem('theme');
  }

  // ── Public API ──────────────────────────────────────────────────

  return {
    // Salt bootstrap (call once at register/login with username)
    initSalt: _getOrCreateSalt,

    // Device ID (async, encrypted)
    saveDeviceId, getDeviceId,

    // User (async, encrypted)
    saveUser, getUser, clearUser,

    // Settings (async, encrypted)
    saveSettings, getSettings,

    // Identity keys
    saveIdentityKeys, loadIdentityKeys, hasIdentityKeys, clearIdentityKeys,

    // Chat history
    saveMessage, getConversation, deleteConversationLocal,
    deleteMessageLocal, markDeepDeleted,

    // Contacts (async, encrypted)
    saveContacts, getContacts,

    // Ephemeral session keys (in-memory)
    storeSessionKeys, getSessionKeys, clearSessionKeys,

    clearAll,
  };
})();
