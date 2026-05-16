/**
 * storage.js — SecureIM Encrypted Local Storage
 *
 * Manages all client-side persistence:
 *  - Encrypted private keys (PBKDF2-derived key)
 *  - Encrypted chat history (per-conversation, per-user)
 *  - Session ephemeral keys (in-memory only — lost on tab close)
 *  - User settings (store_history, session_mode)
 *  - Contact list & verified status
 *
 * Session-mode behavior:
 *  - When session_mode = ON: messages from the CURRENT session are held
 *    in memory only. They are NOT written to localStorage. On page refresh
 *    they are gone. Older persisted history remains intact.
 *  - When session_mode = OFF (default): all messages are encrypted and
 *    stored in localStorage.
 */

const SecureStorage = (() => {

  const KEYS = {
    identity:       'sim_identity',      // {ecdsa: {enc...}, ecdh: {enc...}}
    deviceId:       'sim_device_id',
    authToken:      'sim_auth_token',
    user:           'sim_user',
    settings:       'sim_settings',
    contacts:       'sim_contacts',
    storageKeyMeta: 'sim_storage_meta',  // {salt, username}
  };

  function historyKey(conversationId) {
    return `sim_hist_${conversationId}`;
  }

  // ── Auth / Session ──────────────────────────────────────────────

  function saveAuthToken(token)  { localStorage.setItem(KEYS.authToken, token); }
  function getAuthToken()        { return localStorage.getItem(KEYS.authToken); }
  function clearAuthToken()      { localStorage.removeItem(KEYS.authToken); }

  function saveUser(user)  { localStorage.setItem(KEYS.user, JSON.stringify(user)); }
  function getUser()       { const u = localStorage.getItem(KEYS.user); return u ? JSON.parse(u) : null; }
  function clearUser()     { localStorage.removeItem(KEYS.user); }

  function saveDeviceId(id) { localStorage.setItem(KEYS.deviceId, id); }
  function getDeviceId()    { return localStorage.getItem(KEYS.deviceId); }

  function saveSettings(s)  { localStorage.setItem(KEYS.settings, JSON.stringify(s)); }
  function getSettings()    {
    const raw = localStorage.getItem(KEYS.settings);
    return raw ? JSON.parse(raw) : { store_history: true, session_mode: false };
  }

  // ── Identity Keys ───────────────────────────────────────────────

  /**
   * Save encrypted key pair to localStorage.
   * Called once on registration, or when re-encrypting keys.
   */
  async function saveIdentityKeys(password, ecdsaPrivJwk, ecdhPrivJwk) {
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

  // In-memory store for current-session messages (session_mode=ON)
  const _sessionMessages = {};

  /**
   * Save a message to storage.
   * Behavior depends on settings.session_mode and settings.store_history.
   */
  async function saveMessage(password, conversationId, message) {
    const settings = getSettings();

    // Always keep in-memory for current session
    if (!_sessionMessages[conversationId]) _sessionMessages[conversationId] = [];
    _sessionMessages[conversationId].push(message);

    // Persist to localStorage only if both flags allow it
    if (!settings.store_history) return;
    if (settings.session_mode) return;  // Session mode: don't persist current session msgs

    await appendToHistory(password, conversationId, message);
  }

  async function appendToHistory(password, conversationId, message) {
    const existing = await loadHistory(password, conversationId);
    existing.push(message);
    // Keep last 500 messages per conversation
    const trimmed = existing.slice(-500);
    const key = historyKey(conversationId);
    const encrypted = await SecureCrypto.encryptForStorage(password, trimmed);
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

  /**
   * Get full conversation history:
   * - Persisted (encrypted localStorage) messages, PLUS
   * - Current in-memory session messages (deduplicated by message id)
   */
  async function getConversation(password, conversationId) {
    const settings = getSettings();
    let persisted = [];

    if (settings.store_history) {
      persisted = await loadHistory(password, conversationId);
    }

    const sessionMsgs = _sessionMessages[conversationId] || [];

    // Merge + deduplicate
    const seen = new Set(persisted.map(m => m.id));
    const merged = [...persisted];
    for (const m of sessionMsgs) {
      if (!seen.has(m.id)) merged.push(m);
    }

    return merged.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  }

  /**
   * Delete all locally-stored messages for a conversation (delete-for-me).
   * Does NOT affect the server or the other party.
   */
  async function deleteConversationLocal(conversationId) {
    localStorage.removeItem(historyKey(conversationId));
    delete _sessionMessages[conversationId];
  }

  /**
   * Remove a single message from local history (delete-for-me on single msg).
   */
  async function deleteMessageLocal(password, conversationId, messageId) {
    const msgs = await loadHistory(password, conversationId);
    const filtered = msgs.filter(m => m.id !== messageId);
    const key = historyKey(conversationId);
    if (filtered.length > 0) {
      const encrypted = await SecureCrypto.encryptForStorage(password, filtered);
      localStorage.setItem(key, JSON.stringify(encrypted));
    } else {
      localStorage.removeItem(key);
    }
    // Also remove from session memory
    if (_sessionMessages[conversationId]) {
      _sessionMessages[conversationId] = _sessionMessages[conversationId].filter(m => m.id !== messageId);
    }
  }

  /**
   * Mark a message as deep-deleted in local storage.
   */
  async function markDeepDeleted(password, conversationId, messageId) {
    const msgs = await loadHistory(password, conversationId);
    const updated = msgs.map(m =>
      m.id === messageId ? { ...m, is_deep_deleted: true, plaintext: null } : m
    );
    const key = historyKey(conversationId);
    const encrypted = await SecureCrypto.encryptForStorage(password, updated);
    localStorage.setItem(key, JSON.stringify(encrypted));

    if (_sessionMessages[conversationId]) {
      _sessionMessages[conversationId] = _sessionMessages[conversationId].map(m =>
        m.id === messageId ? { ...m, is_deep_deleted: true, plaintext: null } : m
      );
    }
  }

  // ── Contacts ────────────────────────────────────────────────────

  function saveContacts(contacts) {
    localStorage.setItem(KEYS.contacts, JSON.stringify(contacts));
  }

  function getContacts() {
    const raw = localStorage.getItem(KEYS.contacts);
    return raw ? JSON.parse(raw) : [];
  }

  // ── Ephemeral Session Keys (in-memory only) ────────────────────

  const _sessionKeys = {};  // sessionId → { aesKey, hmacKey, myEphemeral }

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
    // Clear all history keys
    const toRemove = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith('sim_')) toRemove.push(k);
    }
    toRemove.forEach(k => localStorage.removeItem(k));
  }

  // ── Public API ──────────────────────────────────────────────────

  return {
    saveAuthToken, getAuthToken, clearAuthToken,
    saveUser, getUser, clearUser,
    saveDeviceId, getDeviceId,
    saveSettings, getSettings,

    saveIdentityKeys, loadIdentityKeys, hasIdentityKeys, clearIdentityKeys,

    saveMessage, getConversation, deleteConversationLocal,
    deleteMessageLocal, markDeepDeleted,

    saveContacts, getContacts,

    storeSessionKeys, getSessionKeys, clearSessionKeys,

    clearAll,
  };
})();
