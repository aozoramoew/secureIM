/**
 * chat.js — Main chat UI, SocketIO client, and E2EE orchestration
 */

const CHAT_API = '/api/chat';
let socket = null;
let currentUser = null;
let currentPassword = null; // held in memory for storage decryption
let activeConversation = null; // { type:'dm', id, sessionId, name }
let myEcdhPrivKey = null;      // CryptoKey object (ECDH private, in-memory)
let myEcdsaPrivKey = null;     // CryptoKey object (ECDSA private, in-memory)

// FIFO queue of { tempId, convId } for optimistically-rendered outgoing messages
// awaiting the server's `receive_message` echo, used to flip "sending" → "delivered".
let _pendingOutgoing = [];

// Cache of all known users: id → {id, username, ...} — populated by loadUserList
const _userMap = {};

// Device key cache: username → [{device_id, ecdh_public_key, ...}]
const _deviceKeyCache = {};

// Set of user_ids currently known to be offline — cleared when they come back online.
// Used to decide offline vs ephemeral path without clearing session keys from RAM.
const _offlineUsers = new Set();

// ── Bootstrap ────────────────────────────────────────────────────

async function initChat() {
  if (!SecureStorage.hasIdentityKeys()) { window.location.href = '/login'; return; }

  document.getElementById('unlock-switch-account-btn')?.addEventListener('click', () => {
    if (confirm('Switching accounts will remove this account\'s encrypted keys and message history from this device (they cannot be recovered). Continue?')) {
      logout();
    }
  });

  // Pre-populate the "Unlocking as …" label from the stored salt meta (before password known).
  try {
    const meta = JSON.parse(localStorage.getItem('sim_storage_meta') || '{}');
    if (meta.username) {
      const el = document.getElementById('unlock-username');
      if (el) el.textContent = meta.username;
    }
  } catch { /* ignore */ }

  // Prompt for password — retry loop so a wrong password never wipes storage.
  let keys = null;
  while (!keys) {
    currentPassword = await promptPassword();
    if (!currentPassword) {
      showAlert('🔒 Enter your password to unlock your keys.', 'warning');
      continue;
    }
    keys = await SecureStorage.loadIdentityKeys(currentPassword);
    if (!keys) {
      showAlert('❌ Wrong password. Please try again.', 'error');
      currentPassword = null;
    }
  }

  currentUser = await SecureStorage.getUser(currentPassword);
  if (!currentUser) {
    // Fallback: user data missing from encrypted storage (e.g. stored with old plaintext
    // code before the encrypted-storage upgrade). Re-fetch from server and re-save.
    try {
      const meRes = await fetch('/api/auth/me', { credentials: 'include' });
      if (!meRes.ok) { window.location.href = '/login'; return; }
      const { user } = await meRes.json();
      await SecureStorage.saveUser(currentPassword, user);
      await SecureStorage.saveSettings(currentPassword, user.settings || {});
      currentUser = user;
    } catch { window.location.href = '/login'; return; }
  }

  const unlockUsernameEl = document.getElementById('unlock-username');
  if (unlockUsernameEl) unlockUsernameEl.textContent = currentUser.username;

  myEcdhPrivKey  = await SecureCrypto.importPrivateECDH(keys.ecdhPrivJwk);
  myEcdsaPrivKey = await crypto.subtle.importKey(
    'jwk', JSON.parse(keys.ecdsaPrivJwk),
    { name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign']
  );

  renderCurrentUser();
  connectSocket();
  await loadUserList();
  applySettings();
}

function promptPassword() {
  return new Promise(resolve => {
    const overlay  = document.getElementById('unlock-overlay');
    const input    = document.getElementById('unlock-password');
    overlay.style.display = 'flex';
    input.value = '';
    input.focus();
    const submit = () => {
      const pwd = input.value;
      overlay.style.display = 'none';
      input.removeEventListener('keydown', onKeydown);
      resolve(pwd);
    };
    const onKeydown = (e) => { if (e.key === 'Enter') submit(); };
    input.addEventListener('keydown', onKeydown);
    document.getElementById('unlock-btn').onclick = submit;
  });
}

// ── SocketIO ─────────────────────────────────────────────────────

function connectSocket() {
  socket = io({
    withCredentials: true,  // send HttpOnly cookie with SocketIO handshake
    reconnection: true,
    reconnectionDelay: 1000,
    reconnectionAttempts: 10,
  });

  socket.on('connect', () => {
    console.log('🔌 Connected');
    showConnectionBanner(true);
  });
  socket.on('disconnect', () => showConnectionBanner(false));
  socket.on('connect_error', (err) => {
    console.error('Socket connect error:', err.message);
    showConnectionBanner(false);
  });

  socket.on('user_online', d => {
    updateUserStatus(d.user_id, true);
    _offlineUsers.delete(d.user_id);
    // Re-initiate session if active DM has no usable keys
    if (activeConversation?.type === 'dm' && activeConversation.id === d.user_id) {
      const keys = SecureStorage.getSessionKeys(activeConversation.sessionId);
      if (!keys?.aesKey) {
        initiateSession(activeConversation.id, activeConversation.username).then(sess => {
          if (sess) activeConversation.sessionId = sess.id;
        });
      }
    }
  });
  socket.on('user_offline', d => {
    updateUserStatus(d.user_id, false);
    // Mark the peer as offline so next outgoing message uses the offline path.
    // Do NOT clear session keys — in-flight echo messages still need them to decrypt.
    _offlineUsers.add(d.user_id);
    if (activeConversation?.type === 'dm' && activeConversation.id === d.user_id) {
      if (activeConversation.username) delete _deviceKeyCache[activeConversation.username];
      updateEncryptionBadge(false);
    }
  });

  socket.on('session_request', onSessionRequest);
  socket.on('session_ready',   onSessionReady);
  socket.on('key_rotation_required', onKeyRotationRequired);

  socket.on('receive_message', onReceiveMessage);
  socket.on('message_deleted', onMessageDeleted);
  socket.on('message_read',    onMessageRead);

  socket.on('typing', d => {
    if (!activeConversation || d.user_id === currentUser.id) return;
    const match = activeConversation.type === 'dm' && d.conversation_type === 'dm' && activeConversation.id === d.peer_id;
    if (match) showTypingIndicator(d.is_typing);
  });
}

// ── ECDH Session Management ───────────────────────────────────────

async function initiateSession(recipientId, recipientUsername) {
  const ephemeral = await SecureCrypto.generateEphemeralKeyPair();
  const ephPubJwk = await SecureCrypto.exportKeyJWK(ephemeral.publicKey);

  // Sign the ephemeral public key with our long-term ECDSA identity key.
  // This binds the ephemeral key to our identity — any relay that substitutes
  // a different public key cannot produce a valid signature without our private key.
  // This fully prevents MitM on the ECDH key exchange.
  if (!myEcdsaPrivKey) { showAlert('❌ Identity key not loaded', 'error'); return null; }
  const signature = await SecureCrypto.signData(myEcdsaPrivKey, ephPubJwk);

  const res = await apiPost(`${CHAT_API}/sessions`, {
    recipient_id:  recipientId,
    ephemeral_pub: ephPubJwk,
    ephemeral_sig: signature,
  });
  const { session } = await res.json();
  SecureStorage.storeSessionKeys(session.id, null, null, ephemeral.privateKey);

  // Track which session belongs to which contact so onSessionReady can verify
  // the responder's signature even when they complete the handshake while
  // this conversation is not the active one.
  if (recipientUsername && currentPassword) {
    const contacts = await SecureStorage.getContacts(currentPassword);
    const updated = contacts.map(c =>
      c.id === recipientId ? { ...c, _pendingSessionId: session.id } : c
    );
    await SecureStorage.saveContacts(currentPassword, updated);
  }

  return session;
}

async function onSessionRequest(data) {
  const { session_id, initiator_id, initiator, initiator_device_id, ephemeral_pub_a, ephemeral_sig_a } = data;

  // ── Step 1: Verify initiator's ECDSA signature BEFORE key exchange ──
  const keysRes = await apiGet(`${CHAT_API}/users/${initiator}/keys`);
  if (!keysRes.ok) { showAlert('❌ Could not fetch sender public key', 'error'); return; }
  const { devices } = await keysRes.json();
  if (!devices.length) { showAlert('❌ No device keys found for sender', 'error'); return; }

  // Try the device that signed first (identified by device_id from server),
  // then fall back to verifying against ALL active devices for this user.
  // This handles the case where the initiator is on a new device whose key
  // was just registered — the server sends the correct device_id to match.
  let isValid = false;
  const primaryDevice = initiator_device_id
    ? devices.find(d => d.device_id === initiator_device_id)
    : null;

  if (primaryDevice) {
    isValid = await SecureCrypto.verifySignature(
      primaryDevice.ecdsa_public_key, ephemeral_pub_a, ephemeral_sig_a
    );
  }
  // If primary device check failed or no device_id given, try all devices
  if (!isValid) {
    for (const dev of devices) {
      if (dev === primaryDevice) continue;
      isValid = await SecureCrypto.verifySignature(
        dev.ecdsa_public_key, ephemeral_pub_a, ephemeral_sig_a
      );
      if (isValid) break;
    }
  }

  if (!isValid) {
    showAlert('⛔ KEY EXCHANGE SIGNATURE INVALID — Possible MitM attack! Session aborted.', 'error');
    console.error('[SecureIM] MitM detected: ephemeral key signature verification failed for', initiator);
    return;  // ABORT — do not derive any keys
  }

  // ── Step 2: Generate our ephemeral key pair + sign it ──────────
  const ephemeral = await SecureCrypto.generateEphemeralKeyPair();
  const ephPubJwk = await SecureCrypto.exportKeyJWK(ephemeral.publicKey);
  const signature = await SecureCrypto.signData(myEcdsaPrivKey, ephPubJwk);

  // ── Step 3: Derive session keys from the VERIFIED ephemeral pub ─
  const aesKey  = await SecureCrypto.deriveSessionKey(ephemeral.privateKey, ephemeral_pub_a);
  const hmacKey = await SecureCrypto.deriveHMACKey(ephemeral.privateKey, ephemeral_pub_a);
  SecureStorage.storeSessionKeys(session_id, aesKey, hmacKey, ephemeral.privateKey);

  // ── Step 4: Send our signed public key to complete handshake ────
  await apiPut(`${CHAT_API}/sessions/${session_id}`, {
    ephemeral_pub: ephPubJwk,
    ephemeral_sig: signature,
  });

  // If this session is for the currently open DM, re-decrypt any [Encrypted] bubbles
  // that arrived before keys were ready (e.g. messages sent while we were offline).
  if (activeConversation?.type === 'dm' && activeConversation.sessionId === session_id) {
    updateEncryptionBadge(true);
    await _redecryptActiveConversation(aesKey, hmacKey);
  } else if (activeConversation?.type === 'dm' && initiator_id === activeConversation.id) {
    activeConversation.sessionId = session_id;
    updateEncryptionBadge(true);
    await _redecryptActiveConversation(aesKey, hmacKey);
  }
}


async function onSessionReady(data) {
  const {
    session_id, ephemeral_pub_b, ephemeral_sig_b,
    responder_device_id, responder_username,
  } = data;

  const stored = SecureStorage.getSessionKeys(session_id);

  // If we have no in-memory state for this session (e.g. page was refreshed),
  // the other side already completed their half. We need to start a fresh
  // handshake — look up who the responder is and re-initiate toward them.
  if (!stored || !stored.myEphemeral) {
    let resolvedUsername = responder_username;
    if (!resolvedUsername && currentPassword) {
      const contacts = await SecureStorage.getContacts(currentPassword);
      resolvedUsername = contacts.find(c => c._pendingSessionId === session_id)?.username;
    }
    if (resolvedUsername && activeConversation?.username === resolvedUsername) {
      console.log('[SecureIM] Lost session state — re-initiating with', resolvedUsername);
      const sess = await initiateSession(activeConversation.id, resolvedUsername);
      if (sess) activeConversation.sessionId = sess.id;
    }
    return;
  }

  const isThisSession = activeConversation?.sessionId === session_id;

  // ── Verify the responder's ECDSA signature BEFORE computing shared secret ──
  let verifyUsername = responder_username || (isThisSession ? activeConversation?.username : null);
  if (!verifyUsername && currentPassword) {
    const contacts = await SecureStorage.getContacts(currentPassword);
    verifyUsername = contacts.find(c => c._pendingSessionId === session_id)?.username;
  }

  if (verifyUsername && ephemeral_sig_b) {
    const keysRes = await apiGet(`${CHAT_API}/users/${verifyUsername}/keys`);
    if (keysRes.ok) {
      const { devices } = await keysRes.json();
      if (devices.length) {
        const primaryDev = responder_device_id
          ? devices.find(d => d.device_id === responder_device_id)
          : null;
        let isValid = false;
        if (primaryDev) {
          isValid = await SecureCrypto.verifySignature(
            primaryDev.ecdsa_public_key, ephemeral_pub_b, ephemeral_sig_b
          );
        }
        if (!isValid) {
          for (const dev of devices) {
            if (dev === primaryDev) continue;
            isValid = await SecureCrypto.verifySignature(
              dev.ecdsa_public_key, ephemeral_pub_b, ephemeral_sig_b
            );
            if (isValid) break;
          }
        }
        if (!isValid) {
          showAlert('⛔ KEY EXCHANGE SIGNATURE INVALID — MitM attack detected! Aborting session.', 'error');
          console.error('[SecureIM] MitM detected: session_ready signature failed for', verifyUsername);
          SecureStorage.clearSessionKeys(session_id);
          if (isThisSession) updateEncryptionBadge(false);
          return;  // ABORT
        }
      }
    }
  }

  const aesKey  = await SecureCrypto.deriveSessionKey(stored.myEphemeral, ephemeral_pub_b);
  const hmacKey = await SecureCrypto.deriveHMACKey(stored.myEphemeral, ephemeral_pub_b);
  SecureStorage.storeSessionKeys(session_id, aesKey, hmacKey, stored.myEphemeral);

  if (isThisSession) {
    // Only show "session established" once per conversation open, not on every re-key
    if (!activeConversation._sessionShown) {
      activeConversation._sessionShown = true;
      showAlert('🔒 Secure session established with ' + activeConversation.name, 'success');
    }
    updateEncryptionBadge(true);
    // Re-decrypt any messages that arrived before session keys were ready
    await _redecryptActiveConversation(aesKey, hmacKey);
  }
}

// Re-decrypt messages already in the DOM that were rendered as [Encrypted]
// because the session key was not yet available when they arrived.
async function _redecryptActiveConversation(aesKey, hmacKey) {
  if (!activeConversation || activeConversation.type !== 'dm') return;
  const otherId = activeConversation.id;
  const res = await apiGet(`${CHAT_API}/messages/${otherId}`);
  if (!res.ok) return;
  const { messages } = await res.json();
  const deviceId = await SecureStorage.getDeviceId(currentPassword);

  for (const msg of messages) {
    const el = document.getElementById(`msg-${msg.id}`);
    if (!el) continue;
    const body = el.querySelector('.msg-body');
    // Only re-decrypt bubbles that failed previously
    if (!body || body.textContent !== '🔒 [Encrypted]') continue;

    const payloads = msg.encrypted_payloads || {};
    const myPayload = payloads[deviceId];
    if (!myPayload || myPayload.offline_delivery) continue;

    try {
      const plaintext = await SecureCrypto.decryptMessage(aesKey, hmacKey, myPayload);
      body.textContent = plaintext;
      body.classList.remove('deleted-msg');
      // Update saved copy
      const convId = getActiveConvId();
      const enriched = { ...msg, plaintext };
      if (currentPassword) await SecureStorage.saveMessage(currentPassword, convId, enriched);
    } catch { /* leave as [Encrypted] if still fails */ }
  }
}

async function onKeyRotationRequired(data) {
  const { session_id } = data;
  showAlert('🔄 Key rotation triggered — refreshing session keys for forward secrecy…', 'info');
  SecureStorage.clearSessionKeys(session_id);
  if (activeConversation?.sessionId === session_id) {
    const sess = await initiateSession(activeConversation.id, activeConversation.username);
    activeConversation.sessionId = sess.id;
  }
}

// ── Self-destruct timer ────────────────────────────────────────────

let _selectedTimerSeconds = 0;

const TIMER_LABELS = { 0: '⏱️', 60: '1m', 300: '5m', 3600: '1h', 86400: '24h' };

function setSelectedTimer(seconds) {
  _selectedTimerSeconds = seconds;
  const btn = document.getElementById('timer-btn');
  if (btn) {
    btn.textContent = TIMER_LABELS[seconds] || '⏱️';
    btn.classList.toggle('active', seconds > 0);
    btn.title = seconds > 0
      ? `Self-destruct: ${TIMER_LABELS[seconds]} (click to change)`
      : 'Self-destruct timer';
  }
  document.querySelectorAll('.timer-option').forEach(opt => {
    opt.classList.toggle('active', parseInt(opt.dataset.value) === seconds);
  });
}

// ── Send Message ─────────────────────────────────────────────────

let currentAttachment = null;

function clearAttachment() {
  currentAttachment = null;
  document.getElementById('file-input').value = '';
  document.getElementById('media-preview').style.display = 'none';
  document.getElementById('media-preview-img').style.display = 'none';
  document.getElementById('media-preview-video').style.display = 'none';
  document.getElementById('media-preview-file').style.display = 'none';
  document.getElementById('media-preview-img').src = '';
  document.getElementById('media-preview-video').src = '';
  document.getElementById('media-preview-file').textContent = '';
}

// Extensions that must never be sent as attachments — executable or script
// content that a recipient's OS/browser could run if opened directly.
const BLOCKED_FILE_EXTENSIONS = new Set([
  'exe', 'bat', 'cmd', 'com', 'msi', 'msp', 'scr', 'ps1', 'psm1', 'vbs', 'vbe',
  'js', 'jse', 'wsf', 'wsh', 'jar', 'app', 'sh', 'bash', 'apk', 'deb', 'rpm',
  'dll', 'sys', 'cpl', 'gadget', 'reg', 'lnk', 'html', 'htm', 'svg',
]);

function getFileExtension(filename) {
  const idx = filename.lastIndexOf('.');
  return idx === -1 ? '' : filename.slice(idx + 1).toLowerCase();
}

let _sending = false;
async function sendMessage() {
  if (_sending) return;
  _sending = true;
  try {
    await _sendMessageInner();
  } finally {
    _sending = false;
  }
}

async function _sendMessageInner() {
  const input = document.getElementById('message-input');
  const text  = input.value.trim();
  if (!text && !currentAttachment) return;
  if (!activeConversation) return;

  if (!socket?.connected) {
    showAlert('⚠️ Not connected — please wait and try again.', 'warning');
    return;
  }

  input.value = '';
  input.style.height = 'auto';
  input.focus();

  const sessionKeys = SecureStorage.getSessionKeys(activeConversation.sessionId);
  const peerOffline = _offlineUsers.has(activeConversation.id);
  const hasEphemeralSession = !!(sessionKeys?.aesKey) && !peerOffline;

  if (peerOffline) {
    showAlert('📨 Recipient is offline — message will be delivered when they reconnect.', 'info');
  }

  try {
    let deviceMap = {};
    const fileAttach = currentAttachment;
    clearAttachment();

    // Derive a per-device AES+HMAC key pair from our ephemeral private key and the
    // device's static ECDH public key. Used when no live ephemeral session exists.
    async function deriveStaticKeys(deviceEcdhPubJwk) {
      const ephemeral = await SecureCrypto.generateEphemeralKeyPair();
      const ephPubJwk = await SecureCrypto.exportKeyJWK(ephemeral.publicKey);
      const aesKey  = await SecureCrypto.deriveSessionKey(ephemeral.privateKey, deviceEcdhPubJwk);
      const hmacKey = await SecureCrypto.deriveHMACKey(ephemeral.privateKey, deviceEcdhPubJwk);
      return { aesKey, hmacKey, senderEphPub: ephPubJwk };
    }

    async function encryptForDevice(aesKey, hmacKey) {
      if (fileAttach) {
        // Slice the buffer to prevent detachment issues across async boundaries
        const buf = fileAttach.buffer.slice(0);
        const payload = await SecureCrypto.encryptBinaryMessage(
          aesKey, hmacKey, buf,
          { filename: fileAttach.file.name, mime: fileAttach.file.type }
        );
        payload.content_type = 'media';
        if (text) payload.caption = text;
        return payload;
      }
      return SecureCrypto.encryptMessage(aesKey, hmacKey, text);
    }

    if (!activeConversation.username) {
      showAlert('❌ Cannot send: recipient username unknown.', 'error');
      return;
    }

    // Fetch recipient devices (cached per username to avoid round-trip on every send)
    if (!_deviceKeyCache[activeConversation.username]) {
      const keysRes = await apiGet(`${CHAT_API}/users/${activeConversation.username}/keys`);
      if (!keysRes.ok) { showAlert('❌ Could not fetch recipient keys.', 'error'); return; }
      const { devices: d } = await keysRes.json();
      if (!d?.length) { showAlert('❌ Recipient has no registered devices.', 'error'); return; }
      _deviceKeyCache[activeConversation.username] = d;
    }
    const devices = _deviceKeyCache[activeConversation.username];

    for (const dev of devices) {
      if (hasEphemeralSession) {
        const payload = await encryptForDevice(sessionKeys.aesKey, sessionKeys.hmacKey);
        deviceMap[dev.device_id] = payload;
      } else {
        const { aesKey, hmacKey, senderEphPub } = await deriveStaticKeys(dev.ecdh_public_key);
        const payload = await encryptForDevice(aesKey, hmacKey);
        payload.sender_eph_pub = senderEphPub;
        payload.offline_delivery = true;
        deviceMap[dev.device_id] = payload;
      }
    }

    // Encrypt for our own devices so we can read our own sent messages (cached)
    if (!_deviceKeyCache[currentUser.username]) {
      const myKeysRes = await apiGet(`${CHAT_API}/users/${currentUser.username}/keys`);
      const { devices: d } = await myKeysRes.json();
      _deviceKeyCache[currentUser.username] = d || [];
    }
    const myDevices = _deviceKeyCache[currentUser.username];
    for (const dev of myDevices) {
      if (deviceMap[dev.device_id]) continue;
      if (hasEphemeralSession) {
        deviceMap[dev.device_id] = await encryptForDevice(sessionKeys.aesKey, sessionKeys.hmacKey);
      } else {
        const { aesKey, hmacKey, senderEphPub } = await deriveStaticKeys(dev.ecdh_public_key);
        const payload = await encryptForDevice(aesKey, hmacKey);
        payload.sender_eph_pub = senderEphPub;
        payload.offline_delivery = true;
        deviceMap[dev.device_id] = payload;
      }
    }

    // Self-destruct: read expires_seconds from the timer popup selection
    const expiresSec = _selectedTimerSeconds;

    socket.emit('send_message', {
      session_id:          activeConversation.sessionId,
      recipient_id:        activeConversation.id,
      encrypted_payloads:  deviceMap,
      msg_type:            'dm',
      expires_seconds:     expiresSec || undefined,
    });

    // Optimistically render outgoing message
    const expiresAt = expiresSec ? new Date(Date.now() + expiresSec * 1000).toISOString() : null;
    const tempId = Date.now();
    const optimistic = {
      id: tempId, sender_id: currentUser.id, plaintext: text || null,
      timestamp: new Date().toISOString(), is_deep_deleted: false,
      expires_at: expiresAt, status: 'sending',
    };
    
    if (fileAttach) {
      optimistic.content_type = 'media';
      const blob = new Blob([fileAttach.buffer], { type: fileAttach.file.type });
      optimistic.mediaUrl = URL.createObjectURL(blob);
      optimistic.mediaType = mediaTypeFor(fileAttach.file.type);
      optimistic.mediaMime = fileAttach.file.type;
      optimistic.mediaData = SecureCrypto.bufToB64(fileAttach.buffer);
      optimistic.fileName = fileAttach.file.name;
      optimistic.fileSize = fileAttach.file.size;
    }

    renderMessage(optimistic, true);
    _pendingOutgoing.push({ tempId, convId: getActiveConvId() });

  } catch (err) {
    console.error('[sendMessage] error:', err);
    showAlert('❌ Failed to send: ' + err.message, 'error');
    _sending = false;
  }
}

// ── Receive Message ───────────────────────────────────────────────

async function onReceiveMessage(msg) {
  // Compute the canonical conversation id for this message — used for
  // storage, badge updates, and reconciliation. Must be consistent with
  // getActiveConvId() and _convIdForMessage().
  const convId = _convIdForMessage(msg);
  const isMine = msg.sender_id === currentUser.id;

  // A message belongs to the active conversation only when its convId matches.
  const isForActiveConversation = convId === getActiveConvId();

  // ── Decrypt ──────────────────────────────────────────────────────
  const deviceId  = await SecureStorage.getDeviceId(currentPassword);
  const payloads  = msg.encrypted_payloads || {};
  const myPayload = payloads[deviceId];

  let plaintext = null;
  let mediaObj  = {};

  if (myPayload) {
    try {
      let aesKey, hmacKey;

      if (myPayload.offline_delivery && myPayload.sender_eph_pub) {
        aesKey  = await SecureCrypto.deriveSessionKey(myEcdhPrivKey, myPayload.sender_eph_pub);
        hmacKey = await SecureCrypto.deriveHMACKey(myEcdhPrivKey, myPayload.sender_eph_pub);
      } else {
        // Use session key for this specific conversation — not activeConversation
        const sessionId = msg.session_id || (isForActiveConversation ? activeConversation?.sessionId : null);
        const keys = SecureStorage.getSessionKeys(sessionId);
        if (keys?.aesKey) {
          aesKey  = keys.aesKey;
          hmacKey = keys.hmacKey;
        }
      }

      if (aesKey) {
        if (myPayload.content_type === 'media') {
          const { metadata, fileBuffer } = await SecureCrypto.decryptBinaryMessage(
            aesKey, hmacKey, myPayload
          );
          const blob = new Blob([fileBuffer], { type: metadata.mime });
          mediaObj = {
            content_type: 'media',
            mediaUrl:  URL.createObjectURL(blob),
            mediaType: mediaTypeFor(metadata.mime),
            mediaMime: metadata.mime,
            mediaData: SecureCrypto.bufToB64(fileBuffer),
            fileName:  metadata.filename || 'file',
            fileSize:  fileBuffer.byteLength,
            plaintext: myPayload.caption || null,
          };
        } else {
          plaintext = await SecureCrypto.decryptMessage(aesKey, hmacKey, myPayload);
        }
      }
    } catch (e) {
      plaintext = '🔒 [Encrypted]';
    }
  }

  const enriched = { ...msg, ...mediaObj };
  if (!mediaObj.content_type) enriched.plaintext = plaintext;

  // ── Render / reconcile ───────────────────────────────────────────
  if (isMine) {
    // Echo of our own outgoing message — update the optimistic bubble
    // ONLY if it belongs to the currently displayed conversation.
    if (isForActiveConversation) {
      _reconcileOutgoing(convId, enriched);
    } else {
      // Echo for a background conversation — no bubble to update.
      // Drop from pending queue so it doesn't block future reconciliations.
      _pendingOutgoing = _pendingOutgoing.filter(p => p.convId !== convId
        || document.getElementById(`msg-${p.tempId}`));
    }
  } else if (isForActiveConversation) {
    renderMessage(enriched, false);
  } else {
    updateUnreadBadge(msg.group_id || msg.sender_id);
  }

  // ── Persist ──────────────────────────────────────────────────────
  if (currentPassword) {
    await SecureStorage.saveMessage(currentPassword, convId, enriched);
  }
}

// ── Message Deletion ─────────────────────────────────────────────

async function deleteMessage(msgId, type) {
  socket.emit('delete_message', { message_id: msgId, delete_type: type });
  if (type === 'local') {
    const convId = getActiveConvId();
    await SecureStorage.deleteMessageLocal(currentPassword, convId, msgId);
    document.getElementById(`msg-${msgId}`)?.remove();
  }
}

function onMessageDeleted(data) {
  const { message_id, type } = data;
  const el = document.getElementById(`msg-${message_id}`);
  if (!el) return;
  if (type === 'deep' || type === 'expired') {
    const body = el.querySelector('.msg-body');
    if (body) {
      body.textContent = type === 'expired' ? '⏱️ Message expired.' : '🗑️ This message was deleted.';
      body.classList.add('deleted-msg');
    }
    el.querySelector('.msg-actions')?.remove();
    el.querySelector('.msg-timer')?.remove();
    if (currentPassword) {
      const convId = getActiveConvId();
      SecureStorage.markDeepDeleted(currentPassword, convId, message_id);
    }
  }
}

function onMessageRead(data) {
  const { message_id } = data;
  const el = document.getElementById(`msg-${message_id}`);
  if (!el) return;
  const receipt = el.querySelector('.msg-receipt');
  if (receipt) { receipt.textContent = '✓✓'; receipt.style.color = '#00d4ff'; }
}


// ── Open DM Conversation ─────────────────────────────────────────

async function openDM(userId, username) {
  clearMessages();
  clearAttachment();
  activeConversation = { type: 'dm', id: userId, username, name: username, sessionId: null };
  document.getElementById('chat-header-name').textContent = username;
  const avatarEl = document.getElementById('chat-header-avatar');
  if (avatarEl) { avatarEl.textContent = username[0].toUpperCase(); avatarEl.classList.remove('group-avatar'); }
  document.getElementById('no-chat-placeholder').style.display = 'none';
  document.getElementById('chat-main').style.display = 'flex';

  updateEncryptionBadge(false);
  setActiveSidebarItem(userId, 'user');
  clearUnreadBadge(userId);

  // Start ECDH session
  const sess = await initiateSession(userId, username);
  if (!sess) return;
  activeConversation.sessionId = sess.id;

  // Load stored history
  const convId = `dm_${Math.min(currentUser.id, userId)}_${Math.max(currentUser.id, userId)}`;
  const history = await SecureStorage.getConversation(currentPassword, convId);
  history.forEach(m => renderMessage(m, m.sender_id === currentUser.id));

  // Mark all unread messages from this contact as read
  history.filter(m => m.sender_id === userId && !m.read_at).forEach(m => {
    apiPost(`${CHAT_API}/messages/${m.id}/read`, {}).catch(() => {});
  });
}



// ── CSP-safe DOM builder for messages ────────────────────────────
// No inline onclick handlers — all listeners attached via addEventListener.

function buildMessageEl(msg, isMine) {
  const div = document.createElement('div');
  div.id        = `msg-${msg.id}`;
  div.className = `message ${isMine ? 'mine' : 'theirs'}`;

  const time = new Date(_asUTC(msg.timestamp)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  if (msg.is_deep_deleted) {
    const body = document.createElement('div');
    body.className   = 'msg-body deleted-msg';
    body.textContent = '🗑️ This message was deleted.';
    div.appendChild(body);
    return div;
  }

  const bubble = document.createElement('div');
  bubble.className = 'msg-bubble';

  // Restore media URL from base64 data if missing
  if (msg.content_type === 'media') {
    if (!msg.mediaUrl && msg.mediaData) {
      const buf = SecureCrypto.b64ToBuf(msg.mediaData);
      const blob = new Blob([buf], { type: msg.mediaMime });
      msg.mediaUrl = URL.createObjectURL(blob);
    }
    
    if (msg.mediaUrl) {
      if (msg.mediaType === 'image') {
        const img = document.createElement('img');
        img.className = 'msg-media';
        img.src = msg.mediaUrl;
        bubble.appendChild(img);
      } else if (msg.mediaType === 'video') {
        const vid = document.createElement('video');
        vid.className = 'msg-media-video';
        vid.src = msg.mediaUrl;
        vid.controls = true;
        bubble.appendChild(vid);
      } else {
        // Generic file attachment — offer it as a download, never inline-rendered
        // (avoids the browser executing/interpreting HTML, SVG, etc.).
        const fileBox = document.createElement('a');
        fileBox.className = 'msg-file';
        fileBox.href = msg.mediaUrl;
        fileBox.download = msg.fileName || 'file';
        fileBox.target = '_blank';
        fileBox.rel = 'noopener noreferrer';

        const icon = document.createElement('span');
        icon.className = 'msg-file-icon';
        icon.textContent = '📎';

        const info = document.createElement('span');
        info.className = 'msg-file-info';

        const name = document.createElement('span');
        name.className = 'msg-file-name';
        name.textContent = msg.fileName || 'file';

        const size = document.createElement('span');
        size.className = 'msg-file-size';
        size.textContent = formatFileSize(msg.fileSize);

        info.append(name, size);
        fileBox.append(icon, info);
        bubble.appendChild(fileBox);
      }
    }
  }

  // Message body — built from text nodes / anchors only, never innerHTML, so it stays XSS-safe
  if (msg.plaintext) {
    const body = document.createElement('div');
    body.className = 'msg-body';
    linkifyText(body, msg.plaintext);
    bubble.appendChild(body);
  } else if (!msg.content_type) {
    const body = document.createElement('div');
    body.className   = 'msg-body';
    body.textContent = '🔒 [Encrypted]';
    bubble.appendChild(body);
  }

  // Meta row
  const meta = document.createElement('div');
  meta.className = 'msg-meta';
  const timeEl = document.createElement('span');
  timeEl.className   = 'msg-time';
  timeEl.textContent = time;
  const lockEl = document.createElement('span');
  lockEl.className   = 'msg-enc-icon';
  lockEl.title       = 'End-to-end encrypted';
  lockEl.textContent = '🔒';

  // Read receipt (only on outgoing messages)
  if (isMine) {
    const receipt = document.createElement('span');
    receipt.className = 'msg-receipt';
    if (msg.status === 'sending') {
      receipt.classList.add('sending');
      receipt.title       = 'Sending…';
      receipt.textContent = '🕓';
    } else {
      receipt.title       = msg.read_at ? 'Read' : (msg.delivered_at ? 'Delivered' : 'Sent');
      receipt.textContent = (msg.read_at || msg.delivered_at) ? '✓✓' : '✓';
      if (msg.read_at) receipt.style.color = '#00d4ff';
    }
    meta.append(timeEl, lockEl, receipt);
  } else {
    meta.append(timeEl, lockEl);
  }
  bubble.appendChild(meta);

  // Self-destruct countdown
  if (msg.expires_at) {
    const timerEl = document.createElement('div');
    timerEl.className = 'msg-timer';
    const expiresMs = new Date(_asUTC(msg.expires_at)).getTime();
    const updateTimer = () => {
      const remaining = Math.max(0, Math.floor((expiresMs - Date.now()) / 1000));
      if (remaining === 0) { timerEl.textContent = '⏱️ Expired'; return; }
      const m = Math.floor(remaining / 60), s = remaining % 60;
      timerEl.textContent = `⏱️ ${m}m ${s}s`;
    };
    updateTimer();
    const interval = setInterval(() => {
      const remaining = Math.max(0, Math.floor((expiresMs - Date.now()) / 1000));
      updateTimer();
      if (remaining === 0) clearInterval(interval);
    }, 1000);
    bubble.appendChild(timerEl);
  }

  // Actions
  const actions = document.createElement('div');
  actions.className = 'msg-actions';

  const dotsBtn = document.createElement('button');
  dotsBtn.className   = 'msg-action-btn';
  dotsBtn.textContent = '⋯';
  dotsBtn.addEventListener('click', () => {
    const menu = div.querySelector('.delete-menu');
    if (menu) menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
  });

  const menu = document.createElement('div');
  menu.className = 'delete-menu';
  menu.style.display = 'none';

  const delForMe = document.createElement('button');
  delForMe.textContent = 'Delete for me';
  delForMe.addEventListener('click', () => { menu.style.display='none'; deleteMessage(msg.id, 'local'); });
  menu.appendChild(delForMe);

  if (isMine) {
    const delAll = document.createElement('button');
    delAll.textContent = 'Delete for everyone';
    delAll.addEventListener('click', () => { menu.style.display='none'; deleteMessage(msg.id, 'deep'); });
    menu.appendChild(delAll);
  }

  actions.append(dotsBtn, menu);
  bubble.appendChild(actions);
  div.appendChild(bubble);
  return div;
}

/** Build a "Today" / "Wednesday, Jun 3" separator shown between days in the thread. */
function buildDateSepEl(timestamp) {
  const d = new Date(_asUTC(timestamp)), now = new Date();
  const label = d.toDateString() === now.toDateString()
    ? 'Today'
    : d.toLocaleDateString([], { weekday: 'long', month: 'short', day: 'numeric' });
  const sep = document.createElement('div');
  sep.className = 'date-sep';
  sep.innerHTML = '<span class="date-sep-line"></span>' +
    `<span class="date-sep-text">${escapeHtml(label)}</span>` +
    '<span class="date-sep-line"></span>';
  return sep;
}

function renderMessage(msg, isMine) {
  const container = document.getElementById('messages-container');
  const day = new Date(_asUTC(msg.timestamp)).toDateString();
  if (container.dataset.lastDate !== day) {
    container.appendChild(buildDateSepEl(msg.timestamp));
    container.dataset.lastDate = day;
  }
  container.appendChild(buildMessageEl(msg, isMine));
  container.scrollTop = container.scrollHeight;
}

function showDeleteMenu(msgId) {
  const menu = document.getElementById(`del-menu-${msgId}`);
  if (menu) menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
}

function clearMessages() {
  const c = document.getElementById('messages-container');
  if (c) { c.innerHTML = ''; delete c.dataset.lastDate; }
}

// Server sends naive UTC ISO timestamps (no trailing 'Z'). Append it so the
// browser's Date parser treats the value as UTC instead of local time —
// otherwise message times, date separators, and countdowns shift by the
// local UTC offset.
function _asUTC(isoStr) {
  if (!isoStr) return isoStr;
  return isoStr.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(isoStr) ? isoStr : isoStr + 'Z';
}

// Classifies an attachment by MIME type for rendering: inline image, inline
// video, or a generic downloadable file bubble for everything else.
function mediaTypeFor(mime) {
  if (mime?.startsWith('image/')) return 'image';
  if (mime?.startsWith('video/')) return 'video';
  return 'file';
}

function formatFileSize(bytes) {
  if (!bytes && bytes !== 0) return '';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// Splits text on http(s)/www URLs and appends text nodes and <a> elements to
// `container`. Builds DOM nodes directly (no innerHTML) so message content
// can never be interpreted as HTML, even though links become clickable.
const URL_PATTERN = /(https?:\/\/[^\s<>"]+|www\.[^\s<>"]+)/gi;
function linkifyText(container, text) {
  let lastIndex = 0;
  for (const match of text.matchAll(URL_PATTERN)) {
    const url = match[0];
    const start = match.index;
    if (start > lastIndex) {
      container.appendChild(document.createTextNode(text.slice(lastIndex, start)));
    }
    const a = document.createElement('a');
    a.href = url.startsWith('www.') ? `https://${url}` : url;
    a.textContent = url;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.className = 'msg-link';
    container.appendChild(a);
    lastIndex = start + url.length;
  }
  if (lastIndex < text.length) {
    container.appendChild(document.createTextNode(text.slice(lastIndex)));
  }
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── User / Group Lists ────────────────────────────────────────────

async function loadUserList(q = '') {
  try {
    const res = await apiGet(`${CHAT_API}/users?q=${encodeURIComponent(q)}`);
    if (!res.ok) {
      console.error('[loadUserList] API error', res.status);
      return;
    }
    const { users } = await res.json();
    const list = document.getElementById('contacts-list');
    list.innerHTML = '';
    // Online contacts first, then alphabetical by username
    users.sort((a, b) =>
      (b.is_online ? 1 : 0) - (a.is_online ? 1 : 0) ||
      a.username.localeCompare(b.username));
    if (!users || users.length === 0) {
      const empty = document.createElement('li');
      empty.style.cssText = 'padding:12px 16px; color:var(--text-3); font-size:12px; text-align:center;';
      empty.textContent = q ? 'No results found' : 'No other users yet';
      list.appendChild(empty);
      return;
    }
    users.forEach(u => {
      _userMap[u.id] = u;
      const li = document.createElement('li');
      li.className = 'contact-item';
      li.setAttribute('data-user-id', u.id);
      li.innerHTML = `
        <div class="contact-avatar">${u.username[0].toUpperCase()}
          <span class="online-dot ${u.is_online ? 'online' : 'offline'}"></span>
        </div>
        <div class="contact-info">
          <span class="contact-name">${escapeHtml(u.username)}</span>
          ${u.is_verified_by_me ? '<span class="verified-badge" title="Public key verified out-of-band">✅ Verified</span>' : ''}
        </div>
        <span class="unread-badge"></span>`;
      li.addEventListener('click', () => openDM(u.id, u.username));
      list.appendChild(li);
    });
  } catch (err) {
    console.error('[loadUserList] Error:', err);
  }
}


// ── Contact Key Verification ─────────────────────────────────────

async function verifyContact(contactId, username) {
  const keysRes = await apiGet(`${CHAT_API}/users/${username}/keys`);
  const { devices } = await keysRes.json();
  if (!devices.length) { showAlert('No keys found for this user.', 'error'); return; }

  const fp = await SecureCrypto.computeFingerprint(devices[0].ecdsa_public_key);

  const confirmed = confirm(
    `Key fingerprint for ${username}:\n\n${fp}\n\nVerify this out-of-band (e.g., in person or via phone).\n\nMark as verified?`
  );
  if (!confirmed) return;

  const res = await apiPost(`${CHAT_API}/contacts/${contactId}/verify`, { fingerprint: fp });
  if (res.ok) {
    showAlert(`✅ ${username} marked as verified.`, 'success');
    loadUserList();
  }
}

// ── Settings ──────────────────────────────────────────────────────
// store_history is always ON — messages are encrypted locally with PBKDF2 key.
// Ephemeral session keys are always used for forward secrecy; they live in RAM only.
function applySettings() {
  if (currentPassword) {
    SecureStorage.saveSettings(currentPassword, { store_history: true, session_mode: false });
  }
}

// ── Encryption Status Badge ────────────────────────────────────────

function updateEncryptionBadge(active) {
  const badge = document.getElementById('enc-status-badge');
  if (!badge) return;
  badge.textContent = active ? '🔒 E2EE Active' : '⏳ Establishing session…';
  badge.className   = active ? 'enc-badge active' : 'enc-badge pending';
}

// ── UI Utilities ─────────────────────────────────────────────────

function _convIdForMessage(msg) {
  const otherId = msg.sender_id === currentUser.id ? msg.recipient_id : msg.sender_id;
  return `dm_${Math.min(currentUser.id, otherId)}_${Math.max(currentUser.id, otherId)}`;
}

/**
 * Match the server's echo of our own message to the oldest pending optimistic
 * bubble for that conversation, swap in the real message id, and update the
 * "sending" indicator to a delivered/read receipt.
 */
function _reconcileOutgoing(convId, msg) {
  // Remove entries whose bubble no longer exists in the DOM
  _pendingOutgoing = _pendingOutgoing.filter(
    p => document.getElementById(`msg-${p.tempId}`)
  );

  // Take the oldest pending bubble for this conversation (FIFO)
  const idx = _pendingOutgoing.findIndex(p => p.convId === convId);
  if (idx === -1) return;
  const { tempId } = _pendingOutgoing.splice(idx, 1)[0];

  const el = document.getElementById(`msg-${tempId}`);
  if (!el) return;

  // Avoid stealing an id already claimed by a previous echo
  if (msg.id && document.getElementById(`msg-${msg.id}`)) return;

  if (msg.id) el.id = `msg-${msg.id}`;

  const receipt = el.querySelector('.msg-receipt');
  if (receipt) {
    receipt.classList.remove('sending');
    receipt.title       = msg.read_at ? 'Read' : (msg.delivered_at ? 'Delivered' : 'Sent');
    receipt.textContent = (msg.read_at || msg.delivered_at) ? '✓✓' : '✓';
    if (msg.read_at) receipt.style.color = '#00d4ff';
  }
}

function getActiveConvId() {
  if (!activeConversation) return null;
  return `dm_${Math.min(currentUser.id, activeConversation.id)}_${Math.max(currentUser.id, activeConversation.id)}`;
}

function renderCurrentUser() {
  const el = document.getElementById('current-username');
  if (el) el.textContent = currentUser.username;
  const av = document.getElementById('user-avatar-initials');
  if (av && currentUser.username) av.textContent = currentUser.username[0].toUpperCase();
}

function updateUserStatus(userId, online) {
  const dot = document.querySelector(`[data-user-id="${userId}"] .online-dot`);
  if (dot) dot.className = `online-dot ${online ? 'online' : 'offline'}`;
}

function setActiveSidebarItem(id, type) {
  document.querySelectorAll('.contact-item').forEach(li => li.classList.remove('active'));
  const el = type === 'user'
    ? document.querySelector(`[data-user-id="${id}"]`)
    : document.querySelector(`[data-group-id="${id}"]`);
  if (el) el.classList.add('active');
}

function updateUnreadBadge(id) {
  const el = document.querySelector(`[data-user-id="${id}"] .unread-badge, [data-group-id="${id}"] .unread-badge`);
  if (el) {
    el.textContent = (+el.textContent || 0) + 1;
    el.style.display = 'flex';
  }
}

function clearUnreadBadge(id) {
  const el = document.querySelector(`[data-user-id="${id}"] .unread-badge, [data-group-id="${id}"] .unread-badge`);
  if (el) {
    el.textContent = '';
    el.style.display = 'none';
  }
}

function showTypingIndicator(show) {
  const el = document.getElementById('typing-indicator');
  if (el) el.style.display = show ? 'block' : 'none';
}

function showConnectionBanner(connected) {
  const el = document.getElementById('conn-banner');
  if (el) {
    el.textContent = connected ? '' : '⚠️ Disconnected — reconnecting…';
    el.style.display = connected ? 'none' : 'block';
  }
}

function showAlert(msg, type = 'info') {
  const container = document.getElementById('chat-alert');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = msg;
  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.add('toast-out');
    setTimeout(() => toast.remove(), 250);
  }, 4000);
}

function closeModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.remove('open');
}

function logout() {
  fetch('/api/auth/logout', { method: 'POST', credentials: 'include' }).catch(() => {});
  SecureStorage.clearAll();
  window.location.href = '/login';
}

// ── API Helpers ──────────────────────────────────────────────────

function apiGet(url) {
  return fetch(url, { credentials: 'include' });
}

function apiPost(url, body) {
  return fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(body),
  });
}

function apiPut(url, body) {
  return fetch(url, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(body),
  });
}

// ── Typing debounce ──────────────────────────────────────────────

let _typingTimeout = null;
function onInputTyping() {
  if (!activeConversation) return;
  socket?.emit('typing', { recipient_id: activeConversation.id, is_typing: true });
  clearTimeout(_typingTimeout);
  _typingTimeout = setTimeout(() => {
    socket?.emit('typing', { recipient_id: activeConversation?.id, is_typing: false });
  }, 2000);
}

// ── Search ───────────────────────────────────────────────────────

let _searchTimeout = null;
function onSearch(e) {
  clearTimeout(_searchTimeout);
  _searchTimeout = setTimeout(() => loadUserList(e.target.value), 300);
}

// ── Init ─────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  if (!SecureStorage.hasIdentityKeys()) { window.location.href = '/login'; return; }

  initChat();

  document.getElementById('message-input')?.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
      e.preventDefault();
      sendMessage();
    } else {
      onInputTyping();
    }
  });
  document.getElementById('send-btn')?.addEventListener('click', e => {
    e.preventDefault();
    sendMessage();
  });
  document.getElementById('search-input')?.addEventListener('input', onSearch);
  document.getElementById('logout-btn')?.addEventListener('click', logout);

  // ── Emojis ──────────────────────────────────────────────────
  const EMOJIS = ['😀','😃','😄','😁','😆','😅','😂','🤣','🥲','☺️','😊','😇','🙂','🙃','😉','😌','😍','🥰','😘','😗','😙','😚','😋','😛','😝','😜','🤪','🤨','🧐','🤓','😎','🥸','🤩','🥳','😏','😒','😞','😔','😟','😕','🙁','☹️','😣','😖','😫','😩','🥺','😢','😭','😤','😠','😡','🤬','🤯','😳','🥵','🥶','😱','😨','😰','😥','😓','🤗','🤔','🤭','🤫','🤥','😶','😐','😑','😬','🙄','😯','😦','😧','😮','😲','🥱','😴','🤤','😪','😵','🤐','🥴','🤢','🤮','🤧','😷','🤒','🤕','🤑','🤠','😈','👿','👹','👺','🤡','💩','👻','💀','☠️','👽','👾','🤖','🎃','😺','😸','😹','😻','😼','😽','🙀','😿','😾'];

  const emojiGrid = document.getElementById('emoji-grid');
  if (emojiGrid) {
    EMOJIS.forEach(emo => {
      const el = document.createElement('div');
      el.className = 'emoji-item';
      el.textContent = emo;
      el.onclick = () => {
        const inp = document.getElementById('message-input');
        inp.value += emo;
        inp.focus();
      };
      emojiGrid.appendChild(el);
    });
  }

  const emojiBtn = document.getElementById('emoji-btn');
  const emojiPicker = document.getElementById('emoji-picker');
  if (emojiBtn && emojiPicker) {
    emojiBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      emojiPicker.style.display = emojiPicker.style.display === 'none' ? 'flex' : 'none';
    });
    document.addEventListener('click', e => {
      if (!emojiPicker.contains(e.target) && !emojiBtn.contains(e.target)) {
        emojiPicker.style.display = 'none';
      }
    });
  }

  // ── Self-destruct timer popup ────────────────────────────────
  const timerBtn = document.getElementById('timer-btn');
  const timerMenu = document.getElementById('timer-menu');
  if (timerBtn && timerMenu) {
    setSelectedTimer(0);
    timerBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      timerMenu.style.display = timerMenu.style.display === 'none' ? 'flex' : 'none';
    });
    timerMenu.querySelectorAll('.timer-option').forEach(opt => {
      opt.addEventListener('click', () => {
        setSelectedTimer(parseInt(opt.dataset.value));
        timerMenu.style.display = 'none';
      });
    });
    document.addEventListener('click', e => {
      if (!timerMenu.contains(e.target) && !timerBtn.contains(e.target)) {
        timerMenu.style.display = 'none';
      }
    });
  }

  // ── Attachments ────────────────────────────────────────────
  const attachBtn = document.getElementById('attach-btn');
  const fileInput = document.getElementById('file-input');
  const previewBox = document.getElementById('media-preview');
  const previewImg = document.getElementById('media-preview-img');
  const previewVid = document.getElementById('media-preview-video');
  const previewFile = document.getElementById('media-preview-file');
  const previewClose = document.getElementById('media-preview-close');

  if (attachBtn && fileInput) {
    attachBtn.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;

      const ext = getFileExtension(file.name);
      if (BLOCKED_FILE_EXTENSIONS.has(ext)) {
        showAlert(`⚠️ Files of type ".${ext}" cannot be sent for security reasons.`, 'warning');
        fileInput.value = '';
        return;
      }
      if (file.size > 5 * 1024 * 1024) {
        showAlert('⚠️ File too large. Max 5MB allowed.', 'warning');
        fileInput.value = '';
        return;
      }
      const buffer = await file.arrayBuffer();
      currentAttachment = { file, buffer };

      const mediaType = mediaTypeFor(file.type);
      previewImg.style.display = mediaType === 'image' ? 'block' : 'none';
      previewVid.style.display = mediaType === 'video' ? 'block' : 'none';
      previewFile.style.display = mediaType === 'file' ? 'flex' : 'none';

      const blobUrl = URL.createObjectURL(file);
      if (mediaType === 'image') previewImg.src = blobUrl;
      else if (mediaType === 'video') previewVid.src = blobUrl;
      else previewFile.textContent = `📎 ${file.name} (${formatFileSize(file.size)})`;

      previewBox.style.display = 'flex';
    });
    previewClose?.addEventListener('click', clearAttachment);
  }

  // ── Theme toggle ────────────────────────────────────────
  const themeBtn = document.getElementById('theme-btn');
  const applyTheme = (theme) => {
    document.documentElement.setAttribute('data-theme', theme);
    if (themeBtn) themeBtn.textContent = theme === 'light' ? '🌙' : '☀️';
    localStorage.setItem('theme', theme);
  };
  // Restore saved theme
  applyTheme(localStorage.getItem('theme') || 'dark');
  themeBtn?.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme') || 'dark';
    applyTheme(current === 'dark' ? 'light' : 'dark');
  });
});
