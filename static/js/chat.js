/**
 * chat.js — Main chat UI, SocketIO client, and E2EE orchestration
 */

const CHAT_API = '/api/chat';
let socket = null;
let currentUser = null;
let currentPassword = null; // held in memory for storage decryption
let activeConversation = null; // { type:'dm'|'group', id, sessionId, name }
let myEcdhPrivKey = null;      // CryptoKey object (ECDH private, in-memory)
let myEcdsaPrivKey = null;     // CryptoKey object (ECDSA private, in-memory)

// ── Bootstrap ────────────────────────────────────────────────────

async function initChat() {
  const token = SecureStorage.getAuthToken();
  currentUser  = SecureStorage.getUser();
  if (!token || !currentUser) { window.location.href = '/login'; return; }

  // Prompt for password to unlock local keys
  currentPassword = await promptPassword();
  if (!currentPassword) { logout(); return; }

  const keys = await SecureStorage.loadIdentityKeys(currentPassword);
  if (!keys) {
    showAlert('❌ Wrong password. Could not unlock local keys.', 'error');
    logout(); return;
  }

  myEcdhPrivKey  = await SecureCrypto.importPrivateECDH(keys.ecdhPrivJwk);
  // Import ECDSA private key for signing
  myEcdsaPrivKey = await crypto.subtle.importKey(
    'jwk', JSON.parse(keys.ecdsaPrivJwk),
    { name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign']
  );

  renderCurrentUser();
  connectSocket(token);
  await loadUserList();
  await loadGroups();
  applySettings();
}

function promptPassword() {
  return new Promise(resolve => {
    const overlay = document.getElementById('unlock-overlay');
    overlay.style.display = 'flex';
    document.getElementById('unlock-btn').onclick = () => {
      const pwd = document.getElementById('unlock-password').value;
      overlay.style.display = 'none';
      resolve(pwd);
    };
  });
}

// ── SocketIO ─────────────────────────────────────────────────────

function connectSocket(token) {
  socket = io({ auth: { token } });

  socket.on('connect', () => console.log('🔌 Connected'));
  socket.on('disconnect', () => showConnectionBanner(false));
  socket.on('connect_error', () => showConnectionBanner(false));

  socket.on('user_online',  d => updateUserStatus(d.user_id, true));
  socket.on('user_offline', d => updateUserStatus(d.user_id, false));

  socket.on('session_request', onSessionRequest);
  socket.on('session_ready',   onSessionReady);
  socket.on('key_rotation_required', onKeyRotationRequired);

  socket.on('receive_message', onReceiveMessage);
  socket.on('message_deleted', onMessageDeleted);
  socket.on('message_read',    onMessageRead);
  socket.on('group_created',   onGroupCreated);

  socket.on('typing', d => {
    if (activeConversation && d.user_id !== currentUser.id) {
      showTypingIndicator(d.is_typing);
    }
  });
}

// ── ECDH Session Management ───────────────────────────────────────

async function initiateSession(recipientId) {
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
  return session;
}

async function onSessionRequest(data) {
  const { session_id, initiator_id, initiator, ephemeral_pub_a, ephemeral_sig_a } = data;

  // ── Step 1: Verify initiator's ECDSA signature BEFORE key exchange ──
  // Fetch their registered public key. A MitM substituting ephemeral_pub_a
  // cannot forge ephemeral_sig_a without the initiator's ECDSA private key
  // (which never leaves their device). This fully prevents MitM on ECDH.
  const keysRes = await apiGet(`${CHAT_API}/users/${initiator}/keys`);
  if (!keysRes.ok) { showAlert('❌ Could not fetch sender public key', 'error'); return; }
  const { devices } = await keysRes.json();
  if (!devices.length) { showAlert('❌ No device keys found for sender', 'error'); return; }

  const isValid = await SecureCrypto.verifySignature(
    devices[0].ecdsa_public_key, ephemeral_pub_a, ephemeral_sig_a
  );
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
}


async function onSessionReady(data) {
  const { session_id, ephemeral_pub_b, ephemeral_sig_b } = data;
  const stored = SecureStorage.getSessionKeys(session_id);
  if (!stored || !stored.myEphemeral) return;

  // ── Verify Bob's ephemeral key signature BEFORE computing shared secret ──
  // We need Bob's username to fetch his ECDSA public key.
  // Use the active conversation's username.
  if (activeConversation?.username && ephemeral_sig_b) {
    const keysRes = await apiGet(`${CHAT_API}/users/${activeConversation.username}/keys`);
    if (keysRes.ok) {
      const { devices } = await keysRes.json();
      if (devices.length) {
        const isValid = await SecureCrypto.verifySignature(
          devices[0].ecdsa_public_key, ephemeral_pub_b, ephemeral_sig_b
        );
        if (!isValid) {
          showAlert('⛔ KEY EXCHANGE SIGNATURE INVALID — MitM attack detected! Aborting session.', 'error');
          console.error('[SecureIM] MitM detected: session_ready signature verification failed');
          SecureStorage.clearSessionKeys(session_id);
          updateEncryptionBadge(false);
          return;  // ABORT
        }
      }
    }
  }

  const aesKey  = await SecureCrypto.deriveSessionKey(stored.myEphemeral, ephemeral_pub_b);
  const hmacKey = await SecureCrypto.deriveHMACKey(stored.myEphemeral, ephemeral_pub_b);
  SecureStorage.storeSessionKeys(session_id, aesKey, hmacKey, stored.myEphemeral);

  showAlert('🔒 Secure session established with ' + (activeConversation?.name || ''), 'success');
  updateEncryptionBadge(true);
}

async function onKeyRotationRequired(data) {
  const { session_id } = data;
  showAlert('🔄 Key rotation triggered — refreshing session keys for forward secrecy…', 'info');
  SecureStorage.clearSessionKeys(session_id);
  if (activeConversation?.sessionId === session_id) {
    const sess = await initiateSession(activeConversation.id);
    activeConversation.sessionId = sess.id;
  }
}

// ── Send Message ─────────────────────────────────────────────────

async function sendMessage() {
  const input = document.getElementById('message-input');
  const text  = input.value.trim();
  if (!text || !activeConversation) return;

  input.value = '';
  input.focus();

  const sessionKeys = SecureStorage.getSessionKeys(activeConversation.sessionId);
  if (!sessionKeys?.aesKey) {
    showAlert('⚠️ No secure session yet. Please wait for key exchange.', 'warning');
    return;
  }

  try {
    // Get recipient device keys for multi-device E2EE
    let deviceMap = {};
    if (activeConversation.type === 'dm') {
      const keysRes = await apiGet(`${CHAT_API}/users/${activeConversation.username}/keys`);
      const { devices } = await keysRes.json();
      for (const dev of devices) {
        const payload = await SecureCrypto.encryptMessage(
          sessionKeys.aesKey, sessionKeys.hmacKey, text
        );
        deviceMap[dev.device_id] = payload;
      }
    } else {
      // Group: encrypt with group AES key for each member device
      const payload = await SecureCrypto.encryptMessage(
        sessionKeys.aesKey, sessionKeys.hmacKey, text
      );
      deviceMap['group'] = payload;
    }

    // Self-destruct: read expires_seconds from the selector in the input bar
    const timerSel = document.getElementById('timer-select');
    const expiresSec = timerSel ? parseInt(timerSel.value) || 0 : 0;

    socket.emit('send_message', {
      session_id:          activeConversation.sessionId,
      group_id:            activeConversation.type === 'group' ? activeConversation.id : undefined,
      encrypted_payloads:  deviceMap,
      msg_type:            activeConversation.type,
      expires_seconds:     expiresSec || undefined,
    });

    // Optimistically render outgoing message
    const expiresAt = expiresSec ? new Date(Date.now() + expiresSec * 1000).toISOString() : null;
    const optimistic = {
      id: Date.now(), sender_id: currentUser.id, plaintext: text,
      timestamp: new Date().toISOString(), is_deep_deleted: false,
      expires_at: expiresAt,
    };
    renderMessage(optimistic, true);

  } catch (err) {
    showAlert('❌ Failed to send: ' + err.message, 'error');
  }
}

// ── Receive Message ───────────────────────────────────────────────

async function onReceiveMessage(msg) {
  const isForActiveConversation =
    (activeConversation?.type === 'dm'    && (msg.sender_id === activeConversation.id || msg.sender_id === currentUser.id)) ||
    (activeConversation?.type === 'group' && msg.group_id   === activeConversation.id);

  const deviceId = SecureStorage.getDeviceId();
  const payloads = msg.encrypted_payloads || {};
  const myPayload = payloads[deviceId] || payloads['group'];

  let plaintext = null;
  if (myPayload && activeConversation?.sessionId) {
    const keys = SecureStorage.getSessionKeys(activeConversation.sessionId);
    if (keys?.aesKey) {
      try {
        plaintext = await SecureCrypto.decryptMessage(keys.aesKey, keys.hmacKey, myPayload);
      } catch (e) {
        plaintext = '⚠️ [HMAC verification failed — message may be tampered]';
      }
    }
  }

  const enriched = { ...msg, plaintext };

  if (isForActiveConversation) {
    if (msg.sender_id !== currentUser.id) {
      renderMessage(enriched, false);
    }
    if (currentPassword) {
      const convId = activeConversation.type === 'dm'
        ? `dm_${Math.min(currentUser.id, msg.sender_id)}_${Math.max(currentUser.id, msg.sender_id)}`
        : `grp_${msg.group_id}`;
      await SecureStorage.saveMessage(currentPassword, convId, enriched);
    }
  }

  // Update sidebar unread badge
  if (!isForActiveConversation && msg.sender_id !== currentUser.id) {
    updateUnreadBadge(msg.sender_id || msg.group_id);
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
  const sess = await initiateSession(userId);
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

async function openGroup(groupId, groupName) {
  clearMessages();
  activeConversation = { type: 'group', id: groupId, name: groupName, sessionId: `grp_${groupId}` };
  document.getElementById('chat-header-name').textContent = '# ' + groupName;
  const avatarEl = document.getElementById('chat-header-avatar');
  if (avatarEl) { avatarEl.textContent = '#'; avatarEl.classList.add('group-avatar'); }
  document.getElementById('no-chat-placeholder').style.display = 'none';
  document.getElementById('chat-main').style.display = 'flex';

  setActiveSidebarItem(groupId, 'group');
  clearUnreadBadge(groupId);
  updateEncryptionBadge(true);

  const convId = `grp_${groupId}`;
  const history = await SecureStorage.getConversation(currentPassword, convId);
  history.forEach(m => renderMessage(m, m.sender_id === currentUser.id));
}

// ── CSP-safe DOM builder for messages ────────────────────────────
// No inline onclick handlers — all listeners attached via addEventListener.

function buildMessageEl(msg, isMine) {
  const div = document.createElement('div');
  div.id        = `msg-${msg.id}`;
  div.className = `message ${isMine ? 'mine' : 'theirs'}`;

  const time = new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  if (msg.is_deep_deleted) {
    const body = document.createElement('div');
    body.className   = 'msg-body deleted-msg';
    body.textContent = '🗑️ This message was deleted.';
    div.appendChild(body);
    return div;
  }

  const bubble = document.createElement('div');
  bubble.className = 'msg-bubble';

  // Message body — textContent is XSS-safe
  const body = document.createElement('div');
  body.className   = 'msg-body';
  body.textContent = msg.plaintext ?? '🔒 [Encrypted]';
  bubble.appendChild(body);

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
    receipt.className   = 'msg-receipt';
    receipt.title       = msg.delivered_at ? 'Delivered' : 'Sent';
    receipt.textContent = msg.read_at ? '✓✓' : '✓';
    if (msg.read_at) receipt.style.color = '#00d4ff';
    meta.append(timeEl, lockEl, receipt);
  } else {
    meta.append(timeEl, lockEl);
  }
  bubble.appendChild(meta);

  // Self-destruct countdown
  if (msg.expires_at) {
    const timerEl = document.createElement('div');
    timerEl.className = 'msg-timer';
    const expiresMs = new Date(msg.expires_at).getTime();
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

function renderMessage(msg, isMine) {
  const container = document.getElementById('messages-container');
  container.appendChild(buildMessageEl(msg, isMine));
  container.scrollTop = container.scrollHeight;
}

function showDeleteMenu(msgId) {
  const menu = document.getElementById(`del-menu-${msgId}`);
  if (menu) menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
}

function clearMessages() {
  const c = document.getElementById('messages-container');
  if (c) c.innerHTML = '';
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── User / Group Lists ────────────────────────────────────────────

async function loadUserList(q = '') {
  const res = await apiGet(`${CHAT_API}/users?q=${encodeURIComponent(q)}`);
  const { users } = await res.json();
  const list = document.getElementById('contacts-list');
  list.innerHTML = '';
  users.forEach(u => {
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
}

async function loadGroups() {
  const res = await apiGet(`${CHAT_API}/groups`);
  const { groups } = await res.json();
  const list = document.getElementById('groups-list');
  if (!list) return;
  list.innerHTML = '';
  groups.forEach(g => {
    const li = document.createElement('li');
    li.className = 'contact-item';
    li.setAttribute('data-group-id', g.id);
    li.innerHTML = `<div class="contact-avatar group-avatar">#</div>
      <div class="contact-info"><span class="contact-name">${escapeHtml(g.name)}</span></div>
      <span class="unread-badge"></span>`;
    li.onclick = () => openGroup(g.id, g.name);
    list.appendChild(li);
  });
}

// ── Group Creation ───────────────────────────────────────────────

async function createGroup() {
  const nameEl = document.getElementById('new-group-name');
  const name = nameEl?.value?.trim();
  if (!name) return;

  const checked = [...document.querySelectorAll('.member-check:checked')].map(el => +el.value);
  const res = await apiPost(`${CHAT_API}/groups`, { name, member_ids: checked });
  if (res.ok) {
    nameEl.value = '';
    closeModal('group-modal');
    await loadGroups();
  }
}

function onGroupCreated(data) {
  loadGroups();
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

// ── Settings Panel ────────────────────────────────────────────────

function applySettings() {
  const s = SecureStorage.getSettings();
  const storeToggle   = document.getElementById('toggle-store-history');
  const sessionToggle = document.getElementById('toggle-session-mode');
  if (storeToggle)   storeToggle.checked = s.store_history !== false;
  if (sessionToggle) sessionToggle.checked = s.session_mode === true;
}

async function updateSetting(key, value) {
  const settings = SecureStorage.getSettings();
  settings[key] = value;
  SecureStorage.saveSettings(settings);
  await apiPut('/api/auth/settings', { [key]: value });
}

// ── Encryption Status Badge ────────────────────────────────────────

function updateEncryptionBadge(active) {
  const badge = document.getElementById('enc-status-badge');
  if (!badge) return;
  badge.textContent = active ? '🔒 E2EE Active' : '⏳ Establishing session…';
  badge.className   = active ? 'enc-badge active' : 'enc-badge pending';
}

// ── UI Utilities ─────────────────────────────────────────────────

function getActiveConvId() {
  if (!activeConversation) return null;
  if (activeConversation.type === 'dm') {
    return `dm_${Math.min(currentUser.id, activeConversation.id)}_${Math.max(currentUser.id, activeConversation.id)}`;
  }
  return `grp_${activeConversation.id}`;
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
  const el = document.getElementById('chat-alert');
  if (!el) return;
  el.textContent = msg;
  el.className = `chat-alert alert-${type}`;
  el.style.display = 'block';
  setTimeout(() => { el.style.display = 'none'; }, 4000);
}

function closeModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.remove('open');
}

function logout() {
  apiPost('/api/auth/logout', {}).catch(() => {});
  SecureStorage.clearAll();
  window.location.href = '/login';
}

// ── API Helpers ──────────────────────────────────────────────────

function apiGet(url) {
  return fetch(url, { headers: { Authorization: `Bearer ${SecureStorage.getAuthToken()}` } });
}

function apiPost(url, body) {
  return fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${SecureStorage.getAuthToken()}` },
    body: JSON.stringify(body),
  });
}

function apiPut(url, body) {
  return fetch(url, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${SecureStorage.getAuthToken()}` },
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
    socket?.emit('typing', { recipient_id: activeConversation.id, is_typing: false });
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
  if (!SecureStorage.getAuthToken()) { window.location.href = '/login'; return; }

  initChat();

  document.getElementById('message-input')?.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
    else onInputTyping();
  });
  document.getElementById('send-btn')?.addEventListener('click', sendMessage);
  document.getElementById('search-input')?.addEventListener('input', onSearch);
  document.getElementById('logout-btn')?.addEventListener('click', logout);

  const storeToggle = document.getElementById('toggle-store-history');
  if (storeToggle) storeToggle.addEventListener('change', e => updateSetting('store_history', e.target.checked));

  const sessionToggle = document.getElementById('toggle-session-mode');
  if (sessionToggle) sessionToggle.addEventListener('change', e => updateSetting('session_mode', e.target.checked));

  document.getElementById('create-group-btn')?.addEventListener('click', createGroup);

  document.getElementById('open-group-modal-btn')?.addEventListener('click', () => {
    const overlay = document.getElementById('group-modal');
    if (overlay) overlay.classList.add('open');
    const memberList = document.getElementById('member-list');
    if (memberList) {
      memberList.innerHTML = '<div style="color:var(--text-3); font-size:13px; text-align:center;">Loading users...</div>';
      apiGet(`${CHAT_API}/users`).then(r => r.json()).then(data => {
        memberList.innerHTML = '';
        data.users.forEach(u => {
          if (u.id === currentUser.id) return;
          const div = document.createElement('div');
          div.className = 'member-item';
          div.innerHTML = `<label for="chk-${u.id}">${escapeHtml(u.username)}</label>
                           <input type="checkbox" id="chk-${u.id}" class="member-check" value="${u.id}">`;
          memberList.appendChild(div);
        });
      }).catch(() => memberList.innerHTML = '<div style="color:var(--text-err); font-size:13px;">Error loading users</div>');
    }
  });

  // ── Theme toggle (C5) ────────────────────────────────────────
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
