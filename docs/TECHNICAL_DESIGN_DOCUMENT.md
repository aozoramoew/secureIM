# SecureIM — Technical Design Document

**Project:** Secure Messaging System (Project 1)
**Version:** 1.0
**Live Deployment:** https://web-production-ce7b.up.railway.app/
**Date:** 2026-06-10

---

## 1. Introduction

### 1.1 Purpose

SecureIM is a cross-platform, web-based Instant Messaging (IM) system designed around a **Zero-Trust** architecture. The central design assumption is that the server, the network, and any intermediate infrastructure (hosting provider, reverse proxies, database operators) are **untrusted**. The system is engineered so that confidentiality and integrity of message content do not depend on the server behaving honestly.

This document describes:

- The **Threat Model** the system was designed against.
- **Data Flow Diagrams (DFDs)** describing how data moves through the system, with trust boundaries explicitly marked.
- A **justification of the cryptographic libraries and algorithms** chosen for each security property required by the project specification.

### 1.2 Scope

The current deployment (commit `4f2ac13`, FastAPI migration) implements:

- End-to-End Encryption (E2EE) for one-to-one (direct message) conversations.
- ECDH-based key exchange with identity-bound (signed) ephemeral keys.
- Message integrity via AES-256-GCM authentication tags **and** an explicit HMAC-SHA256.
- Forward secrecy via per-session ephemeral ECDH keys and periodic key rotation.
- Identity management via per-device ECDSA/ECDH key pairs linked to user accounts.
- Encrypted client-side local storage (chat history, identity keys, contacts) using AES-256-GCM with PBKDF2-derived keys.
- Self-destructing messages with server-side hard deletion of ciphertext.
- Out-of-band contact verification ("Verified" badges) via SHA-256 key fingerprints.
- A work-in-progress encrypted file/image attachment pipeline.

---

## 2. System Architecture Overview

### 2.1 Components

| Component | Technology | Responsibility |
|---|---|---|
| Web/API server | FastAPI (Python), ASGI via Uvicorn/Gunicorn | Serves static assets, REST API for auth/session/contacts, hosts the Socket.IO server |
| Real-time transport | python-socketio (AsyncServer, ASGI mode) | Relays encrypted message envelopes and signaling messages between connected clients |
| Database | SQLAlchemy ORM, SQLite (dev) / PostgreSQL (production, Railway) | Stores user accounts, device public keys, **encrypted** message payloads, session metadata, audit logs |
| Background scheduler | APScheduler | Periodically purges expired ("self-destruct") messages |
| Client | Vanilla JavaScript + Web Crypto API | Performs **all** cryptographic operations: key generation, ECDH, signing/verification, AES-GCM encryption/decryption, HMAC computation, PBKDF2-based local storage encryption |
| Hosting | Railway (Nixpacks build, Gunicorn + Uvicorn worker) | Production deployment at `https://web-production-ce7b.up.railway.app/` |

### 2.2 Trust Boundary

The single most important architectural decision is the placement of the **trust boundary at the browser tab boundary**. Everything to the left of this boundary (the user's browser, holding plaintext and private keys in memory/localStorage) is trusted. Everything to the right (network, server, database, hosting provider) is **untrusted** and is assumed to be a passive or active adversary (per the threat model in Section 3).

```
 ┌─────────────────────────┐        ┌──────────────────────────────────────┐
 │   CLIENT (Browser)       │        │         SERVER (Untrusted Relay)      │
 │   TRUSTED ZONE           │        │         UNTRUSTED ZONE                │
 │                          │        │                                       │
 │  - Plaintext messages    │ ‖TLS‖  │  - Ciphertext + HMAC only             │
 │  - Private keys (ECDSA,  │ ====>  │  - Public keys only                   │
 │    ECDH)                 │ <====  │  - User metadata (username, hashes)  │
 │  - Session AES/HMAC keys │        │  - Audit logs (event types, no       │
 │  - Argon2/PBKDF2 derived │        │    plaintext)                         │
 │    storage keys          │        │                                       │
 └─────────────────────────┘        └──────────────────────────────────────┘
        TRUST BOUNDARY  ───────────────────►
```

---

## 3. Threat Model

### 3.1 Methodology

The threat model follows a simplified **STRIDE**-oriented approach, focused on the assets and adversaries most relevant to an IM system, as required by the project brief: eavesdropping, identity spoofing, MitM, replay, bit-flipping, and server-side compromise.

### 3.2 Assets

| Asset | Description | Confidentiality | Integrity | Availability |
|---|---|---|---|---|
| A1 — Message plaintext | Text/file content exchanged between two users | Critical | Critical | Medium |
| A2 — Long-term identity private keys (ECDSA P-384, ECDH P-256) | Per-device keys that anchor a user's identity | Critical | Critical | High |
| A3 — Session keys (AES-256-GCM key, HMAC-SHA256 key) | Derived per-conversation via ECDH+HKDF | Critical | Critical | Medium |
| A4 — User credentials (password) | Used to authenticate and to derive local storage encryption key | Critical | Critical | Medium |
| A5 — JWT session cookie | Authenticates the browser to the server | High | High | Medium |
| A6 — Contact public keys & fingerprints | Used for MitM detection via out-of-band verification | Medium | Critical | Low |
| A7 — Server-side metadata (who talks to whom, when) | Stored in `Message`, `ChatSession`, `AuditLog` tables | Medium | Medium | Medium |

### 3.3 Adversaries

| ID | Adversary | Capabilities | Position |
|---|---|---|---|
| T1 — Network eavesdropper | Passive observer of traffic between client and server | Outside trust boundary | Network / ISP / Wi-Fi |
| T2 — Active MitM | Can intercept, modify, drop, or inject network traffic, including TLS-stripping attempts | Outside trust boundary | Network |
| T3 — Malicious / compromised server operator | Full read/write access to the database, application code, and live process memory of the server | Defines the untrusted zone | Server |
| T4 — Malicious peer / impersonator | A registered user attempting to impersonate another user or hijack a session | Inside the application, outside victim's trust boundary | Application |
| T5 — Local attacker on client device | Has access to the victim's browser localStorage / disk (e.g., shared computer, malware) | Partially inside trust boundary | Client |
| T6 — Replay/Tamper attacker | Captures legitimate ciphertext and attempts to resend or bit-flip it | Network / Server | Network/Server |

### 3.4 Threat Analysis & Mitigations

#### T1 — Network Eavesdropper (Confidentiality of A1, A3)

- **Threat:** Capture traffic between browser and server to read message content.
- **Mitigations:**
  1. **Transport-layer**: All traffic served over HTTPS/WSS (enforced by Railway's TLS termination and `Strict-Transport-Security` header in `app/security.py`).
  2. **Application-layer (defense in depth)**: Even if TLS were broken, message bodies are AES-256-GCM ciphertext (`static/js/crypto.js`). The eavesdropper sees only `{ciphertext, nonce, hmac}` — no plaintext is ever transmitted.
- **Residual risk:** Traffic metadata (message size, timing, sender/recipient IDs) is visible to a network observer. This is an inherent limitation of a centralized relay architecture and is documented as an accepted residual risk (no traffic padding/mixing is implemented).

#### T2 — Active Man-in-the-Middle

- **Threat:** An attacker positioned between client and server (or controlling the server itself, T3) attempts to substitute their own ECDH public key during the key exchange handshake, performing a classic MitM key-substitution attack.
- **Mitigations:**
  1. **Signed ephemeral keys**: Every ephemeral ECDH P-256 public key is signed with the sender's long-term **ECDSA P-384** identity private key before being sent (`static/js/chat.js`, session initiation flow).
  2. **Mandatory signature verification**: The receiving party fetches the sender's published ECDSA public key (registered at account creation, stored in `DeviceKey.ecdsa_public_key`) and verifies the signature **before** deriving any session key. If verification fails, the session is aborted and no key material is derived.
  3. **Out-of-band identity verification ("Verified" badges)**: Because the server itself controls which ECDSA public key is "published" for a user (T3 — server compromise), signature verification alone does not fully rule out a malicious server substituting an attacker's key pair *and* its corresponding public key at registration time. To close this gap, SecureIM implements manual, out-of-band fingerprint verification: users compute a SHA-256 fingerprint of a contact's ECDSA public key and compare it via a side channel (e.g., in person, voice call). Verified contacts are marked in the `ContactVerification` table and shown with a green "✅ Verified" badge in the UI.
- **Residual risk:** Until a contact is manually verified, a malicious server (T3) could theoretically present a substituted identity key on first contact ("Trust On First Use" gap), which is an inherent limitation of any system without a separate, independently-trusted PKI/CA — the project brief explicitly scopes this to manual out-of-band verification rather than a third-party CA.

#### T3 — Malicious / Compromised Server

- **Threat:** The server operator (or an attacker who has compromised the server/database) attempts to read message content, forge messages, or tamper with stored data.
- **Mitigations:**
  1. **Zero plaintext storage**: The `Message.encrypted_payloads` column never contains plaintext — only `{device_id: {ciphertext, nonce, hmac}}` per recipient device (`app/models.py`). The server has no decryption keys; AES-256-GCM session keys exist only in browser memory (derived via ECDH, never transmitted).
  2. **Forgery resistance**: Even with full database write access, the server cannot forge a valid message because it cannot produce a valid HMAC-SHA256 (key never leaves the client) nor a valid AES-GCM authentication tag.
  3. **Audit logging without content**: `AuditLog` records security-relevant events (`login_ok`, `login_fail`, `register`, etc.) with `event_type`, `ip_address`, `user_agent`, but **never** message content (`app/models.py`, lines ~188-210).
  4. **Self-destruct hard delete**: When a message expires, the scheduler (`app/scheduler.py`) overwrites `encrypted_payloads` with `'{}'` and sets `is_deep_deleted=True`, so even a database snapshot taken after expiry cannot recover the ciphertext.
- **Residual risk:** The server retains **metadata** — who messaged whom and when (`Message.sender_id`, `recipient_id`, `timestamp`), and total message counts (`ChatSession.message_count`). This is an accepted trade-off of a centralized relay model and is explicitly called out as a residual risk rather than hidden.

#### T4 — Malicious Peer / Impersonation

- **Threat:** A registered user attempts to impersonate another user, or hijack a session belonging to someone else.
- **Mitigations:**
  1. **Per-device identity binding**: Every device generates its own ECDSA P-384 / ECDH P-256 key pair at registration (`app/auth.py`), stored in `DeviceKey`, tied to a `user_id`.
  2. **JWT-based authentication**: All REST and Socket.IO actions require a valid JWT (HS256, `JWT_SECRET_KEY`) delivered via an `HttpOnly`, `Secure`, `SameSite=Strict` cookie (`sim_token`), preventing session-cookie theft via XSS and cross-site request forgery.
  3. **Argon2id password hashing**: Credentials are never stored in recoverable form (`app/crypto_utils.py` — Argon2id, 64 MB memory cost, 3 iterations, parallelism 4).

#### T5 — Local Attacker (Client-Side Storage)

- **Threat:** An attacker with access to the victim's browser storage (shared/public computer, device theft, browser extension malware) attempts to extract chat history or private keys from `localStorage`.
- **Mitigations:**
  1. **Encrypted local storage**: All persisted data — chat history (`sim_hist_*`), identity private keys (`sim_identity`), contacts (`sim_contacts`), settings (`sim_settings`), user object (`sim_user`), device ID — is encrypted with AES-256-GCM using a key derived from the user's password via **PBKDF2-SHA256 with 310,000 iterations** (OWASP 2023/2024 recommended minimum) (`static/js/crypto.js`, `static/js/storage.js`).
  2. **Session Mode**: Users may opt into a mode where chat history is held only in memory for the active tab session and is never written to `localStorage`, eliminating persistence entirely for highly sensitive conversations.
  3. **Password never persisted**: The password is held only transiently in a JS variable for the duration needed to derive the storage key and is never written to disk.
- **Residual risk:** If the attacker can run arbitrary JavaScript in the page's origin (e.g., a successful XSS), the in-memory password and derived keys are exposed. This is mitigated by the strict CSP (`app/security.py`) which disallows inline scripts and restricts script sources to `'self'`.

#### T6 — Replay & Bit-Flipping

- **Threat:** An attacker (network or server) captures a previously sent ciphertext and (a) re-transmits it later (replay), or (b) flips bits in the ciphertext hoping to produce a meaningful plaintext change after decryption (bit-flipping, classically effective against unauthenticated stream/CTR ciphers).
- **Mitigations:**
  1. **Bit-flipping**: AES-256-GCM is an AEAD (Authenticated Encryption with Associated Data) mode — any modification to the ciphertext or nonce causes GCM tag verification to fail and `crypto.subtle.decrypt()` throws. In addition, an **independent HMAC-SHA256** (computed over `nonce || ciphertext` with a key derived separately via HKDF) is verified *before* attempting AES-GCM decryption (`static/js/crypto.js`), providing defense-in-depth against any future implementation that might use a non-AEAD cipher.
  2. **Replay**: Each message uses a fresh, random 96-bit nonce (`crypto.getRandomValues()`), so the same plaintext never produces the same ciphertext twice. Messages are bound to a specific `session_id` (ECDH session) and carry a server-assigned monotonically increasing `id` plus a `timestamp`. A replayed message would decrypt successfully (since GCM/HMAC would still validate against the *original* nonce/ciphertext pair) but would appear as a duplicate with stale content and an out-of-order/duplicate `id`/`timestamp`, which the client UI can detect and the user can recognize as already-seen content.
  3. See Section "Areas for Future Hardening" (Security Audit Report, Section 6) for a discussion of explicit per-message anti-replay tokens, which is identified as a gap rather than a solved problem.

---

## 4. Data Flow Diagrams (DFDs)

### 4.1 DFD Level 0 — Context Diagram

```
                 +------------------+
                 |    User A        |
                 |   (Browser)      |
                 +--------+---------+
                          |
              HTTPS/WSS (TLS)  -- ciphertext, public keys, signed handshakes
                          |
                 +--------v---------+
                 |  SecureIM Server  |
                 |  (FastAPI +       |
                 |   Socket.IO +     |
                 |   PostgreSQL)     |
                 +--------+---------+
                          |
              HTTPS/WSS (TLS)  -- ciphertext, public keys, signed handshakes
                          |
                 +--------v---------+
                 |    User B        |
                 |   (Browser)      |
                 +------------------+
```

### 4.2 DFD Level 1 — Registration & Identity Provisioning

```
[User] --(username, password)--> [Browser: auth.js]
   |
   |  1. Generate device_id (random)
   |  2. Generate ECDSA P-384 key pair (identity/signing)
   |  3. Generate ECDH P-256 key pair (key exchange)
   |  4. Derive PBKDF2(password, salt, 310k) -> local storage key
   |  5. Encrypt private keys with AES-256-GCM(local storage key) -> sim_identity
   |
   v
[POST /api/auth/register] --(username, password, device_id,
                               ecdsa_pub_jwk, ecdh_pub_jwk)--> [FastAPI: auth.py]
   |
   |  6. Argon2id(password) -> password_hash
   |  7. INSERT User(username, password_hash)
   |  8. INSERT DeviceKey(user_id, device_id, ecdsa_public_key, ecdh_public_key)
   |  9. Issue JWT (HS256) -> Set-Cookie sim_token (HttpOnly, Secure, SameSite=Strict)
   |
   v
[PostgreSQL/SQLite]: Users, DeviceKeys tables
```

**Trust boundary crossing:** Steps 1-5 occur entirely client-side (trusted zone). Only `password` (over TLS, hashed immediately server-side with Argon2id) and **public** keys cross into the untrusted zone in step 6-8. Private keys never leave the browser.

### 4.3 DFD Level 1 — ECDH Session Establishment (Key Exchange)

```
[User A Browser]                         [Server (Relay)]                    [User B Browser]
       |                                         |                                   |
1. Generate ephemeral ECDH P-256 key pair        |                                   |
2. Sign ephemeral_pub_A with long-term           |                                   |
   ECDSA P-384 private key -> sig_A              |                                   |
       |---- session_request{ephemeral_pub_A,    |                                   |
       |       sig_A, device_id} -------------->| 3. Store in ChatSession           |
       |                                         |    (ephemeral_pub_a, sig_a)        |
       |                                         |---- relay session_request ------->|
       |                                         |                                   | 4. Fetch User A's
       |                                         |                                   |    ECDSA pub key
       |                                         |<--- GET /devices/{A}/keys --------|
       |                                         |---- ecdsa_pub_A ------------------>|
       |                                         |                                   | 5. Verify sig_A over
       |                                         |                                   |    ephemeral_pub_A
       |                                         |                                   |    -> ABORT if invalid
       |                                         |                                   | 6. Generate ephemeral
       |                                         |                                   |    ECDH P-256 pair
       |                                         |                                   | 7. Sign ephemeral_pub_B
       |                                         |                                   |    with ECDSA P-384
       |                                         |<--- session_ready{ephemeral_pub_B,|
       |                                         |       sig_B} ---------------------|
       |<--- relay session_ready ----------------|                                   |
8. Verify sig_B (ECDSA pub key of B)             |                                   |
   -> ABORT if invalid                           |                                   |
9. ECDH(ephemeral_priv_A, ephemeral_pub_B)       | 9. (mirrored)                    |
   -> shared_secret (256-bit)                    |   ECDH(ephemeral_priv_B,          |
                                                  |   ephemeral_pub_A) -> shared_secret|
10. HKDF-SHA256(shared_secret,                   |                                   |
    salt=32x0x00, info="SecureIM-v1-session-key")|                                   |
    -> AES-256-GCM session key                   |     (mirrored on B's side)        |
    HKDF(..., info="SecureIM-v1-hmac-key")       |                                   |
    -> HMAC-SHA256 key                           |                                   |
       |                                         |                                   |
[Both parties now hold identical AES + HMAC keys, never transmitted]
```

**Key Properties:**
- The server only ever sees: ephemeral *public* keys, ECDSA *signatures*, and long-term *public* keys. No private key material or shared secret crosses the trust boundary.
- A compromised server (T3) cannot derive the shared secret because ECDH requires a private key it does not possess.
- An active MitM (T2) cannot substitute an ephemeral public key without invalidating the ECDSA signature, which is checked against the (separately registered) long-term public key.

### 4.4 DFD Level 1 — Message Send/Receive (Steady State)

```
[User A Browser]                                [Server]                        [User B Browser]
      |                                             |                                   |
1. plaintext message (text or file)                |                                   |
2. nonce = random(96 bits)                         |                                   |
3. ciphertext = AES-256-GCM-Encrypt(               |                                   |
       session_aes_key, nonce, plaintext)          |                                   |
4. hmac = HMAC-SHA256(session_hmac_key,            |                                   |
       nonce || ciphertext)                        |                                   |
5. payload = {ciphertext, nonce, hmac}             |                                   |
   (per recipient device_id, since multi-device)   |                                   |
      |---- socket.emit('send_message', {          |                                   |
      |        encrypted_payloads: {dev_B: payload}|                                   |
      |        recipient_id, session_id,           |                                   |
      |        msg_type: 'dm', expires_seconds })  |                                   |
      |-------------------------------------------->|                                   |
      |                                  6. INSERT Message(                            |
      |                                     sender_id, recipient_id,                   |
      |                                     encrypted_payloads, timestamp,             |
      |                                     expires_at, session_id)                    |
      |                                  7. message_count += 1 on ChatSession          |
      |                                     -> if >= KEY_ROTATION_THRESHOLD,           |
      |                                        emit 'key_rotation_required'            |
      |                                  8. emit('receive_message', {payload, ...})    |
      |<--------------------------------------------|---------------------------------->|
                                                      |                                   |
                                                      |                  9. Verify HMAC-SHA256
                                                      |                     (session_hmac_key)
                                                      |                     -> reject if mismatch
                                                      |                  10. AES-256-GCM-Decrypt
                                                      |                      (session_aes_key, nonce,
                                                      |                       ciphertext)
                                                      |                      -> reject if GCM tag invalid
                                                      |                  11. Render plaintext
                                                      |                  12. (optional) Encrypt
                                                      |                      with PBKDF2-derived
                                                      |                      local storage key
                                                      |                      -> persist to localStorage
```

### 4.5 DFD Level 1 — Self-Destruct (Expiring Message) Flow

```
[User Browser] --(expires_seconds=N)--> [send_message event]
                                              |
                                              v
                              [Message row: expires_at = now()+N]
                                              |
                          (every 30s, background job)
                                              v
                          [APScheduler: cleanup_expired_messages]
                              - WHERE expires_at <= now()
                              - SET encrypted_payloads = '{}'
                              - SET is_deep_deleted = True
                              - SET deep_deleted_at = now()
                                              |
                                              v
                          [emit 'message_deleted' {type:'expired'}]
                                              |
                              -----------------------------
                              |                           |
                              v                           v
                     [Sender Browser]            [Recipient Browser]
                     remove from UI/local        remove from UI/local
                     storage                     storage
```

### 4.6 DFD Level 1 — Encrypted Local Storage (Client-Side Persistence)

```
[Password (in-memory only)]
       |
       v  PBKDF2-SHA256(password, salt=32 random bytes, iterations=310,000)
[storage_key (256-bit)]
       |
       +--> AES-256-GCM-Encrypt(storage_key, nonce, identity_keys_JWK)  --> localStorage["sim_identity"]
       +--> AES-256-GCM-Encrypt(storage_key, nonce, chat_history)        --> localStorage["sim_hist_<conv_id>"]
       +--> AES-256-GCM-Encrypt(storage_key, nonce, contacts_list)       --> localStorage["sim_contacts"]
       +--> AES-256-GCM-Encrypt(storage_key, nonce, user_object)         --> localStorage["sim_user"]
       +--> AES-256-GCM-Encrypt(storage_key, nonce, settings)            --> localStorage["sim_settings"]
       +--> AES-256-GCM-Encrypt(storage_key, nonce, device_id)           --> localStorage["sim_device_id"]

  salt stored in plaintext alongside ciphertext (sim_storage_meta) -- standard PBKDF2 practice,
  salt is not secret, only the password + salt + iteration count together produce storage_key.

  [Session Mode = ON] --> chat history kept in JS memory only, never written to localStorage,
                          discarded on tab close / refresh.
```

---

## 5. Cryptographic Library & Algorithm Justification

### 5.1 Summary Table

| Requirement (per project brief) | Chosen Algorithm/Library | Justification |
|---|---|---|
| Key Exchange (ECDH) | **ECDH over NIST P-256**, via browser **Web Crypto API** (`crypto.subtle`) | P-256 is FIPS-approved, has broad native browser support (no external JS crypto library needed, reducing supply-chain risk), and offers ~128-bit security — sufficient for session key establishment given keys are ephemeral and rotated frequently. |
| Identity / Digital Signatures | **ECDSA over NIST P-384**, via Web Crypto API | A higher security margin (~192-bit) is used for *long-term* identity keys since their compromise has long-lasting impact, whereas ephemeral ECDH keys (P-256) are short-lived. Native Web Crypto support avoids bundling external signature libraries. |
| Symmetric Encryption (E2EE payload) | **AES-256-GCM**, via Web Crypto API | AES-GCM is an AEAD cipher providing confidentiality **and** integrity/authenticity in one primitive, satisfying both the E2EE and the "Data Integrity & Authenticity" requirements simultaneously. AES-256 provides a large security margin against brute force. Hardware-accelerated (AES-NI) on essentially all modern devices, so no measurable performance penalty in-browser. |
| Message Authentication (explicit) | **HMAC-SHA256** (independent key derived via HKDF), via Web Crypto API | While AES-GCM already authenticates the ciphertext, an additional, independently-keyed HMAC-SHA256 is computed over `nonce ‖ ciphertext`. This gives defense-in-depth: if a future change swapped the cipher for a non-AEAD mode, the explicit HMAC layer would still satisfy the project's mandatory "HMAC for every message" requirement, and it allows integrity verification to be checked *before* the (more expensive) AEAD decryption is attempted. |
| Key Derivation (session keys) | **HKDF-SHA256** (RFC 5869), via Web Crypto API | HKDF is the standard, cryptographically sound method to derive multiple independent keys (AES key, HMAC key) from a single ECDH shared secret, using domain-separation via distinct `info` strings (`"SecureIM-v1-session-key"`, `"SecureIM-v1-hmac-key"`). This avoids any key reuse between encryption and authentication, a classic cryptographic pitfall. |
| Key Derivation (local storage, password-based) | **PBKDF2-SHA256, 310,000 iterations**, via Web Crypto API | PBKDF2 is natively available in all browsers without external dependencies. 310,000 iterations matches OWASP's 2023 recommendation for PBKDF2-HMAC-SHA256, providing strong resistance to offline brute-force/dictionary attacks against the user's password while keeping derivation latency (~100-300ms) acceptable for UX. *(Argon2 was considered per the brief but was not chosen for the browser-side derivation because no mature, audited, pure-WebAssembly Argon2 implementation ships natively in Web Crypto; PBKDF2 was selected to avoid adding an external/unaudited crypto dependency to the trusted client codebase. Argon2id IS used server-side — see below.)* |
| Password Storage (server-side) | **Argon2id**, via `argon2-cffi` (Python) | Argon2id won the Password Hashing Competition and is the current OWASP #1 recommendation for password storage. Configured with memory cost 64 MB, time cost 3, parallelism 4, salt 16 bytes, hash length 32 bytes — these parameters resist GPU/ASIC cracking far better than PBKDF2/bcrypt at equivalent latency. Used exclusively for authenticating login (never for deriving encryption keys), so the lack of a browser-native implementation is irrelevant. |
| Session Authentication Token | **JWT (HS256 / HMAC-SHA256)** via `PyJWT` | HS256 is sufficient because the JWT is both issued and verified by the same server (no third-party verification needed), avoiding the complexity/key-management overhead of asymmetric JWT signing (RS256). Delivered exclusively via an `HttpOnly`, `Secure`, `SameSite=Strict` cookie to mitigate XSS token theft and CSRF. |
| Forward Secrecy | **Ephemeral ECDH (P-256) key pairs per session + periodic rotation** | Per the project's Forward Secrecy requirement: ephemeral keys are generated fresh for each ECDH handshake and exist only in browser memory, never persisted. The `KEY_ROTATION_THRESHOLD` (default 100 messages) forces a fresh ECDH handshake for long-lived conversations, bounding the amount of traffic protected by any single derived key and limiting exposure if a session key were somehow compromised. |
| Local Database | **SQLAlchemy ORM + SQLite (dev) / PostgreSQL (prod)** | Standard, well-audited ORMs with parameterized queries by default, mitigating SQL injection. PostgreSQL chosen for production (Railway) for durability and concurrent-connection support under a real ASGI server; SQLite used for local development for zero-setup convenience. |
| Real-time Transport | **python-socketio (AsyncServer, ASGI)** | Provides WebSocket transport with automatic fallback, integrates natively with FastAPI's ASGI app, and supports the binary/JSON message sizes needed for encrypted attachments (configured 25 MB max buffer). |
| Web Framework | **FastAPI** | Chosen for native `async`/`await` support (required for efficient Socket.IO + DB I/O concurrency), automatic request validation via Pydantic (reduces input-validation bugs), and built-in OpenAPI documentation for the REST surface. |

### 5.2 Identity Key Algorithm Choice: ECDSA P-384 / ECDH P-256 vs. RSA-4096 / Ed25519

The project brief suggests RSA-4096 or Ed25519 for identity keys. SecureIM instead uses **ECDSA P-384** (signing) and **ECDH P-256** (key exchange), both via the browser's native **Web Crypto API**. Rationale:

1. **No external dependencies in the trusted client**: Ed25519 is *not* supported by `crypto.subtle` in all major browsers at the time of writing without polyfills, which would require bundling a third-party JS crypto library — directly increasing the attack surface of the most security-critical code (client-side key handling). NIST curves (P-256/P-384) are universally supported natively.
2. **RSA-4096 is computationally heavy** for repeated browser-side signing operations (every ephemeral key exchange requires a fresh signature) and produces much larger signatures/keys, increasing message overhead. ECDSA P-384 provides a comparable (actually higher, ~192-bit vs ~150-bit) security level with dramatically smaller keys/signatures and faster operations.
3. **Curve separation by purpose**: P-384 for long-term identity (higher margin, infrequent operations) vs. P-256 for ephemeral session keys (frequent operations, short lifetime) is a deliberate defense-in-depth choice — even in the (currently theoretical) event of a cryptanalytic weakness specific to P-256, long-term identities remain protected by the stronger P-384 curve.

This is documented here as a **deviation from the literal algorithm names in the brief**, while satisfying the underlying requirement (asymmetric identity keys, signature-based authenticity, modern elliptic-curve cryptography).

---

## 6. Identity Management & Session Orchestration

### 6.1 Identity Management

- Each **user account** (`User` table) is identified by a unique, case-insensitive username and an Argon2id password hash.
- Each **device** a user logs in from registers its own `DeviceKey` record containing:
  - `device_id` — a randomly generated, persistent identifier for that browser/device.
  - `ecdsa_public_key` — long-term identity/signing public key (JWK, P-384).
  - `ecdh_public_key` — long-term key-exchange public key (JWK, P-256), used to bootstrap the very first session with a new contact.
- This design supports **multi-device** accounts: a message sent to a user is encrypted separately for each of that user's active devices (`encrypted_payloads: {device_id: {...}}`).
- Devices can be **revoked** via `DELETE /api/auth/devices/{device_id}`, immediately invalidating that device's ability to receive new messages.

### 6.2 Session Orchestration

- **Initialization**: A `ChatSession` row is created when two users first establish an ECDH handshake, recording both parties' signed ephemeral public keys.
- **Maintenance**: `message_count` is incremented per message; once it reaches `KEY_ROTATION_THRESHOLD` (configurable, default 100), the server signals `key_rotation_required`, prompting both clients to perform a fresh ECDH handshake and derive new session keys — implementing the brief's "key rotation policy for long-term conversations."
- **Termination**: Sessions are marked `is_active = False` when no longer needed; ephemeral private keys are discarded from browser memory (never persisted), so termination is effectively instantaneous and irreversible from a key-recovery standpoint.

---

## 7. Current Implementation Status vs. Project Requirements

| Requirement | Status | Notes |
|---|---|---|
| End-to-End Encryption | ✅ Implemented | AES-256-GCM, server stores ciphertext only |
| ECDH Key Exchange | ✅ Implemented | ECDH P-256, signed with ECDSA P-384, HKDF-SHA256 derivation |
| HMAC / Digital Signatures for integrity | ✅ Implemented | AES-GCM tag + explicit HMAC-SHA256 |
| Forward Secrecy | ✅ Implemented | Ephemeral ECDH keys + rotation every N messages |
| Identity Management (asymmetric key pairs) | ✅ Implemented | ECDSA P-384 + ECDH P-256 per device (deviation from RSA/Ed25519, justified in §5.2) |
| Session Orchestration & Key Rotation | ✅ Implemented | `ChatSession` model, `KEY_ROTATION_THRESHOLD` |
| Secure Local Storage (AES-256-GCM + PBKDF2/Argon2) | ✅ Implemented | AES-256-GCM with PBKDF2-SHA256 (310k iterations) |
| Security UI/UX (Verified badges, encryption status) | ✅ Implemented | "Verified" badge via fingerprint comparison; live encryption-status indicator |
| Self-destructing messages | ✅ Implemented | Server-side hard delete via APScheduler every 30s |
| File / Image attachments (E2EE) | 🟡 In Progress | Encrypted binary container format (metadata + bytes, AES-256-GCM + HMAC) implemented in `crypto.js`; UI/UX, dedicated upload flow, and large-file handling still under active development |
| Group Chat | ❌ Removed from scope | Explicitly descoped during development |

---

## 8. Deployment

The application is deployed to **Railway** at:

> https://web-production-ce7b.up.railway.app/

- **Build**: Nixpacks
- **Runtime**: Gunicorn with Uvicorn ASGI workers (`gunicorn --config gunicorn.conf.py run:app`)
- **Database**: PostgreSQL (Railway-managed)
- **TLS**: Terminated by Railway's edge (HTTPS/WSS enforced; `Strict-Transport-Security` header set)
- **Health check**: `GET /login` (per `railway.json`)
- **Restart policy**: On failure, max 3 retries

---

## 9. Ongoing Development — File & Image Attachments

The next development milestone extends the existing E2EE pipeline to support binary attachments (images, documents) without weakening the zero-trust model:

- **Encryption**: Reuses the existing AES-256-GCM + HMAC-SHA256 session keys — files are encrypted with the *same* per-conversation keys as text messages, so no new key-exchange logic is required.
- **Container format**: `[4-byte metadata length][metadata JSON: {filename, mimeType, size}][raw file bytes]`, encrypted as a single AES-GCM payload — the server sees only an opaque encrypted blob, identical in structure to a text message's `encrypted_payloads` entry.
- **Transport**: Encrypted attachments are sent over the existing Socket.IO `send_message` channel (25 MB buffer limit configured server-side), avoiding the need for a separate unencrypted file-upload endpoint.
- **Remaining work**:
  - Client-side file picker / drag-and-drop UI.
  - Progress indicators and chunking for larger files.
  - Robust handling of `localStorage` quota limits when persisting media-bearing chat history (a related fix already landed for quota-crash prevention).
  - Inline preview/rendering of decrypted images and "click to download" for other file types.
  - Decision on whether large files should bypass `localStorage` entirely (e.g., IndexedDB with the same encryption-at-rest scheme) to avoid quota exhaustion.

---

## 10. Conclusion

SecureIM satisfies the core technical requirements of the brief — E2EE, ECDH-based key exchange, message authenticity (AES-GCM + HMAC-SHA256), and forward secrecy via ephemeral/rotating keys — using algorithms chosen to maximize use of audited, natively-available browser cryptography (Web Crypto API) for all client-side trusted operations, while using industry-standard, OWASP-aligned primitives (Argon2id, PBKDF2 310k, AES-256-GCM) for storage and authentication. The architecture explicitly documents its trust boundary, the residual risks accepted (metadata leakage to the server, TOFU gap prior to manual contact verification), and a clear roadmap for the in-progress encrypted file/image attachment feature.
