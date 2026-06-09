# SecureIM — Zero-Trust End-to-End Encrypted Messaging

A web-based instant messaging system that implements **Zero-Trust architecture**: the server is a dumb relay that stores only ciphertext and public keys. All cryptographic operations happen in the browser using the native Web Crypto API — no third-party crypto library required.

---

## Threat Model

| Threat | Mitigation |
|---|---|
| Eavesdropping | AES-256-GCM E2EE — server stores only ciphertext |
| Identity spoofing | ECDSA P-384 per-device identity keys; ephemeral keys are signed before exchange |
| Man-in-the-Middle | ECDH ephemeral key exchange + ECDSA signature verification on both sides |
| Replay attacks | 96-bit random GCM nonce per message; replayed nonces fail GCM auth tag |
| Bit-flipping | AES-GCM auth tag + independent HMAC-SHA256 both reject any modified ciphertext |
| Server-side compromise | DB holds zero plaintext — only ciphertext blobs, Argon2id hashes, public keys |
| Credential theft | Argon2id (m=64MB, t=3, p=4) server-side; private keys encrypted client-side with PBKDF2-AES-256-GCM |
| Forward secrecy violation | Fresh ephemeral ECDH key pair per session; automatic rotation every 100 messages |

---

## Core Technical Requirements

### ✅ End-to-End Encryption (E2EE)

Every message is encrypted **in the sender's browser** before leaving the device. The server receives and stores a JSON blob of base64-encoded ciphertext — it never sees plaintext.

**How it works:**
1. After ECDH handshake both parties hold the same `aesKey` (in RAM only)
2. Sender: `encryptMessage(aesKey, hmacKey, plaintext)` → `{ ciphertext, nonce, hmac }`
3. Server receives ciphertext, stores it, forwards to recipient's socket room
4. Recipient: `decryptMessage(aesKey, hmacKey, payload)` → plaintext rendered in UI
5. For multi-device users, the payload is encrypted separately per registered device key

**Files:** [`static/js/crypto.js`](static/js/crypto.js) → `encryptMessage()` / `decryptMessage()`  
**Server relay:** [`app/chat.py`](app/chat.py) → `send_message` SocketIO handler stores `encrypted_payloads` as-is

---

### ✅ Cryptographic Key Exchange (ECDH)

Uses **Elliptic Curve Diffie-Hellman (P-256)** so both parties compute the same shared secret without transmitting it. The shared secret is stretched via **HKDF-SHA256** into two independent keys:
- `SecureIM-v1-session-key` → 256-bit AES-GCM key
- `SecureIM-v1-hmac-key` → 256-bit HMAC-SHA256 key

**Handshake flow:**
```
Alice                           Server                          Bob
  │                               │                              │
  ├─ generateEphemeralKeyPair()   │                              │
  ├─ sign(ephA_pub, ecdsaPriv)    │                              │
  ├─ POST /sessions ─────────────►│                              │
  │                               ├─ emit session_request ──────►│
  │                               │                              ├─ verify Alice's ECDSA sig ✓
  │                               │                              ├─ generateEphemeralKeyPair()
  │                               │                              ├─ deriveSessionKey(ephB_priv, ephA_pub)
  │                               │                              ├─ sign(ephB_pub, ecdsaPriv)
  │                               │◄── PUT /sessions/{id} ───────┤
  │                               ├─ emit session_ready ────────►│
  │◄── session_ready ─────────────┤                              │
  ├─ verify Bob's ECDSA sig ✓     │                              │
  ├─ deriveSessionKey(ephA_priv, ephB_pub)                       │
  │  ↳ same aesKey as Bob ✓       │                              │
```

**Files:** [`static/js/crypto.js`](static/js/crypto.js) → `generateEphemeralKeyPair()`, `deriveSessionKey()`, `deriveHMACKey()`  
**Session tracking:** [`app/models.py`](app/models.py) → `ChatSession`; [`app/chat.py`](app/chat.py) → `create_session()`, `update_session()`

---

### ✅ Data Integrity & Authenticity

Each message carries **two independent integrity checks**:

1. **AES-256-GCM authentication tag** — built into GCM mode; any bit modification to ciphertext fails decryption
2. **HMAC-SHA256** over `nonce ‖ ciphertext` using the separately derived HMAC key

The client verifies the HMAC **before** attempting AES-GCM decryption. A tampered or replayed message is rejected and shown as an error in the UI.

**Files:** [`static/js/crypto.js`](static/js/crypto.js) → `encryptMessage()` computes both; `decryptMessage()` verifies HMAC first, then decrypts

---

### ✅ Forward Secrecy

- **Per-session ephemeral keys:** each DM session generates a fresh ECDH key pair. Compromising a user's long-term ECDSA identity key reveals nothing about past sessions because the ephemeral private keys are never persisted — they live only in JavaScript memory and vanish when the tab is closed.
- **Automatic key rotation:** after every 100 messages, the server emits `key_rotation_required`. Both clients discard the old session key and initiate a new ECDH handshake with fresh ephemeral keys.

**Files:** [`app/chat.py`](app/chat.py) line ~182 → `message_count >= KEY_ROTATION_THRESHOLD`;  
[`static/js/chat.js`](static/js/chat.js) → `onKeyRotationRequired()`

---

## Key Features

### ✅ 1. Identity Management

**Requirement:** identities linked to public/private key pairs (RSA-4096 or equivalent)

**Implementation:**  
On registration, the browser generates two key pairs via Web Crypto API:
- **ECDSA P-384** — long-term identity key used to sign ephemeral keys (prevents MitM substitution)
- **ECDH P-256** — used for key exchange

Private keys are encrypted with PBKDF2-derived AES-256-GCM key (password as passphrase) and stored in `localStorage`. They never leave the device in plaintext. Only public keys are uploaded to the server.

Each browser/device registers its own key pair in the `device_keys` table. New device logins generate a new key pair automatically.

**Key fingerprint:** SHA-256 of the ECDSA public key, displayed as `XX:XX:XX:…` hex pairs for out-of-band verification.

**Files:** [`static/js/auth.js`](static/js/auth.js) → `handleRegister()`, `handleLogin()`;  
[`app/auth.py`](app/auth.py) → `register()`, `login()`;  
[`app/models.py`](app/models.py) → `User`, `DeviceKey`;  
[`static/js/crypto.js`](static/js/crypto.js) → `generateIdentityKeyPair()`, `computeFingerprint()`

---

### ✅ 2. Session Orchestration

**Requirement:** initialize, maintain, and terminate secure sessions; key rotation for long-term conversations

**Implementation:**
- **Init:** `initiateSession()` generates ephemeral ECDH key pair, signs it with ECDSA identity key, POSTs to server → server forwards to recipient via SocketIO
- **Maintain:** server tracks `ChatSession` with `message_count`; emits `key_rotation_required` at threshold (default 100, configurable via `KEY_ROTATION_THRESHOLD` env var)
- **Rotate:** client clears old session keys from memory, re-runs full ECDH handshake with new ephemeral keys
- **Reconnect:** when a user reconnects after being offline, the server replays any pending `session_request` events they missed
- **Terminate:** closing the tab discards all ephemeral keys; logout deactivates the device record

**Files:** [`app/chat.py`](app/chat.py) → `create_session()`, `update_session()`, `connect()` (pending replay);  
[`static/js/chat.js`](static/js/chat.js) → `initiateSession()`, `onSessionRequest()`, `onSessionReady()`, `onKeyRotationRequired()`

---

### ✅ 3. Secure Local Storage

**Requirement:** AES-256-GCM with PBKDF2 or Argon2 for client-side data

**Implementation:**

| Data | Storage | Encryption |
|---|---|---|
| ECDSA private key | `localStorage` (sim_identity) | AES-256-GCM, key = PBKDF2(password, random-salt, **310 000 iter**, SHA-256) |
| ECDH private key | `localStorage` (sim_identity) | same as above |
| Chat history | `localStorage` (sim_hist_*) | AES-256-GCM, key = PBKDF2(password, stored-salt, 310 000 iter, SHA-256) |
| Ephemeral session keys | JavaScript RAM only | never persisted |
| Auth JWT | `localStorage` (plaintext) | standard web practice — short-lived (30 days) |

- **310 000 PBKDF2-SHA256 iterations** — exceeds OWASP 2023 minimum (260 000)
- **Random 32-byte salt** generated per encryption operation
- **Session mode:** when enabled, current-session messages are held in JS memory only, never written to `localStorage`
- **Unlock screen:** on returning to the tab, the user re-enters their password to decrypt private keys from `localStorage` — wrong password = cannot derive key = cannot decrypt = access denied

**Files:** [`static/js/crypto.js`](static/js/crypto.js) → `deriveStorageKey()`, `encryptForStorage()`, `decryptFromStorage()`;  
[`static/js/storage.js`](static/js/storage.js) → `saveIdentityKeys()`, `loadIdentityKeys()`, `saveMessage()`, `getConversation()`

---

### ✅ 4. Security UI/UX

**Requirement:** visual indicators of encryption status; "Verified" badges for out-of-band verified contacts

**Implementation:**

| Indicator | Where | Meaning |
|---|---|---|
| `⏳ Establishing…` (amber) | Chat header badge | ECDH handshake in progress |
| `🔒 E2EE Active` (cyan) | Chat header badge | Session keys established, AES-256-GCM active |
| `✅ Verified` label | Contact in sidebar | You have manually verified this contact's key fingerprint out-of-band |
| `⛔ KEY EXCHANGE INVALID` alert | Full-width error | ECDSA signature verification failed during handshake — possible MitM |
| `⚠️ HMAC verification failed` | Message body | Message was tampered in transit |
| `🗑️ This message was deleted` | Message body | Deep-delete applied by sender |
| 🟢 / ⚫ dot | Sidebar contact | Online / offline presence |

**Fingerprint verification flow:** click "Verify Keys" on a contact → SHA-256 fingerprint shown → user compares via phone/in-person → mark as Verified → `✅` badge appears.

**Files:** [`templates/chat.html`](templates/chat.html);  
[`static/js/chat.js`](static/js/chat.js) → `updateEncryptionBadge()`, `verifyContact()`, `renderMessage()`

---

## Additional Features

### Message Deletion
- **Delete for me** — removes from local `localStorage` and hides in UI; other party unaffected
- **Deep delete** — server marks `is_deep_deleted=True` and clears ciphertext; both parties see `🗑️ This message was deleted`

### Group Chat
- Group messages encrypted with a per-group symmetric AES key
- Group key version increments on membership changes; clients re-exchange keys
- Each member receives an encrypted copy of the group key via their ECDH public key

### Self-Destruct Timer
- Messages can be set to auto-expire (1 min / 5 min / 1 hr / 24 hr)
- Server scheduler (`app/scheduler.py`) cleans up expired messages

### Ephemeral Session Mode
- Toggle in sidebar: current session messages held in JS memory only, never persisted to `localStorage`

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   BROWSER (Client)                   │
│                                                      │
│  Web Crypto API — no external crypto library         │
│  ┌────────────┐  ┌────────────┐  ┌────────────────┐ │
│  │ ECDSA P-384│  │ ECDH P-256 │  │ AES-256-GCM    │ │
│  │ (identity) │  │(key exchange│  │ HMAC-SHA256    │ │
│  └────────────┘  └────────────┘  └────────────────┘ │
│        ↕                ↕                ↕           │
│  PBKDF2-encrypted localStorage    RAM session keys   │
└──────────────────────┬──────────────────────────────┘
                       │ HTTPS / WSS  (ciphertext only)
┌──────────────────────▼──────────────────────────────┐
│              SERVER (FastAPI + python-socketio)       │
│                                                      │
│  SocketIO relay  │  REST API  │  Background scheduler│
│  ┌──────────────────────────────────────────────┐   │
│  │  Database (SQLite dev / PostgreSQL prod)      │   │
│  │  users          — username, argon2id hash     │   │
│  │  device_keys    — public keys per device      │   │
│  │  messages       — encrypted_payloads only     │   │
│  │  chat_sessions  — ephemeral public keys       │   │
│  │  audit_logs     — events, no message content  │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

---

## Cryptographic Primitives

| Primitive | Algorithm | Purpose |
|---|---|---|
| Identity key | ECDSA P-384 | Sign ephemeral keys; key fingerprints |
| Key exchange | ECDH P-256 | Establish shared secret without transmitting it |
| Key derivation (session) | HKDF-SHA256 | Derive AES + HMAC keys from ECDH shared secret |
| Message encryption | AES-256-GCM | Authenticated encryption of every message |
| Message integrity | HMAC-SHA256 | Independent MAC over nonce ‖ ciphertext |
| Key derivation (storage) | PBKDF2-SHA256, 310 000 iter | Derive AES key from user password for localStorage |
| Password hashing (server) | Argon2id (64MB, t=3, p=4) | Slow hash for credential storage |
| Session tokens | JWT HS256 | Stateless device authentication |

All browser-side operations use the **native Web Crypto API** — zero external crypto library dependency, hardware-accelerated, FIPS 140-2 compliant.

---

## Security Audit Self-Assessment

| Attack Vector | Status | Defence |
|---|---|---|
| Replay attack | ✅ Mitigated | 96-bit random GCM nonce per message; HMAC covers nonce |
| Bit-flipping | ✅ Mitigated | AES-GCM auth tag + independent HMAC both reject any mutation |
| Server-side DB leak | ✅ Mitigated | Zero plaintext in DB — only ciphertext + public keys |
| MitM on key exchange | ✅ Mitigated | ECDSA signatures on ephemeral keys verified before key derivation |
| Passive traffic analysis | ✅ Mitigated | All traffic over HTTPS/WSS; message sizes padded by GCM overhead |
| Password brute-force | ✅ Mitigated | Argon2id (64MB RAM, 3 iterations) — offline attack is memory-expensive |
| Private key theft from browser | ✅ Mitigated | Private keys AES-encrypted at rest; plaintext only in RAM after unlock |
| XSS key exfiltration | ⚠️ Partial | Strict CSP (`script-src 'self'`); keys in encrypted localStorage |
| JWT forgery | ✅ Mitigated | HS256 signed with `JWT_SECRET_KEY` set as Railway env var |

---

## Setup

### Requirements
- Python 3.11+

### Install & run locally

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS/Linux
pip install -r requirements.txt
python run.py
```

Open **http://localhost:8000**

### Environment variables

```env
# Required in production — generate with: python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=<random-64-char-hex>
JWT_SECRET_KEY=<random-64-char-hex>

# Database — leave unset for local SQLite, set for Railway PostgreSQL
DATABASE_URL=postgresql://user:pass@host/db

# Optional tuning
KEY_ROTATION_THRESHOLD=100   # rotate session keys every N messages
DEBUG=false
PORT=8000
```

### Deploy to Railway

The project includes [`railway.json`](railway.json). Push to GitHub → connect repo in Railway → add `SECRET_KEY`, `JWT_SECRET_KEY`, and a PostgreSQL plugin → deploy.

### Quick demo (two users)

1. Open two browser tabs (or one normal + one incognito)
2. Register two accounts
3. Log in with both accounts
4. Click the other user in the sidebar → secure session establishes automatically
5. Send messages — watch the `🔒 E2EE Active` badge appear after key exchange
6. Click "Verify Keys" on the contact to compare ECDSA fingerprints out-of-band

---

## Project Structure

```
secureIM/
├── app/
│   ├── __init__.py       # FastAPI app factory + SocketIO ASGI wrapper
│   ├── models.py         # SQLAlchemy ORM (User, DeviceKey, Message, ChatSession…)
│   ├── auth.py           # Auth API (register, login, logout, device management)
│   ├── chat.py           # Chat REST API + SocketIO event handlers
│   ├── routes.py         # HTML page routes
│   ├── crypto_utils.py   # Argon2id, JWT, secure token generation
│   ├── security.py       # SecurityHeadersMiddleware (CSP, HSTS, etc.)
│   ├── scheduler.py      # Background job: expire self-destruct messages
│   ├── database.py       # SQLAlchemy engine + session factory
│   ├── socket_manager.py # python-socketio server instance
│   └── limiter.py        # slowapi rate limiter instance
├── static/
│   ├── css/style.css     # Dark theme UI
│   └── js/
│       ├── crypto.js     # All E2EE logic (Web Crypto API wrapper)
│       ├── storage.js    # Encrypted localStorage management
│       ├── auth.js       # Registration + login UI
│       ├── chat.js       # Chat UI, SocketIO client, E2EE orchestration
│       └── socket.io.min.js
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   └── chat.html
├── config.py             # Settings singleton (reads env vars)
├── run.py                # Entry point (uvicorn)
├── gunicorn.conf.py      # Gunicorn config for production
├── railway.json          # Railway deployment config
└── requirements.txt
```
