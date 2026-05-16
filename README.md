# SecureIM — Zero-Trust End-to-End Encrypted Messaging System

> A cross-platform instant messaging web application that prioritizes user privacy and data integrity through modern cryptographic primitives.

---

## 1. Project Overview

SecureIM is built on a **Zero-Trust architecture**: the central server is treated as an untrusted relay that possesses no technical means to access plaintext message content. All encryption and decryption occur exclusively on the user's device inside the browser's native Web Crypto API sandbox.

### Threat Model

| Threat | Mitigation |
|---|---|
| **Eavesdropping** | AES-256-GCM E2EE — server stores only ciphertext |
| **Identity Spoofing** | ECDSA P-384 identity key pairs per device + key fingerprint out-of-band verification |
| **Man-in-the-Middle (MitM)** | ECDH ephemeral key exchange + HMAC-SHA256 per message — any relay tampering is detectable |
| **Replay Attacks** | Per-message random nonce (GCM IV) + timestamp; replayed messages have mismatching nonces |
| **Bit-Flipping** | AES-GCM authentication tag + explicit HMAC-SHA256 both reject any modified ciphertext |
| **Server-Side Compromise** | Server holds zero plaintext. Compromising the DB yields only ciphertext blobs, Argon2id hashes, and public keys |
| **Credential Theft** | Argon2id (m=64MB, t=3, p=4) password hashing; private keys encrypted client-side with PBKDF2-AES-256-GCM |
| **Forward Secrecy violation** | Fresh ephemeral ECDH keys per session; key rotation every 100 messages |

---

## 2. Core Technical Requirements

### ✅ End-to-End Encryption (E2EE)
- Every message payload is encrypted with **AES-256-GCM** in the sender's browser before transmission
- The server receives and stores only a JSON blob of base64-encoded ciphertexts
- Decryption happens exclusively in the recipient's browser
- For multi-device users, the payload is encrypted separately for each registered device key
- **The server has no technical means to access plaintext** — even with full database access

**Implementation:** `static/js/crypto.js` → `encryptMessage()` / `decryptMessage()`  
**Server relay:** `app/chat.py` → `on_send_message()` stores `encrypted_payloads` JSON without parsing plaintext

---

### ✅ Cryptographic Key Exchange (ECDH)
- Uses **Elliptic Curve Diffie-Hellman (ECDH) with curve P-256**
- Both parties independently generate ephemeral ECDH key pairs and exchange **only their public keys** via the server relay
- Both compute the same `shared_secret = ECDH(myPrivate, theirPublic)` — the shared secret is never transmitted
- **HKDF (HMAC-based Key Derivation Function)** with SHA-256 stretches the shared secret into:
  - A 256-bit AES-GCM session key (info = `SecureIM-v1-session-key`)
  - A 256-bit HMAC-SHA256 key (info = `SecureIM-v1-hmac-key`)
- Domain-separated derivation prevents key reuse between encryption and authentication

**Handshake flow:**
1. Alice POSTs her ephemeral public key to `/api/chat/sessions`
2. Server stores it and notifies Bob via SocketIO `session_request`
3. Bob generates his ephemeral key pair, derives session keys, PUTs his public key to `/api/chat/sessions/<id>`
4. Server notifies Alice via `session_ready` with Bob's public key
5. Alice derives the same session keys — handshake complete

**Implementation:** `static/js/crypto.js` → `generateEphemeralKeyPair()`, `deriveSessionKey()`, `deriveHMACKey()`

---

### ✅ Data Integrity & Authenticity
Every encrypted message carries **two independent integrity checks**:

1. **AES-256-GCM authentication tag** (built into GCM mode) — any bit modification to the ciphertext causes decryption to fail
2. **HMAC-SHA256** computed over `nonce || ciphertext` using the separately derived HMAC key — provides an explicit, independently verifiable MAC

On receipt, the client **verifies the HMAC before attempting decryption**. A tampered or replayed message is rejected with an error displayed to the user.

**Implementation:** `static/js/crypto.js` → `encryptMessage()` computes both; `decryptMessage()` verifies HMAC first

---

### ✅ Forward Secrecy
- **Session-level forward secrecy:** Each DM session uses a **fresh ephemeral ECDH key pair** generated at session start. Compromising a user's long-term identity key reveals nothing about past sessions.
- **Key rotation:** After every **100 messages**, the server emits a `key_rotation_required` event. Both clients discard the old session key and initiate a new ECDH handshake with fresh ephemeral keys.
- Group sessions use a per-session symmetric key distributed via ECDH to each member.

**Implementation:** `app/chat.py` → `on_send_message()` tracks `session.message_count`; `static/js/chat.js` → `onKeyRotationRequired()`

---

## 3. Key Features

### ✅ 1. Identity Management
- On registration, the browser generates two key pairs via Web Crypto API:
  - **ECDSA P-384** identity key pair — used for signing and key fingerprinting
  - **ECDH P-256** static key pair — used for initial key exchange and multi-device delivery
- **Private keys never leave the device** — they are encrypted with a PBKDF2-derived key before being stored in `localStorage`
- Public keys are uploaded to the server and associated with the user account
- Each additional device registers its own key pair; the server maintains a `device_keys` table
- **2FA via email link** is required for every new device login (15-minute expiry, single-use token)
- **Key fingerprints** (first 16 bytes of SHA-256(publicKey)) are displayed for out-of-band verification

**Implementation:** `app/models.py` → `User`, `DeviceKey`; `app/auth.py`; `static/js/crypto.js` → `generateIdentityKeyPair()`, `computeFingerprint()`

---

### ✅ 2. Session Orchestration
- Sessions are tracked in the `chat_sessions` table with ephemeral public keys and message counts
- **Key rotation policy:** automatic rotation every 100 messages (configurable via `KEY_ROTATION_THRESHOLD` in `config.py`)
- **Session termination:** logging out deactivates the device; the session key is never persisted — it exists only in memory (`SecureStorage._sessionKeys`)
- **Multi-device:** when a user registers a new device, existing sessions continue uninterrupted; the new device receives its own encrypted copy of messages going forward
- Group membership changes (join/leave) trigger group key version increment, signalling clients to rotate the group symmetric key

**Implementation:** `app/models.py` → `ChatSession`; `app/chat.py` → `create_session()`, `on_key_rotation_required()`; `static/js/chat.js` → `initiateSession()`, `onKeyRotationRequired()`

---

### ✅ 3. Secure Local Storage
All client-side data is protected at rest:

| Data | Encryption |
|---|---|
| ECDSA private key | AES-256-GCM, key = PBKDF2(password, random-salt, 310,000 iter, SHA-256) |
| ECDH private key | AES-256-GCM, key = PBKDF2(password, random-salt, 310,000 iter, SHA-256) |
| Chat history | AES-256-GCM, key = PBKDF2(password, stored-salt, 310,000 iter, SHA-256) |
| Contact list | Plaintext (non-sensitive metadata) |
| Auth JWT | Plaintext in localStorage (standard web practice) |

- **PBKDF2 iterations:** 310,000 — meets OWASP 2023 recommendation for PBKDF2-SHA256
- **Session mode:** when enabled, current-session messages are held only in memory (JS heap) and never written to `localStorage`. Older persisted history remains intact.
- **Store History toggle:** when disabled, no messages are written to `localStorage` at all
- On the unlock screen, the user enters their password to decrypt keys — wrong password = cannot decrypt = access denied

**Implementation:** `static/js/crypto.js` → `encryptForStorage()`, `decryptFromStorage()`, `deriveStorageKey()`; `static/js/storage.js`

---

### ✅ 4. Security UI/UX

| Indicator | Location | Meaning |
|---|---|---|
| 🔒 **E2EE Active** (green badge) | Chat header | ECDH handshake complete, AES session key established |
| ⏳ **Establishing session…** (amber badge) | Chat header | Key exchange in progress |
| ✅ **Verified** (green label) | Contact sidebar | User has manually verified this contact's public key fingerprint out-of-band |
| 🔒 (lock icon per message) | Each message bubble | Confirms that specific message was E2EE encrypted |
| ⚠️ **HMAC verification failed** | Message body | Message was tampered in transit — displayed in red |
| 🗑️ **This message was deleted** | Message body | Deep-delete applied — shown to both parties |
| 🔴 / 🟢 dot | Contact sidebar | Online / Offline presence indicator |
| 📧 **2FA waiting** | Login page | Polling for device authorization after email link sent |
| **Fingerprint dialog** | "Verify Keys" button | Displays SHA-256 fingerprint of contact's ECDSA public key for out-of-band comparison |

**Implementation:** `templates/chat.html`, `static/js/chat.js` → `updateEncryptionBadge()`, `renderMessage()`, `verifyContact()`

---

## 4. Additional Features

### Message Deletion Modes
- **Delete for me** — removes message from local `localStorage` and hides it in the UI; the other party is unaffected
- **Deep delete** — marks message as `is_deep_deleted=True` on the server; both parties see "🗑️ This message was deleted"; the encrypted payload remains but is ignored by both clients
- Accessible via the `⋯` action button on each message bubble

### Group Chat
- Create groups with any set of users; group admin can manage members
- Group messages are encrypted with a symmetric group key
- Group key version increments on membership changes; clients re-exchange keys

### Multi-Device Support
- Each browser/device registers its own ECDSA + ECDH key pair
- 2FA via email link is required for every new device
- Devices can be revoked from the account settings (REST API)
- Messages are delivered to all active devices of a recipient

---

## 5. Architecture & Data Flow

```
┌─────────────────────────────────────────────────────────┐
│                    CLIENT (Browser)                      │
│                                                          │
│  Web Crypto API (native — no JS library needed)          │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────────┐  │
│  │ ECDSA    │  │ ECDH     │  │ AES-256-GCM + HMAC    │  │
│  │ Identity │  │ Key Exch │  │ Message Encrypt/Dec    │  │
│  └──────────┘  └──────────┘  └───────────────────────┘  │
│       ↕               ↕               ↕                  │
│  PBKDF2-encrypted localStorage    In-memory session keys  │
└──────────────────────┬──────────────────────────────────┘
                       │ HTTPS / WSS (ciphertext only)
┌──────────────────────▼──────────────────────────────────┐
│                   SERVER (Python/Flask)                   │
│                                                          │
│  Flask-SocketIO relay  │  REST API                        │
│  ┌─────────────────────────────────────────────────────┐ │
│  │  SQLite DB                                           │ │
│  │  users (argon2id hash, public keys)                  │ │
│  │  messages (encrypted_payloads — NO PLAINTEXT)        │ │
│  │  chat_sessions (ephemeral public keys only)          │ │
│  │  device_keys (public keys per device)                │ │
│  └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**DFD — Message Send:**
1. Sender types message → `encryptMessage(aesKey, hmacKey, plaintext)` → `{ciphertext, nonce, hmac}`
2. Payload POSTed over WSS to server → server stores ciphertext, relays to recipient's SocketIO room
3. Recipient's browser receives ciphertext → `decryptMessage()` verifies HMAC, then AES-GCM decrypts → plaintext rendered

---

## 6. Cryptographic Libraries

| Library | Purpose | Justification |
|---|---|---|
| **Web Crypto API** (browser native) | ECDSA, ECDH, AES-GCM, HMAC, HKDF, PBKDF2 | Zero external dependency, FIPS 140-2 compliant, hardware-accelerated |
| **argon2-cffi** (Python) | Server-side password hashing | Argon2id is the Password Hashing Competition winner; memory-hard, side-channel resistant |
| **PyJWT** (Python) | Device session tokens | Industry-standard JWT with HS256 signing |
| **Flask-SocketIO / eventlet** | Real-time WebSocket relay | Lightweight, production-grade async server |

---

## 7. Security Audit Self-Assessment

| Attack | Status | Defense |
|---|---|---|
| **Replay attack** | ✅ Mitigated | 12-byte random GCM nonce per message; replayed nonce causes GCM/HMAC failure |
| **Bit-flipping** | ✅ Mitigated | AES-GCM is authenticated encryption; HMAC provides redundant check |
| **Server-side compromise** | ✅ Mitigated | DB contains zero plaintext; only ciphertext blobs + public keys |
| **MitM on key exchange** | ⚠️ Partial | Detectable via key fingerprint UI; requires user to verify fingerprint out-of-band |
| **Password brute-force** | ✅ Mitigated | Argon2id (64MB RAM, 3 iterations) makes offline attacks expensive |
| **Private key theft** | ✅ Mitigated | Private keys AES-encrypted in localStorage with PBKDF2-derived key |
| **XSS key exfiltration** | ⚠️ Partial | CSP headers recommended in production; private keys in encrypted localStorage |
| **Session hijacking** | ✅ Mitigated | Short-lived JWT per device; device revocation API; 2FA for new devices |

---

## 8. Setup & Installation

### Prerequisites
- Python 3.11+
- pip

### Install

```bash
cd c:\Projects\secureIM
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### Configure (optional)

Create a `.env` file for production settings:

```env
SECRET_KEY=change-this-to-a-random-64-char-string
JWT_SECRET_KEY=change-this-to-another-random-string
BASE_URL=http://localhost:5000

# Email (leave MAIL_SUPPRESS_SEND=true for dev — links print to console)
MAIL_SUPPRESS_SEND=true
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=SecureIM <noreply@yourdomain.com>
```

### Run

```bash
python run.py
```

Open **http://localhost:5000** in your browser.

> **Development tip:** With `MAIL_SUPPRESS_SEND=true`, all email links are printed to the terminal console — no SMTP setup required.

### Quick Start (Two-User Demo)

1. Open two browser tabs (or use a private/incognito window for the second user)
2. Register two accounts in each tab
3. Check the terminal for the email verification links — click them
4. Log in with both accounts
5. Search for the other user in the sidebar → click to start a DM
6. Send messages — watch the 🔒 E2EE Active badge appear after key exchange
7. Click "Verify Keys" to compare key fingerprints out-of-band

---

## 9. Project Structure

```
secureIM/
├── app/
│   ├── __init__.py       # Flask app factory
│   ├── models.py         # SQLAlchemy models (User, DeviceKey, Message, Group…)
│   ├── auth.py           # Auth routes (register, login, 2FA, email verify)
│   ├── chat.py           # Chat REST API + SocketIO event handlers
│   ├── routes.py         # HTML page routes
│   ├── crypto_utils.py   # Argon2id, JWT, token generation
│   └── email_utils.py    # Email sending (Flask-Mail + console fallback)
├── static/
│   ├── css/style.css     # Dark cyberpunk theme
│   └── js/
│       ├── crypto.js     # Web Crypto API wrapper (all E2EE logic)
│       ├── storage.js    # Encrypted localStorage management
│       ├── auth.js       # Registration, login, 2FA UI
│       └── chat.js       # Chat UI, SocketIO, E2EE orchestration
├── templates/
│   ├── base.html         # Base layout
│   ├── login.html        # Login + 2FA waiting
│   ├── register.html     # Registration
│   ├── chat.html         # Main chat interface
│   ├── verify_email.html # Email activation landing
│   └── device_authorized.html  # 2FA link landing
├── config.py             # All configuration (reads from .env)
├── run.py                # Application entry point
├── requirements.txt      # Python dependencies
└── README.md             # This file
```
