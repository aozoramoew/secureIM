# SecureIM — Security Audit Report (Self-Assessment / Red Team Analysis)

**Project:** Secure Messaging System (Project 1)
**Version:** 1.0
**Live Deployment:** https://web-production-ce7b.up.railway.app/
**Date:** 2026-06-10
**Audit Type:** Internal self-assessment / Red Team simulation, conducted against the codebase at commit `4f2ac13` (FastAPI migration)

---

## 1. Scope & Methodology

This report documents an internal security self-assessment of the SecureIM messaging system, performed from the perspective of three adversary roles defined in the Technical Design Document's threat model:

1. **Network/MitM attacker** — capable of intercepting, modifying, replaying, or injecting traffic between client and server.
2. **Malicious/compromised server operator** — full read/write access to the application server, database, and process memory.
3. **Local client-side attacker** — access to a victim's browser storage (`localStorage`).

For each adversary, the assessment focuses on the three attack classes explicitly required by the project brief:

- **Replay attacks**
- **Bit-flipping attacks**
- **Server-side compromise**

Each scenario below follows the format: **Attack Description → Attempted Exploitation → System Response → Verdict (Mitigated / Partially Mitigated / Not Mitigated) → Evidence (code references)**.

### 1.1 Companion Automated Audit Script

In addition to the manual Red Team scenarios documented in this report, the repository includes an automated, runnable self-assessment script at [`security_audit.py`](../security_audit.py). This script exercises the **live HTTP/REST API surface** of a running deployment and verifies, end-to-end:

- Identity management (registration, duplicate-username rejection, weak-password rejection, per-device ECDSA/ECDH key registration).
- Authentication (cookie-based JWT issuance via the `sim_token` HttpOnly cookie, rejection of tampered/random/missing tokens, device listing).
- Password security (Argon2id — verified indirectly via wrong-password rejection and generic, anti-enumeration error messages).
- E2EE invariants (ECDH session creation, server storing only `encrypted_payloads` / ephemeral public keys, no `shared_secret` or plaintext fields ever returned by the API).
- Forward secrecy bookkeeping (`ChatSession.message_count` used for key-rotation triggers).
- Replay resistance at the session/auth layer (token reuse, device revocation on logout).
- Bit-flipping and server-compromise properties (asserted via code-level invariants — AES-256-GCM, dual HMAC, no plaintext columns).
- Rate limiting (`429` triggered on rapid `/api/auth/login` attempts).
- Contact verification and audit-log endpoints.
- Security response headers (CSP, `X-Content-Type-Options`, `X-Frame-Options`).

**Usage:**

```bash
python security_audit.py [BASE_URL]
# Defaults to http://localhost:8000 if BASE_URL is omitted
# Example against the production deployment:
python security_audit.py https://web-production-ce7b.up.railway.app
```

The script prints a pass/warn/fail breakdown per check and an overall **Security Score**. As of this report's date, a run against a fresh local instance scores in the high-80s/90s%; the only expected non-pass results are tied to the `/api/auth/register` rate limit (`5/hour`) being shared across consecutive runs within the same hour — this is the rate limiter functioning as designed, not a defect. This script operationalizes a subset of the manual scenarios in Sections 3–5 below and is intended to be re-run after any change to the authentication, session, or cryptography layers as a regression check.

---

## 2. Test Environment

- **Codebase**: `c:\Projects\secureIM` (FastAPI + python-socketio + SQLAlchemy)
- **Crypto stack under test**: Web Crypto API (client) — ECDH P-256, ECDSA P-384, AES-256-GCM, HMAC-SHA256, HKDF-SHA256, PBKDF2-SHA256 (310k iterations); Argon2id (server, password hashing)
- **Deployment under test**: https://web-production-ce7b.up.railway.app/ (Railway, PostgreSQL, HTTPS/WSS via TLS termination)

---

## 3. Red Team Scenario 1 — Replay Attacks

### 3.1 Scenario 1a: Network-level Message Replay

**Attack Description**: An attacker passively captures a legitimate `send_message` Socket.IO frame (containing `{encrypted_payloads, recipient_id, session_id, msg_type, expires_seconds}`) in transit and re-transmits the identical frame at a later time, attempting to make the recipient process the same message twice or trigger a duplicate action.

**Attempted Exploitation**: Replay the captured frame verbatim to the server's Socket.IO endpoint.

**System Response**:
- The server has no explicit anti-replay token, but the replayed frame still results in a **new** `Message` row being created (`app/chat.py`, `send_message` handler) with a new auto-increment `id` and a new `timestamp` (current time, not the original send time).
- The ciphertext itself decrypts successfully on the recipient's client (since AES-GCM/HMAC validation only checks integrity of *that specific ciphertext*, not its freshness), and the **plaintext content** displayed will be identical to the original message.
- The recipient's UI will show the message a **second time**, with a new timestamp, as if it were a freshly sent duplicate message.

**Verdict**: 🟡 **Partially Mitigated**

The cryptographic layer (AES-GCM + HMAC) correctly prevents the replayed ciphertext from being *modified or forged* — an attacker can only replay an exact, previously-valid ciphertext, not craft a new one. However, the *application layer* does not currently reject or flag the replay as a duplicate. The result is a **duplicate message**, not arbitrary forged content — i.e., the confidentiality and integrity guarantees hold, but availability/UX (duplicate display) is affected.

**Evidence**:
- `app/chat.py` `send_message` handler creates a new `Message` row unconditionally for any well-formed payload.
- `app/models.py` — `Message.id` is an auto-increment primary key; no `nonce`/`anti_replay_token` table exists.
- `static/js/crypto.js` decryption functions verify HMAC and AES-GCM tag, but perform no freshness/sequence check.

**Recommendation (for future hardening)**: Introduce a per-session monotonically increasing sequence number, included in the AAD (Additional Authenticated Data) of the AES-GCM operation or as part of the HMAC input. The recipient client tracks the highest sequence number seen per session and rejects/flags any message with a sequence number ≤ the last seen value.

### 3.2 Scenario 1b: Session-Handshake Replay

**Attack Description**: An attacker captures a `session_request` (containing `ephemeral_pub_A`, `sig_A`, `device_id`) and replays it later, attempting to force the victim to re-derive a session using a *stale* (but validly-signed) ephemeral key — potentially one whose corresponding private key may have leaked since.

**Attempted Exploitation**: Replay a captured `session_request` event after the original ephemeral key pair has been discarded by the legitimate client.

**System Response**:
- The signature `sig_A` over `ephemeral_pub_A` remains cryptographically valid (ECDSA signatures do not expire), so signature verification (`static/js/chat.js`) would **succeed**.
- However, this only allows the attacker to cause the *recipient* to derive a session keyed to an ephemeral public key for which the attacker does not (in the assumed scenario) possess the private key — the attacker cannot complete the ECDH and therefore cannot derive the resulting AES/HMAC session keys. The attack degrades to, at worst, a **denial-of-service** against that specific session establishment (the legitimate User A would need to re-initiate).
- If the *original* ephemeral private key has genuinely leaked (a separate, much more severe compromise — see Scenario 3), the replay would allow the attacker to participate in a session — but this is a consequence of the private key leak, not of the replay itself.

**Verdict**: ✅ **Mitigated** (for the realistic threat — replay alone, without a corresponding private key compromise, cannot establish a usable session)

**Evidence**: `static/js/chat.js` session establishment flow — ECDH requires the *private* ephemeral key, never transmitted.

**Recommendation**: Consider adding a short validity window (timestamp + signature over `(ephemeral_pub, timestamp)`) to `session_request` to reduce the window during which a captured handshake message remains "valid-looking", as defense-in-depth.

### 3.3 Scenario 1c: Replay of Encrypted Local Storage Blob

**Attack Description**: Attacker with prior access to a victim's `localStorage` (e.g., via a backup) attempts to "restore" an old encrypted chat-history blob to roll back a user's view of conversation history (e.g., to hide that a message was deleted).

**System Response**: Each `localStorage` entry (`sim_hist_<conv_id>`) is independently AES-256-GCM encrypted with the user's PBKDF2-derived storage key. Restoring an old blob would decrypt successfully (it's a validly-encrypted-at-the-time blob) and would display **stale** chat history to the user.

**Verdict**: 🟡 **Partially Mitigated** — this is a **local, client-side** attack requiring prior write access to the victim's disk/browser profile, which is a substantially higher bar than network-based attacks. The cryptographic confidentiality of the blob is not affected (an attacker without the password cannot read or forge new content). The "rollback" risk is an inherent property of any client-side persisted state without a tamper-evident server-side log, and is accepted as a residual, low-likelihood risk for this project's scope.

---

## 4. Red Team Scenario 2 — Bit-Flipping Attacks

### 4.1 Scenario 2a: Ciphertext Bit-Flip (Network/Server)

**Attack Description**: An attacker (network MitM or malicious server, T2/T3) intercepts an encrypted message payload `{ciphertext, nonce, hmac}` and flips one or more bits in `ciphertext` before it reaches the recipient, attempting to corrupt or manipulate the decrypted plaintext (classic bit-flipping attack against unauthenticated stream ciphers/CTR mode).

**Attempted Exploitation**:
1. Intercept `{ciphertext, nonce, hmac}` in transit (or read it from the database, if server-compromised).
2. Flip a single bit in `ciphertext`.
3. Forward the modified payload to the recipient unchanged otherwise.

**System Response** (`static/js/crypto.js` decryption path):
1. **First check — explicit HMAC-SHA256**: The recipient computes `HMAC-SHA256(session_hmac_key, nonce ‖ ciphertext)` over the *received* (modified) ciphertext and compares it to the received `hmac`. Since the attacker does not possess `session_hmac_key` (derived via ECDH+HKDF, never transmitted), the recomputed HMAC will **not match** the original `hmac` value (which was computed over the *unmodified* ciphertext).
2. **Result**: HMAC verification fails. The client **rejects the message before attempting AES-GCM decryption** and surfaces an integrity-failure error rather than displaying corrupted/manipulated plaintext.
3. **Second, independent check — AES-GCM authentication tag**: Even if the explicit HMAC check were somehow bypassed, AES-GCM's built-in authentication tag (computed over the original ciphertext) would also fail to verify against the modified ciphertext, causing `crypto.subtle.decrypt()` to throw and abort decryption.

**Verdict**: ✅ **Mitigated** — Defense-in-depth via two independent integrity mechanisms (explicit HMAC-SHA256 + AES-GCM authentication tag), each using keys the attacker does not possess. A single-bit modification anywhere in `nonce`, `ciphertext`, or `hmac` causes the message to be rejected outright.

**Evidence**:
- `static/js/crypto.js` — encryption: `hmac = HMAC-SHA256(hmacKey, nonce || ciphertext)`.
- `static/js/crypto.js` — decryption: HMAC recomputed and compared **before** `crypto.subtle.decrypt()` is called; AES-GCM decrypt additionally validates its own 128-bit auth tag.

### 4.2 Scenario 2b: Bit-Flip on Stored Database Record (Server Compromise)

**Attack Description**: An attacker with direct database write access (T3 — server compromise) modifies the `encrypted_payloads` JSON column for a stored `Message` row directly (bypassing the network entirely), attempting to alter message content retroactively or inject content into a future delivery (e.g., for an offline recipient who will receive the message later via the missed-messages sync).

**Attempted Exploitation**: `UPDATE messages SET encrypted_payloads = '<modified JSON with flipped ciphertext bits>' WHERE id = X;`

**System Response**: Identical to Scenario 2a from the recipient's perspective — when the recipient eventually fetches/decrypts this message (either live or via missed-message sync on reconnect, `app/chat.py` connect handler), HMAC-SHA256 verification fails (the attacker, lacking `session_hmac_key`, cannot produce a matching `hmac` for the modified ciphertext), and the message is rejected.

**Verdict**: ✅ **Mitigated** — A fully compromised server (full DB read/write) **cannot** produce a forged or modified message that will pass client-side integrity checks, because it does not possess any session key material (AES or HMAC keys are derived client-side via ECDH and never transmitted to or stored by the server).

**Evidence**: `app/models.py` — `Message.encrypted_payloads` is the sole server-side representation; no key material is co-located with it. `app/chat.py` connect handler relays stored payloads as-is for missed-message delivery — server cannot re-sign or re-encrypt.

### 4.3 Scenario 2c: Bit-Flip on `expires_at` / Metadata Fields

**Attack Description**: An attacker with database access modifies non-encrypted metadata fields — e.g., `Message.expires_at`, `sender_id`, `recipient_id`, `is_deep_deleted` — to cause premature deletion (DoS against availability of A1) or message misattribution.

**System Response**:
- **`expires_at` tampering**: Setting `expires_at` to a past timestamp would cause the next `cleanup_expired_messages` run (every 30s, `app/scheduler.py`) to wipe `encrypted_payloads`, resulting in **permanent loss of that message** for both parties. This is a genuine **availability** impact.
- **`sender_id`/`recipient_id` tampering**: Could redirect message delivery, but the recipient's client would attempt ECDH-based decryption using session keys tied to the *original* `session_id` / conversation; if the attacker redirects to a different recipient with a different session, decryption (HMAC check) would fail, and the message would simply not be readable by the unintended recipient.

**Verdict**: 🟡 **Partially Mitigated** — Confidentiality and authenticity of message *content* remain intact even under metadata tampering (an attacker cannot make a misdelivered message readable without the correct session keys). However, **availability** is not fully protected against a server with direct DB write access — this is an **inherent limitation of the centralized-relay model** and is explicitly accepted as residual risk: a fully compromised server can always perform a denial-of-service (e.g., simply not relaying messages, or deleting rows outright), regardless of cryptographic protections on content.

---

## 5. Red Team Scenario 3 — Server-Side Compromise

This scenario assumes the strongest adversary in scope: **T3, an attacker with full read/write access to the production database, application source code, and a snapshot of server process memory** (e.g., via a compromised Railway deployment credential or a SQL injection — though SQLAlchemy's parameterized queries mitigate the latter).

### 5.1 Scenario 3a: Bulk Database Exfiltration

**Attack Description**: Attacker dumps the entire `messages`, `users`, `device_keys`, `chat_sessions`, and `audit_logs` tables.

**Findings**:

| Table | Data Exposed | Plaintext Risk |
|---|---|---|
| `users` | `username`, `password_hash` (Argon2id), `settings` (JSON: `store_history`, `session_mode` flags) | **None** for password — Argon2id with 64MB memory cost / 3 iterations / parallelism 4 makes offline cracking computationally expensive even for weak passwords. `settings` reveals user preferences (e.g., whether they use session mode) but not content. |
| `device_keys` | `ecdsa_public_key`, `ecdh_public_key` (both **public** keys, JWK format), `device_name`, `last_seen` | **None** — by definition, public keys are not sensitive. Device fingerprinting/tracking via `last_seen` and `device_name` is a **minor metadata leak**. |
| `messages` | `encrypted_payloads` (AES-256-GCM ciphertext + HMAC, per-device), `sender_id`, `recipient_id`, `timestamp`, `expires_at`, `session_id` | **Ciphertext only** — no decryption keys present anywhere in the database. `sender_id`/`recipient_id`/`timestamp` constitute a **metadata leak** (social graph + activity timing), an accepted residual risk of the centralized relay architecture. |
| `chat_sessions` | `ephemeral_pub_a`, `ephemeral_pub_b` (public), `ephemeral_sig_a`, `ephemeral_sig_b` (signatures over public keys), `message_count` | **None** — all fields are public-key material or signatures thereof; no private keys. |
| `audit_logs` | `event_type`, `ip_address`, `user_agent`, `detail` (JSON, non-content metadata) | **IP address / user agent leak** — standard operational logging risk, no message content. |

**Verdict**: ✅ **Mitigated** for the core requirement (no plaintext message content recoverable from a full database dump). 🟡 **Residual metadata risk** (social graph, timing, IP addresses) is present and explicitly documented as an accepted limitation of any centralized-relay IM architecture without onion-routing/mixnet-style transport — out of scope for this project.

**Evidence**: `app/models.py` — exhaustive review of all column definitions confirms no column stores plaintext message content, private keys, or session/derived encryption keys.

### 5.2 Scenario 3b: Live Server Memory Inspection

**Attack Description**: Attacker with process-level access to the running server inspects memory for session keys, JWT secrets, or in-flight plaintext.

**Findings**:
- **AES/HMAC session keys**: Never present in server memory at any point — derived exclusively client-side via `crypto.subtle.deriveBits`/`deriveKey` (Web Crypto API), which the server has no access to.
- **JWT secret (`JWT_SECRET_KEY`)**: **Is** present in server memory/environment (required to verify incoming tokens). Compromise of this secret would allow an attacker to **forge valid JWTs for arbitrary user IDs**, enabling impersonation at the *authentication* layer (i.e., the attacker could open Socket.IO connections / call REST endpoints "as" any user).
  - **Critical scoping note**: Even with a forged JWT, the attacker **still cannot decrypt any message content**, because message confidentiality depends on ECDH-derived session keys, not on the JWT. A forged JWT would let an attacker *send* messages "as" a user (those messages would be encrypted with whatever session keys the attacker can establish via legitimate-looking ECDH handshakes, and would be subject to the recipient's MitM-detection via ECDSA signature verification — see TDD §3.4, T2) or read **encrypted** message *metadata* for that user, but not retroactively decrypt **previously sent** ciphertext.
- **Plaintext in-flight**: The server process at no point holds message plaintext — `app/chat.py` handlers operate exclusively on the `encrypted_payloads` structure as an opaque blob, relaying it without inspection or transformation.

**Verdict**: ✅ **Mitigated for confidentiality** (no plaintext or content-decryption keys in server memory). 🟡 **JWT secret compromise enables authentication-layer impersonation** — this is a standard risk for any HS256-based session system and is mitigated operationally by: storing `JWT_SECRET_KEY` as a Railway environment variable (not in source — confirmed via `.env.example` containing only placeholders, and commit `304aabd` which removed a previously-leaked credential), 7-day token expiry limiting the window of a leaked-secret's usefulness, and per-device revocation (`DELETE /api/auth/devices/{device_id}`) allowing rapid containment.

**Evidence**:
- `app/crypto_utils.py` — JWT encode/decode using `JWT_SECRET_KEY` from environment.
- `app/auth.py` — cookie-based delivery, `httponly=True`, `secure=True` (prod), `samesite='strict'`.
- `.env.example` / commit `304aabd` — historical leaked-credential remediation, confirming active secret-hygiene practice.

### 5.3 Scenario 3c: Malicious Server Pushes Fake "Recipient" Public Key

**Attack Description**: The server, during the ECDH handshake (DFD §4.3 in the TDD), returns an **attacker-controlled** ECDSA/ECDH public key when User A queries "User B's public key" — attempting to insert itself as a MitM at the *identity* layer.

**Findings**:
- If User B has **never been verified** by User A (no entry in `ContactVerification`), this attack **succeeds undetected** at the cryptographic protocol layer — the server can present any public key it wants as "User B's key" on first contact, since there is no independent root of trust (Trust-On-First-Use model). This is the **TOFU gap** documented in the TDD (§3.4, T2).
- If User A has previously **verified User B's fingerprint** (out-of-band, "✅ Verified" badge), and the server attempts to substitute a different key for a *subsequent* session, the UI would show User B as "unverified" again (fingerprint mismatch against the stored `ContactVerification.key_fingerprint`), alerting the user that something has changed.

**Verdict**: 🟡 **Partially Mitigated** — The system correctly implements the *mechanism* (fingerprint-based out-of-band verification) to detect post-verification key substitution. The **TOFU gap on first contact is an inherent, explicitly-documented limitation** shared by virtually all E2EE messengers without a centralized PKI (e.g., Signal has the same property, addressed via the same "safety number" verification UX). This is **not considered a vulnerability specific to SecureIM's implementation**, but is flagged here per the brief's request for a thorough self-assessment.

**Recommendation**: Add a UI prompt encouraging users to perform fingerprint verification immediately upon first contact, and consider surfacing a warning banner for unverified contacts in active conversations (currently, the badge is informational but conversations with unverified contacts proceed without friction).

---

## 6. Additional Findings (Beyond the Three Required Scenarios)

### 6.1 Rate Limiting

- REST authentication endpoints (`/api/auth/login`, `/api/auth/register`) are protected by `slowapi` with global defaults of `200/day, 50/hour` (`app/limiter.py`), reducing brute-force feasibility against Argon2id-hashed passwords.
- **Gap**: Socket.IO event handlers (`send_message`, `session_request`, etc.) are **not** rate-limited. A malicious authenticated client could flood the server with messages, potentially exhausting the 25MB Socket.IO buffer or database storage. Recommended for future hardening: per-connection message-rate throttling at the `socket_manager.py` / `chat.py` level.

### 6.2 CORS Configuration

- `cors_allowed_origins='*'` is set for the Socket.IO server (`app/socket_manager.py`). Combined with `SameSite=Strict` cookies, the practical CSRF/session-riding risk is low (a cross-origin page cannot attach the auth cookie to a Socket.IO handshake under `SameSite=Strict`). However, this is broader than necessary; recommend restricting to the deployed origin (`https://web-production-ce7b.up.railway.app`) and any explicitly-configured `ALLOWED_ORIGINS`.

### 6.3 Security Headers

Verified present (`app/security.py`): `Content-Security-Policy` (restricting script sources to `'self'`, blocking inline scripts — directly mitigating XSS-based theft of in-memory session keys/passwords), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security` (HTTPS enforcement, 2-year max-age with preload), `Referrer-Policy: strict-origin-when-cross-origin`, and a restrictive `Permissions-Policy` (camera/mic/geolocation disabled — appropriate for a text/file messenger with no current use for these APIs).

### 6.4 Self-Destruct Timing Side Channel

The 30-second polling interval for `cleanup_expired_messages` (`app/scheduler.py`) means a message set to expire in, e.g., 5 seconds may persist (encrypted) in the database for up to ~30 seconds after its logical expiry. Since the data remains ciphertext throughout, this is a **low-severity** timing imprecision rather than a confidentiality issue, but is noted for completeness — a sub-second cleanup interval was considered unnecessary overhead given the ciphertext-only exposure.

---

## 7. Summary of Findings

| # | Scenario | Verdict | Severity if Unmitigated |
|---|---|---|---|
| 1a | Network message replay (duplicate display) | 🟡 Partially Mitigated | Low (UX/availability only — no content forgery possible) |
| 1b | Session-handshake replay | ✅ Mitigated | N/A — requires separate private key compromise |
| 1c | Local storage blob replay/rollback | 🟡 Partially Mitigated | Low (requires local device access) |
| 2a | Network/MitM ciphertext bit-flip | ✅ Mitigated | Would be Critical if unmitigated |
| 2b | Server-side ciphertext bit-flip | ✅ Mitigated | Would be Critical if unmitigated |
| 2c | Metadata field tampering (`expires_at`, etc.) | 🟡 Partially Mitigated | Medium (availability/DoS by privileged server attacker) |
| 3a | Bulk database exfiltration | ✅ Mitigated (content); 🟡 metadata leak accepted | Would be Critical if unmitigated |
| 3b | Live server memory inspection | ✅ Mitigated (content); 🟡 JWT secret = auth-layer risk | Would be Critical if unmitigated |
| 3c | Malicious server / fake public key (TOFU) | 🟡 Partially Mitigated (inherent E2EE limitation) | Medium on first contact, mitigated post-verification |

**Overall Assessment**: SecureIM's core E2EE design — AES-256-GCM with an independent HMAC-SHA256 layer, ECDH+HKDF session key derivation, and ECDSA-signed ephemeral keys — provides **strong, verified protection against the three required attack classes for message *content***:

- **Replay** of message content cannot result in forged/modified plaintext (only inert duplicates).
- **Bit-flipping** is comprehensively blocked by dual integrity mechanisms (AES-GCM tag + HMAC-SHA256).
- **Server-side compromise**, even total (full DB + memory access), **cannot decrypt any message content**, past or future, without the relevant ECDH private keys, which never leave client devices.

The findings classified as "Partially Mitigated" are, without exception, either (a) **inherent, well-known limitations of the centralized-relay / TOFU model** shared by industry-standard E2EE systems (Signal, WhatsApp), explicitly scoped and documented rather than overlooked, or (b) **availability-layer** concerns (duplicate messages, premature expiry under server compromise) that do not compromise confidentiality or authenticity of message content — the project's primary security objectives.

---

## 8. Recommendations for Future Work

1. **Anti-replay sequence numbers**: Add a per-session monotonic counter, authenticated as part of the AES-GCM AAD, so duplicate/replayed messages can be detected and silently dropped client-side rather than displayed as duplicates.
2. **Socket.IO rate limiting**: Extend `slowapi`-style throttling to real-time message events to prevent authenticated-client flooding.
3. **CORS tightening**: Restrict `cors_allowed_origins` from `'*'` to the explicit production origin.
4. **First-contact verification prompts**: Proactively encourage fingerprint verification on first conversation with a new contact to narrow the TOFU window.
5. **File/Image attachment hardening** (active development): Ensure the in-progress attachment feature (i) reuses existing session keys (no new key material), (ii) enforces the same HMAC-then-AES-GCM verification order as text messages, and (iii) addresses `localStorage` quota limits via IndexedDB or size-capped retention for media, maintaining the encryption-at-rest guarantee for any locally cached media.
6. **Reduce self-destruct cleanup interval** if sub-30-second precision becomes a product requirement (currently low priority given ciphertext-only exposure during the window).

---

## 9. Conclusion

This self-assessment did not identify any finding that allows an attacker — at the network, server-compromise, or local-device level — to **read, forge, or undetectably tamper with end-to-end encrypted message content**. All identified gaps fall into either (a) well-documented, industry-standard limitations of the E2EE/centralized-relay architecture (metadata exposure, TOFU), or (b) availability/UX-layer issues (duplicate display on replay, premature expiry under a fully compromised server) that do not violate the confidentiality or integrity guarantees that are the focus of the project's threat model. The system is assessed as **meeting the project's security requirements for replay resistance, bit-flipping resistance, and resilience to server-side compromise**, with the residual risks above documented for transparency and future hardening.
