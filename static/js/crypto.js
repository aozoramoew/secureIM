/**
 * crypto.js — SecureIM Client-Side Cryptography
 *
 * All cryptographic operations using the browser's native Web Crypto API.
 * No third-party crypto libraries required.
 *
 * Primitives used:
 *  - ECDSA P-384   : Identity key pair (signing / verification)
 *  - ECDH P-256    : Ephemeral key exchange
 *  - HKDF + SHA-256: Session key derivation from ECDH shared secret
 *  - AES-256-GCM   : Symmetric message encryption (provides confidentiality + integrity)
 *  - HMAC-SHA256   : Explicit message authentication code (additional tamper detection)
 *  - PBKDF2 SHA-256: Key derivation from user passphrase (local storage encryption)
 */

const SecureCrypto = (() => {

  // ── Utility ────────────────────────────────────────────────────

  function bufToB64(buf) {
    // Chunked to avoid stack overflow on large buffers (cross-browser safe)
    const bytes = new Uint8Array(buf);
    let binary = '';
    const chunkSize = 8192;
    for (let i = 0; i < bytes.length; i += chunkSize) {
      binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
    }
    return btoa(binary);
  }

  function b64ToBuf(b64) {
    const bin = atob(b64);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  }

  function strToU8(str) {
    return new TextEncoder().encode(str);
  }

  function u8ToStr(buf) {
    return new TextDecoder().decode(buf);
  }

  async function exportKeyJWK(key) {
    return JSON.stringify(await crypto.subtle.exportKey('jwk', key));
  }

  async function importPublicECDSA(jwkStr) {
    return crypto.subtle.importKey(
      'jwk', JSON.parse(jwkStr),
      { name: 'ECDSA', namedCurve: 'P-384' },
      true, ['verify']
    );
  }

  async function importPublicECDH(jwkStr) {
    return crypto.subtle.importKey(
      'jwk', JSON.parse(jwkStr),
      { name: 'ECDH', namedCurve: 'P-256' },
      true, []
    );
  }

  async function importPrivateECDH(jwkStr) {
    return crypto.subtle.importKey(
      'jwk', JSON.parse(jwkStr),
      { name: 'ECDH', namedCurve: 'P-256' },
      true, ['deriveKey', 'deriveBits']
    );
  }

  // ── Key Fingerprint ────────────────────────────────────────────

  /**
   * SHA-256 fingerprint of a public key JWK string.
   * Displayed as XX:XX:XX:... pairs for out-of-band verification.
   */
  async function computeFingerprint(publicKeyJwkStr) {
    const hashBuf = await crypto.subtle.digest('SHA-256', strToU8(publicKeyJwkStr));
    const hex = Array.from(new Uint8Array(hashBuf))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    return hex.match(/.{2}/g).slice(0, 16).join(':').toUpperCase();
  }

  // ── Identity Key Pair (ECDSA P-384) ───────────────────────────

  async function generateIdentityKeyPair() {
    return crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['sign', 'verify']
    );
  }

  async function signData(privateKey, data) {
    const sig = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-384' },
      privateKey,
      strToU8(typeof data === 'string' ? data : JSON.stringify(data))
    );
    return bufToB64(sig);
  }

  async function verifySignature(publicKeyJwkStr, data, signatureB64) {
    try {
      const pubKey = await importPublicECDSA(publicKeyJwkStr);
      return await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-384' },
        pubKey,
        b64ToBuf(signatureB64),
        strToU8(typeof data === 'string' ? data : JSON.stringify(data))
      );
    } catch {
      return false;
    }
  }

  // ── Ephemeral ECDH Key Pair (P-256) ───────────────────────────

  async function generateEphemeralKeyPair() {
    return crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );
  }

  // ── Session Key Derivation (ECDH + HKDF) ──────────────────────

  /**
   * Derive a 256-bit AES-GCM session key from an ECDH exchange.
   * Both parties independently compute the same key.
   * Uses HKDF for key stretching and domain separation.
   */
  async function deriveSessionKey(myPrivateKey, theirPublicKeyJwkStr) {
    const theirPubKey = await importPublicECDH(theirPublicKeyJwkStr);

    const sharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: theirPubKey },
      myPrivateKey,
      256
    );

    const keyMaterial = await crypto.subtle.importKey(
      'raw', sharedBits, 'HKDF', false, ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(32),  // zero salt (context-separated by info)
        info: strToU8('SecureIM-v1-session-key'),
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Also derive a separate HMAC key from the same ECDH shared secret.
   * Provides explicit authentication independent of AES-GCM tag.
   */
  async function deriveHMACKey(myPrivateKey, theirPublicKeyJwkStr) {
    const theirPubKey = await importPublicECDH(theirPublicKeyJwkStr);
    const sharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: theirPubKey },
      myPrivateKey,
      256
    );

    const keyMaterial = await crypto.subtle.importKey(
      'raw', sharedBits, 'HKDF', false, ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(32),
        info: strToU8('SecureIM-v1-hmac-key'),
      },
      keyMaterial,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign', 'verify']
    );
  }

  // ── Message Encryption / Decryption (AES-256-GCM) ─────────────

  /**
   * Encrypt plaintext with AES-256-GCM.
   * Returns { ciphertext, nonce, hmac } all as base64 strings.
   * AES-GCM provides authenticated encryption (integrity + confidentiality).
   * The explicit HMAC-SHA256 provides an additional, independent integrity check.
   */
  async function encryptMessage(aesKey, hmacKey, plaintext) {
    const nonce = crypto.getRandomValues(new Uint8Array(12));  // 96-bit GCM nonce
    const encoded = strToU8(plaintext);

    const ciphertextBuf = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      aesKey,
      encoded
    );

    // HMAC over nonce || ciphertext for explicit integrity proof
    const hmacInput = new Uint8Array(nonce.length + ciphertextBuf.byteLength);
    hmacInput.set(nonce, 0);
    hmacInput.set(new Uint8Array(ciphertextBuf), nonce.length);

    const hmacBuf = await crypto.subtle.sign('HMAC', hmacKey, hmacInput);

    return {
      ciphertext: bufToB64(ciphertextBuf),
      nonce:      bufToB64(nonce),
      hmac:       bufToB64(hmacBuf),
    };
  }

  /**
   * Decrypt a message. Verifies HMAC before attempting AES-GCM decryption.
   * Throws on any integrity failure.
   */
  async function decryptMessage(aesKey, hmacKey, payload) {
    const { ciphertext, nonce, hmac } = payload;
    const nonceBuf      = new Uint8Array(b64ToBuf(nonce));
    const ciphertextBuf = new Uint8Array(b64ToBuf(ciphertext));

    // 1. Verify HMAC first — reject tampered messages before decryption
    const hmacInput = new Uint8Array(nonceBuf.length + ciphertextBuf.length);
    hmacInput.set(nonceBuf, 0);
    hmacInput.set(ciphertextBuf, nonceBuf.length);

    const valid = await crypto.subtle.verify('HMAC', hmacKey, b64ToBuf(hmac), hmacInput);
    if (!valid) {
      throw new Error('HMAC verification failed — message may be tampered');
    }

    // 2. AES-GCM decrypt (also verifies GCM authentication tag)
    const plaintextBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonceBuf },
      aesKey,
      ciphertextBuf
    );

    return u8ToStr(plaintextBuf);
  }

  /**
   * Encrypt a binary file with metadata (filename, mime type).
   * Packs the metadata JSON length (4 bytes), metadata JSON, and raw file bytes together
   * before encrypting with AES-GCM.
   */
  async function encryptBinaryMessage(aesKey, hmacKey, arrayBuffer, metadata) {
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const metaStr = JSON.stringify(metadata);
    const metaBytes = strToU8(metaStr);
    
    // Format: [4 bytes metadata length] + [metadata bytes] + [file bytes]
    const metaLen = new Uint32Array([metaBytes.length]);
    const metaLenBytes = new Uint8Array(metaLen.buffer);
    
    const plaintext = new Uint8Array(4 + metaBytes.length + arrayBuffer.byteLength);
    plaintext.set(metaLenBytes, 0);
    plaintext.set(metaBytes, 4);
    plaintext.set(new Uint8Array(arrayBuffer), 4 + metaBytes.length);

    const ciphertextBuf = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      aesKey,
      plaintext
    );

    const hmacInput = new Uint8Array(nonce.length + ciphertextBuf.byteLength);
    hmacInput.set(nonce, 0);
    hmacInput.set(new Uint8Array(ciphertextBuf), nonce.length);

    const hmacBuf = await crypto.subtle.sign('HMAC', hmacKey, hmacInput);

    return {
      ciphertext: bufToB64(ciphertextBuf),
      nonce:      bufToB64(nonce),
      hmac:       bufToB64(hmacBuf),
    };
  }

  /**
   * Decrypt a binary message and extract metadata and file bytes.
   */
  async function decryptBinaryMessage(aesKey, hmacKey, payload) {
    const { ciphertext, nonce, hmac } = payload;
    const nonceBuf      = new Uint8Array(b64ToBuf(nonce));
    const ciphertextBuf = new Uint8Array(b64ToBuf(ciphertext));

    const hmacInput = new Uint8Array(nonceBuf.length + ciphertextBuf.length);
    hmacInput.set(nonceBuf, 0);
    hmacInput.set(ciphertextBuf, nonceBuf.length);

    const valid = await crypto.subtle.verify('HMAC', hmacKey, b64ToBuf(hmac), hmacInput);
    if (!valid) {
      throw new Error('HMAC verification failed — message may be tampered');
    }

    const plaintextBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonceBuf },
      aesKey,
      ciphertextBuf
    );

    const plaintextBytes = new Uint8Array(plaintextBuf);
    
    // Extract metadata length
    const metaLenBytes = new Uint8Array(4);
    metaLenBytes.set(plaintextBytes.subarray(0, 4));
    const metaLen = new Uint32Array(metaLenBytes.buffer)[0];
    
    // Extract metadata
    const metaBytes = plaintextBytes.subarray(4, 4 + metaLen);
    const metadata = JSON.parse(u8ToStr(metaBytes));
    
    // Extract file bytes
    const fileBytes = plaintextBytes.subarray(4 + metaLen);
    
    return {
      metadata,
      fileBuffer: fileBytes.buffer
    };
  }

  // ── Local Storage Encryption (PBKDF2 + AES-256-GCM) ───────────

  /**
   * Derive an AES-256-GCM key from a user passphrase using PBKDF2.
   * Used to encrypt chat history stored in localStorage.
   */
  async function deriveStorageKey(passphrase, saltB64) {
    const salt = saltB64
      ? new Uint8Array(b64ToBuf(saltB64))
      : crypto.getRandomValues(new Uint8Array(32));

    const keyMaterial = await crypto.subtle.importKey(
      'raw', strToU8(passphrase), 'PBKDF2', false, ['deriveKey']
    );

    const key = await crypto.subtle.deriveKey(
      {
        name:       'PBKDF2',
        hash:       'SHA-256',
        salt,
        iterations: 310000,  // OWASP recommended minimum for PBKDF2-SHA256
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    return { key, saltB64: bufToB64(salt.buffer) };
  }

  async function encryptForStorage(passphrase, data, existingSaltB64 = null) {
    const { key, saltB64 } = await deriveStorageKey(passphrase, existingSaltB64);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = strToU8(JSON.stringify(data));

    const ciphertextBuf = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      key,
      plaintext
    );

    return {
      salt:       saltB64,
      nonce:      bufToB64(nonce),
      ciphertext: bufToB64(ciphertextBuf),
    };
  }

  async function decryptFromStorage(passphrase, encrypted) {
    const { key } = await deriveStorageKey(passphrase, encrypted.salt);
    const plaintextBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(b64ToBuf(encrypted.nonce)) },
      key,
      new Uint8Array(b64ToBuf(encrypted.ciphertext))
    );
    return JSON.parse(u8ToStr(plaintextBuf));
  }

  // ── Key Serialization (for sending to server / persisting) ─────

  async function serializeKeyPair(keyPair) {
    return {
      publicKey:  await exportKeyJWK(keyPair.publicKey),
      privateKey: await exportKeyJWK(keyPair.privateKey),
    };
  }

  // ── Encrypt private key for secure localStorage persistence ────

  /**
   * Encrypts private keys with a key derived from the user's password.
   * Private keys NEVER leave the device in plaintext.
   */
  async function encryptPrivateKey(passphrase, privateKeyJwkStr) {
    return encryptForStorage(passphrase, { jwk: privateKeyJwkStr });
  }

  async function decryptPrivateKey(passphrase, encrypted) {
    const data = await decryptFromStorage(passphrase, encrypted);
    return data.jwk;
  }

  // ── Public API ─────────────────────────────────────────────────

  return {
    // Key generation
    generateIdentityKeyPair,
    generateEphemeralKeyPair,

    // Key exchange & derivation
    deriveSessionKey,
    deriveHMACKey,

    // Message E2EE
    encryptMessage,
    decryptMessage,
    encryptBinaryMessage,
    decryptBinaryMessage,

    // Identity / signing
    signData,
    verifySignature,
    computeFingerprint,

    // Local storage
    encryptForStorage,
    decryptFromStorage,
    encryptPrivateKey,
    decryptPrivateKey,

    // Serialization
    exportKeyJWK,
    importPublicECDSA,
    importPublicECDH,
    importPrivateECDH,
    serializeKeyPair,

    // Utilities
    bufToB64,
    b64ToBuf,
  };
})();
