"""
Server-side cryptographic utilities — framework agnostic.
Handles: Argon2id password hashing, JWT token management,
secure random token generation, key fingerprinting.
Client-side E2EE (ECDH, AES-GCM, HMAC) lives in static/js/crypto.js.
"""
import secrets
import hashlib
from datetime import datetime, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

from config import settings

# Argon2id — OWASP recommended parameters (m=64 MB, t=3, p=4)
_ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


# ── Password ──────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """Return argon2id hash of password."""
    return _ph.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """Verify password against argon2id hash. Returns False on mismatch."""
    try:
        return _ph.verify(hashed, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(hashed: str) -> bool:
    return _ph.check_needs_rehash(hashed)


# ── JWT ───────────────────────────────────────────────────────────

def generate_jwt(user_id: int, device_id: str) -> str:
    """Generate a signed JWT for a given user/device pair."""
    expiry = datetime.now(tz=timezone.utc) + settings.JWT_EXPIRY
    payload = {
        'sub':       str(user_id),
        'device_id': device_id,
        'exp':       expiry,
        'iat':       datetime.now(tz=timezone.utc),
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm='HS256')


def decode_jwt(token: str) -> dict | None:
    """Decode and validate JWT. Returns payload dict or None."""
    try:
        return jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=['HS256'],
        )
    except jwt.PyJWTError:
        return None


# ── Secure Tokens ─────────────────────────────────────────────────

def generate_secure_token(length: int = 48) -> str:
    """Generate a URL-safe random token (hex string)."""
    return secrets.token_urlsafe(length)


def fingerprint(public_key_jwk_str: str) -> str:
    """
    SHA-256 fingerprint of a JWK public key string.
    Displayed as colon-separated hex pairs (like SSH key fingerprints).
    """
    raw = hashlib.sha256(public_key_jwk_str.encode()).hexdigest()
    return ':'.join(raw[i:i+2] for i in range(0, 16, 2))  # first 8 bytes for display
