"""
Authentication API router — FastAPI conversion.

Endpoints:
  POST   /api/auth/register
  POST   /api/auth/login
  POST   /api/auth/logout
  POST   /api/auth/resend-verification
  GET    /api/auth/verify-email          (email link click → redirect)
  GET    /api/auth/2fa-verify            (device auth link → redirect)
  GET    /api/auth/2fa-status            (polling)
  GET    /api/auth/me
  PUT    /api/auth/settings
  GET    /api/auth/devices
  DELETE /api/auth/devices/{device_id}
  GET    /api/auth/dev-links             (dev mode only)

Email verification change:
  - Registration NO LONGER auto-verifies users.
  - Returns {status:'verification_sent'} → frontend shows "check your email" panel.
  - Login rejects unverified accounts with code 'email_not_verified'.
"""
import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, DeviceKey, EmailVerification, AuditLog
from app.limiter import limiter
from app.crypto_utils import (
    hash_password, verify_password, needs_rehash,
    generate_jwt, decode_jwt, generate_secure_token,
)
from app.email_utils import send_verification_email, send_2fa_email, _dev_link_buffer
from config import settings

router = APIRouter()


# ── Auth dependency ────────────────────────────────────────────────

def get_current_user_and_device(
    request: Request,
    db: Session = Depends(get_db),
):
    """Validates the Bearer JWT and returns (user, device) or raises 401."""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        raise HTTPException(status_code=401, detail='Missing authorization token')
    token = auth_header.split(' ', 1)[1]
    payload = decode_jwt(token)
    if not payload:
        raise HTTPException(status_code=401, detail='Invalid or expired token')

    user = db.get(User, int(payload['sub']))
    if not user:
        raise HTTPException(status_code=401, detail='User not found')

    device = db.query(DeviceKey).filter_by(
        user_id=user.id,
        device_id=payload['device_id'],
        is_active=True,
    ).first()
    if not device:
        raise HTTPException(status_code=401, detail='Device not authorized')

    device.last_seen = datetime.utcnow()
    db.commit()
    return user, device


# ── Audit helper ───────────────────────────────────────────────────

def _audit(db: Session, event_type: str, request: Request,
           user_id=None, detail: dict | None = None):
    try:
        entry = AuditLog(
            event_type=event_type,
            user_id=user_id,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get('User-Agent', '')[:256],
            detail=json.dumps(detail or {}),
        )
        db.add(entry)
        db.commit()
    except Exception:
        pass  # Audit must never break the main flow


# ── Pydantic request models ────────────────────────────────────────

class RegisterBody(BaseModel):
    username:         str
    email:            str
    password:         str
    ecdsa_public_key: str
    ecdh_public_key:  str
    device_id:        str
    device_name:      Optional[str] = 'Browser'


class LoginBody(BaseModel):
    username:         str
    password:         str
    device_id:        str
    device_name:      Optional[str] = 'Browser'
    ecdsa_public_key: Optional[str] = None
    ecdh_public_key:  Optional[str] = None


class ResendVerificationBody(BaseModel):
    email: str


class SettingsBody(BaseModel):
    store_history: Optional[bool] = None
    session_mode:  Optional[bool] = None


# ── Register ───────────────────────────────────────────────────────

@router.post('/register', status_code=201)
@limiter.limit('5/hour')
def register(request: Request, body: RegisterBody, db: Session = Depends(get_db)):
    username         = body.username.strip().lower()
    email            = body.email.strip().lower()
    password         = body.password
    ecdsa_public_key = body.ecdsa_public_key
    ecdh_public_key  = body.ecdh_public_key
    device_id        = body.device_id
    device_name      = body.device_name or 'Browser'

    # Validation
    if len(username) < 3 or len(username) > 30:
        raise HTTPException(status_code=400, detail='Username must be 3–30 characters')
    if len(password) < 8:
        raise HTTPException(status_code=400, detail='Password must be at least 8 characters')
    if db.query(User).filter_by(username=username).first():
        raise HTTPException(status_code=409, detail='Username already taken')
    if db.query(User).filter_by(email=email).first():
        raise HTTPException(status_code=409, detail='Email already registered')

    # Create user — email NOT yet verified
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        is_email_verified=False,   # <── real verification required
    )
    db.add(user)
    db.flush()  # get user.id

    # Register first device (inactive until email verified)
    device = DeviceKey(
        user_id=user.id,
        device_id=device_id,
        ecdsa_public_key=ecdsa_public_key,
        ecdh_public_key=ecdh_public_key,
        device_name=device_name,
        is_active=False,  # activated after email verification
    )
    db.add(device)

    # Create email verification token
    exp = datetime.utcnow() + settings.EMAIL_VERIFY_TOKEN_EXPIRY
    ev = EmailVerification(
        user_id=user.id,
        token=generate_secure_token(),
        verification_type='email_verify',
        device_id=device_id,          # so we can activate the device on verify
        expires_at=exp,
    )
    db.add(ev)
    db.commit()

    # Send verification email (non-blocking — fires and returns)
    send_verification_email(user, ev.token)

    _audit(db, 'register', request, user_id=user.id,
           detail={'username': username, 'email': email})

    return {
        'status':  'verification_sent',
        'message': 'Account created! Please check your email and click the activation link.',
        'email':   email,
    }


# ── Resend Verification ────────────────────────────────────────────

@router.post('/resend-verification')
@limiter.limit('3/hour')
def resend_verification(
    request: Request,
    body: ResendVerificationBody,
    db: Session = Depends(get_db),
):
    email = body.email.strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail='Email is required')

    user = db.query(User).filter_by(email=email).first()
    # Always return success to avoid email enumeration
    if not user:
        return {'message': 'If that email is registered, a new verification link has been sent.'}

    if user.is_email_verified:
        raise HTTPException(status_code=400, detail='This account is already verified. Please sign in.')

    # Invalidate existing unused tokens
    old_evs = db.query(EmailVerification).filter_by(
        user_id=user.id, verification_type='email_verify', is_used=False
    ).all()
    for old in old_evs:
        old.is_used = True

    # Fresh token
    exp = datetime.utcnow() + settings.EMAIL_VERIFY_TOKEN_EXPIRY
    ev = EmailVerification(
        user_id=user.id,
        token=generate_secure_token(),
        verification_type='email_verify',
        expires_at=exp,
    )
    db.add(ev)
    db.commit()

    send_verification_email(user, ev.token)
    _audit(db, 'resend_verification', request, user_id=user.id)
    return {'message': 'A new verification email has been sent. Please check your inbox.'}


# ── Email Verification (link click) ───────────────────────────────

@router.get('/verify-email')
def verify_email(token: str = '', db: Session = Depends(get_db)):
    ev = db.query(EmailVerification).filter_by(
        token=token, verification_type='email_verify', is_used=False
    ).first()

    if not ev or ev.is_expired():
        return RedirectResponse(url='/?error=invalid_or_expired_link')

    ev.is_used = True
    ev.user.is_email_verified = True

    # Also activate the device that was registered alongside
    if ev.device_id:
        device = db.query(DeviceKey).filter_by(
            user_id=ev.user_id, device_id=ev.device_id
        ).first()
        if device:
            device.is_active = True
            device.last_seen = datetime.utcnow()

    db.commit()
    return RedirectResponse(url='/login?verified=1')


# ── Login ──────────────────────────────────────────────────────────

@router.post('/login')
@limiter.limit('10/minute')
def login(request: Request, body: LoginBody, db: Session = Depends(get_db)):
    username         = body.username.strip().lower()
    password         = body.password
    device_id        = body.device_id
    device_name      = body.device_name or 'Browser'
    ecdsa_public_key = body.ecdsa_public_key
    ecdh_public_key  = body.ecdh_public_key

    user = db.query(User).filter_by(username=username).first()
    if not user or not verify_password(password, user.password_hash):
        _audit(db, 'login_fail', request, detail={'username': username})
        raise HTTPException(status_code=401, detail='Invalid username or password')

    # Reject unverified accounts
    if not user.is_email_verified:
        raise HTTPException(
            status_code=403,
            detail='Email not verified. Please check your inbox or request a new link.',
            headers={'X-Error-Code': 'email_not_verified'},
        )

    # Rehash if params changed
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
        db.commit()

    existing_device = db.query(DeviceKey).filter_by(
        user_id=user.id, device_id=device_id, is_active=True
    ).first()

    if existing_device:
        # Known device — issue JWT immediately
        existing_device.last_seen = datetime.utcnow()
        if ecdsa_public_key:
            existing_device.ecdsa_public_key = ecdsa_public_key
        if ecdh_public_key:
            existing_device.ecdh_public_key = ecdh_public_key
        db.commit()

        token = generate_jwt(user.id, device_id)
        _audit(db, 'login_ok', request, user_id=user.id, detail={'device_id': device_id})
        return {'status': 'ok', 'token': token, 'user': user.to_dict()}

    else:
        # New device — require 2FA email
        if not ecdsa_public_key or not ecdh_public_key:
            raise HTTPException(
                status_code=400,
                detail='Public keys required for new device registration',
            )

        new_device = DeviceKey(
            user_id=user.id,
            device_id=device_id,
            ecdsa_public_key=ecdsa_public_key,
            ecdh_public_key=ecdh_public_key,
            device_name=device_name,
            is_active=False,
        )
        db.add(new_device)

        exp = datetime.utcnow() + settings.VERIFICATION_TOKEN_EXPIRY
        ev = EmailVerification(
            user_id=user.id,
            token=generate_secure_token(),
            verification_type='2fa_login',
            device_id=device_id,
            expires_at=exp,
        )
        db.add(ev)
        db.commit()

        send_2fa_email(user, device_name, ev.token)
        return {
            'status':    '2fa_required',
            'device_id': device_id,
            'message':   'Check your email to authorize this device.',
        }, 202


# ── 2FA Device Authorization (link click) ─────────────────────────

@router.get('/2fa-verify')
def two_factor_verify(token: str = '', db: Session = Depends(get_db)):
    ev = db.query(EmailVerification).filter_by(
        token=token, verification_type='2fa_login', is_used=False
    ).first()

    if not ev or ev.is_expired():
        return RedirectResponse(url='/?error=invalid_or_expired_2fa')

    device = db.query(DeviceKey).filter_by(
        user_id=ev.user_id, device_id=ev.device_id
    ).first()
    if not device:
        return RedirectResponse(url='/?error=device_not_found')

    device.is_active = True
    device.last_seen = datetime.utcnow()
    ev.is_used = True
    db.commit()
    return RedirectResponse(url=f'/device-authorized?device={device.device_name}')


# ── 2FA Status Polling ─────────────────────────────────────────────

@router.get('/2fa-status')
def two_factor_status(device_id: str = '', db: Session = Depends(get_db)):
    if not device_id:
        raise HTTPException(status_code=400, detail='device_id required')

    device = db.query(DeviceKey).filter_by(device_id=device_id, is_active=True).first()
    if not device:
        return {'status': 'pending'}

    token = generate_jwt(device.user_id, device_id)
    user  = db.get(User, device.user_id)
    return {'status': 'authorized', 'token': token, 'user': user.to_dict()}


# ── Me / Settings / Devices ───────────────────────────────────────

@router.get('/me')
def me(auth=Depends(get_current_user_and_device)):
    user, _ = auth
    return {'user': user.to_dict()}


@router.put('/settings')
def update_settings(body: SettingsBody, auth=Depends(get_current_user_and_device),
                    db: Session = Depends(get_db)):
    user, _ = auth
    s = user.get_settings()
    if body.store_history is not None:
        s['store_history'] = body.store_history
    if body.session_mode is not None:
        s['session_mode'] = body.session_mode
    user.set_settings(s)
    db.commit()
    return {'settings': s}


@router.get('/devices')
def list_devices(auth=Depends(get_current_user_and_device), db: Session = Depends(get_db)):
    user, _ = auth
    devices = db.query(DeviceKey).filter_by(user_id=user.id, is_active=True).all()
    return {'devices': [d.to_dict() for d in devices]}


@router.delete('/devices/{dev_id}')
def revoke_device(dev_id: str, auth=Depends(get_current_user_and_device),
                  db: Session = Depends(get_db)):
    user, _ = auth
    device = db.query(DeviceKey).filter_by(user_id=user.id, device_id=dev_id).first()
    if not device:
        raise HTTPException(status_code=404, detail='Device not found')
    device.is_active = False
    db.commit()
    return {'message': 'Device revoked'}


@router.post('/logout')
def logout(auth=Depends(get_current_user_and_device), db: Session = Depends(get_db)):
    user, device = auth
    device.is_active = False
    db.commit()
    return {'message': 'Logged out successfully'}


# ── Dev-only: view suppressed email links ─────────────────────────

@router.get('/dev-links')
def dev_links():
    if not settings.MAIL_SUPPRESS_SEND:
        raise HTTPException(status_code=403, detail='Not available in production')
    return {
        'note': 'Suppressed emails (dev mode). Copy the link and open it in your browser.',
        'links': list(reversed(_dev_link_buffer)),  # newest first
    }
