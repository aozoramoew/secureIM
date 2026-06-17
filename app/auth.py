"""
Authentication API router — FastAPI.

Endpoints:
  POST   /api/auth/register
  POST   /api/auth/login
  POST   /api/auth/logout
  GET    /api/auth/me
  PUT    /api/auth/settings
  GET    /api/auth/devices
  DELETE /api/auth/devices/{device_id}

JWT is delivered via an HttpOnly, Secure, SameSite=Strict cookie named
`sim_token` — it is never exposed to JavaScript.  All API endpoints that
need authentication read the cookie instead of the Authorization header.
SocketIO auth still accepts a `token` field in the auth dict because
browser WebSocket API cannot send cookies programmatically on every
connection; the SocketIO client is given the token value once on connect.
"""
import json
import logging
import re
from datetime import datetime
from typing import Optional
from config import settings

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, DeviceKey, AuditLog
from app.limiter import limiter
from app.crypto_utils import (
    hash_password, verify_password, needs_rehash,
    generate_jwt, decode_jwt,
)

log = logging.getLogger(__name__)

router = APIRouter()

_COOKIE_NAME = 'sim_token'
_COOKIE_MAX_AGE = 86400 * 7  # 7 days, matching JWT expiry


def _set_auth_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=_COOKIE_NAME,
        value=token,
        max_age=_COOKIE_MAX_AGE,
        httponly=True,
        secure=not settings.DEBUG,  # True in production (HTTPS only)
        samesite='strict',
        path='/',
    )


def _clear_auth_cookie(response: Response) -> None:
    response.delete_cookie(key=_COOKIE_NAME, path='/')


# ── Auth dependency ────────────────────────────────────────────────

def get_current_user_and_device(
    request: Request,
    db: Session = Depends(get_db),
):
    """Validates the JWT from HttpOnly cookie and returns (user, device) or raises 401."""
    token = request.cookies.get(_COOKIE_NAME)

    # Fallback: also accept Bearer header so SocketIO REST calls work
    # (SocketIO HTTP polling carries cookies, but raw fetch calls from
    #  the socket manager use the Authorization header path).
    if not token:
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ', 1)[1]

    if not token:
        raise HTTPException(status_code=401, detail='Missing authorization token')

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
        db.rollback()
        log.warning('Failed to write audit log entry (event_type=%s)', event_type, exc_info=True)


# ── Pydantic request models ────────────────────────────────────────

class RegisterBody(BaseModel):
    username:         str
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


class SettingsBody(BaseModel):
    store_history: Optional[bool] = None
    session_mode:  Optional[bool] = None


# ── Register ───────────────────────────────────────────────────────

@router.post('/register', status_code=201)
@limiter.limit('5/hour')
def register(request: Request, body: RegisterBody,
             response: Response,
             db: Session = Depends(get_db)):
    username = body.username.strip().lower()
    password = body.password
    device_id = body.device_id
    device_name = body.device_name or 'Browser'

    if len(username) < 3 or len(username) > 30:
        raise HTTPException(
            status_code=400, detail='Username must be 3–30 characters')
    if not re.fullmatch(r'[a-z0-9_-]+', username):
        raise HTTPException(
            status_code=400,
            detail='Username may only contain letters, numbers, "_" and "-"')
    if len(password) < 8:
        raise HTTPException(
            status_code=400, detail='Password must be at least 8 characters')
    if db.query(User).filter_by(username=username).first():
        raise HTTPException(status_code=409, detail='Username already taken')

    try:
        user = User(
            username=username,
            password_hash=hash_password(password),
        )
        db.add(user)
        db.flush()

        device = DeviceKey(
            user_id=user.id,
            device_id=device_id,
            ecdsa_public_key=body.ecdsa_public_key,
            ecdh_public_key=body.ecdh_public_key,
            device_name=device_name,
            is_active=True,
        )
        db.add(device)
        db.commit()
    except Exception as exc:
        db.rollback()
        log.exception('[register] DB error for username=%s: %s', username, exc)
        raise HTTPException(status_code=500, detail='Registration failed due to a server error')

    token = generate_jwt(user.id, device_id)
    _set_auth_cookie(response, token)
    _audit(db, 'register', request, user_id=user.id,
           detail={'username': username})

    return {
        'status': 'ok',
        'user': user.to_dict(),
        'message': 'Account created — welcome to SecureIM!',
    }


# ── Login ──────────────────────────────────────────────────────────

@router.post('/login')
@limiter.limit('10/minute')
def login(request: Request, body: LoginBody, response: Response,
          db: Session = Depends(get_db)):
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

    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
        db.commit()

    existing_device = db.query(DeviceKey).filter_by(
        user_id=user.id, device_id=device_id, is_active=True
    ).first()

    if existing_device:
        existing_device.last_seen = datetime.utcnow()
        if ecdsa_public_key:
            existing_device.ecdsa_public_key = ecdsa_public_key
        if ecdh_public_key:
            existing_device.ecdh_public_key = ecdh_public_key
        db.commit()

        token = generate_jwt(user.id, device_id)
        _set_auth_cookie(response, token)
        _audit(db, 'login_ok', request, user_id=user.id,
               detail={'device_id': device_id})
        return {'status': 'ok', 'user': user.to_dict()}

    else:
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
            is_active=True,
        )
        db.add(new_device)
        db.commit()

        token = generate_jwt(user.id, device_id)
        _set_auth_cookie(response, token)
        _audit(db, 'login_ok', request, user_id=user.id,
               detail={'device_id': device_id, 'new_device': True})
        return {'status': 'ok', 'user': user.to_dict()}


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
def list_devices(auth=Depends(get_current_user_and_device),
                 db: Session = Depends(get_db)):
    user, _ = auth
    devices = db.query(DeviceKey).filter_by(user_id=user.id, is_active=True).all()
    return {'devices': [d.to_dict() for d in devices]}


@router.delete('/devices/{dev_id}')
def revoke_device(dev_id: str, auth=Depends(get_current_user_and_device),
                  db: Session = Depends(get_db)):
    user, _ = auth
    device = db.query(DeviceKey).filter_by(
        user_id=user.id, device_id=dev_id
    ).first()
    if not device:
        raise HTTPException(status_code=404, detail='Device not found')
    device.is_active = False
    db.commit()
    return {'message': 'Device revoked'}


@router.post('/logout')
def logout(response: Response, auth=Depends(get_current_user_and_device),
           db: Session = Depends(get_db)):
    user, device = auth
    device.is_active = False
    db.commit()
    _clear_auth_cookie(response)
    return {'message': 'Logged out successfully'}
