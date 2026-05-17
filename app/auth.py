"""
Authentication blueprint — handles:
  POST /api/auth/register
  POST /api/auth/login
  POST /api/auth/logout
  GET  /api/auth/verify-email   (email activation link)
  GET  /api/auth/2fa-verify     (device authorization link)
  GET  /api/auth/2fa-status     (polling endpoint — returns JWT when device authorized)
  GET  /api/auth/me             (current user info)
  PUT  /api/auth/settings       (update user settings)
  GET  /api/auth/devices        (list user's devices)
  DELETE /api/auth/devices/<device_id>  (revoke a device)
"""
from datetime import datetime
from functools import wraps

from flask import Blueprint, request, jsonify, current_app, redirect

from app import db
from app.models import User, DeviceKey, EmailVerification
from app.limiter import limiter
from app.crypto_utils import (
    hash_password, verify_password, needs_rehash,
    generate_jwt, decode_jwt, generate_secure_token,
)
from app.email_utils import send_verification_email, send_2fa_email

auth_bp = Blueprint('auth', __name__)


# ── Auth decorator ─────────────────────────────────────────────────

def token_required(f):
    """Decorator that validates the Bearer JWT and injects current_user, device_id."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing authorization token'}), 401
        token = auth_header.split(' ', 1)[1]
        payload = decode_jwt(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401

        user = User.query.get(int(payload['sub']))
        if not user:
            return jsonify({'error': 'User not found'}), 401

        device = DeviceKey.query.filter_by(
            user_id=user.id,
            device_id=payload['device_id'],
            is_active=True
        ).first()
        if not device:
            return jsonify({'error': 'Device not authorized'}), 401

        # Update last-seen
        device.last_seen = datetime.utcnow()
        db.session.commit()

        return f(user, device, *args, **kwargs)
    return decorated


# ── Register ──────────────────────────────────────────────────────

@auth_bp.route('/register', methods=['POST'])
@limiter.limit('5 per hour')
def register():
    data = request.get_json(silent=True) or {}
    username         = (data.get('username') or '').strip().lower()
    email            = (data.get('email') or '').strip().lower()
    password         = data.get('password') or ''
    ecdsa_public_key = data.get('ecdsa_public_key')   # JWK JSON string
    ecdh_public_key  = data.get('ecdh_public_key')    # JWK JSON string
    device_id        = data.get('device_id')
    device_name      = data.get('device_name', 'Browser')

    # Basic validation
    if not all([username, email, password, ecdsa_public_key, ecdh_public_key, device_id]):
        return jsonify({'error': 'All fields are required'}), 400
    if len(username) < 3 or len(username) > 30:
        return jsonify({'error': 'Username must be 3–30 characters'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already taken'}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 409

    # Create user
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
    )
    db.session.add(user)
    db.session.flush()  # get user.id

    # Register first device
    device = DeviceKey(
        user_id=user.id,
        device_id=device_id,
        ecdsa_public_key=ecdsa_public_key,
        ecdh_public_key=ecdh_public_key,
        device_name=device_name,
    )
    db.session.add(device)

    # Email verification token
    exp = datetime.utcnow() + current_app.config['EMAIL_VERIFY_TOKEN_EXPIRY']
    ev = EmailVerification(
        user_id=user.id,
        token=generate_secure_token(),
        verification_type='email_verify',
        expires_at=exp,
    )
    db.session.add(ev)
    db.session.commit()

    send_verification_email(user, ev.token)

    return jsonify({'message': 'Registration successful. Check your email to verify your account.'}), 201


# ── Email verification (link click) ───────────────────────────────

@auth_bp.route('/verify-email', methods=['GET'])
def verify_email():
    token = request.args.get('token', '')
    ev = EmailVerification.query.filter_by(token=token, verification_type='email_verify', is_used=False).first()
    if not ev or ev.is_expired():
        return redirect('/?error=invalid_or_expired_link')

    ev.is_used = True
    ev.user.is_email_verified = True
    db.session.commit()

    return redirect('/login?verified=1')


# ── Login ─────────────────────────────────────────────────────────

@auth_bp.route('/login', methods=['POST'])
@limiter.limit('10 per minute')
def login():
    data = request.get_json(silent=True) or {}
    username         = (data.get('username') or '').strip().lower()
    password         = data.get('password') or ''
    device_id        = data.get('device_id')
    device_name      = data.get('device_name', 'Browser')
    ecdsa_public_key = data.get('ecdsa_public_key')
    ecdh_public_key  = data.get('ecdh_public_key')

    if not all([username, password, device_id]):
        return jsonify({'error': 'Missing required fields'}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not verify_password(password, user.password_hash):
        return jsonify({'error': 'Invalid username or password'}), 401

    if not user.is_email_verified:
        return jsonify({'error': 'Please verify your email before logging in'}), 403

    # Rehash if needed
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
        db.session.commit()

    # Check if device already authorized
    existing_device = DeviceKey.query.filter_by(user_id=user.id, device_id=device_id, is_active=True).first()

    if existing_device:
        # Known device — issue JWT immediately
        existing_device.last_seen = datetime.utcnow()
        # Update keys if provided (key refresh)
        if ecdsa_public_key:
            existing_device.ecdsa_public_key = ecdsa_public_key
        if ecdh_public_key:
            existing_device.ecdh_public_key = ecdh_public_key
        db.session.commit()

        token = generate_jwt(user.id, device_id)
        return jsonify({'status': 'ok', 'token': token, 'user': user.to_dict()}), 200

    else:
        # New device — require 2FA
        if not ecdsa_public_key or not ecdh_public_key:
            return jsonify({'error': 'Public keys required for new device registration'}), 400

        # Create pending device (inactive until 2FA approved)
        new_device = DeviceKey(
            user_id=user.id,
            device_id=device_id,
            ecdsa_public_key=ecdsa_public_key,
            ecdh_public_key=ecdh_public_key,
            device_name=device_name,
            is_active=False,
        )
        db.session.add(new_device)

        # 2FA token
        exp = datetime.utcnow() + current_app.config['VERIFICATION_TOKEN_EXPIRY']
        ev = EmailVerification(
            user_id=user.id,
            token=generate_secure_token(),
            verification_type='2fa_login',
            device_id=device_id,
            expires_at=exp,
        )
        db.session.add(ev)
        db.session.commit()

        send_2fa_email(user, device_name, ev.token)

        return jsonify({
            'status':    '2fa_required',
            'device_id': device_id,
            'message':   'Check your email to authorize this device.',
        }), 202


# ── 2FA device authorization (email link click) ───────────────────

@auth_bp.route('/2fa-verify', methods=['GET'])
def two_factor_verify():
    token = request.args.get('token', '')
    ev = EmailVerification.query.filter_by(
        token=token, verification_type='2fa_login', is_used=False
    ).first()

    if not ev or ev.is_expired():
        return redirect('/?error=invalid_or_expired_2fa')

    device = DeviceKey.query.filter_by(
        user_id=ev.user_id, device_id=ev.device_id
    ).first()

    if not device:
        return redirect('/?error=device_not_found')

    device.is_active = True
    device.last_seen = datetime.utcnow()
    ev.is_used = True
    db.session.commit()

    # Render a page that tells the user they can close this tab
    return redirect(f'/device-authorized?device={device.device_name}')


# ── 2FA status polling ────────────────────────────────────────────

@auth_bp.route('/2fa-status', methods=['GET'])
def two_factor_status():
    """Original login tab polls this until device is authorized."""
    device_id = request.args.get('device_id', '')
    if not device_id:
        return jsonify({'error': 'device_id required'}), 400

    device = DeviceKey.query.filter_by(device_id=device_id, is_active=True).first()
    if not device:
        return jsonify({'status': 'pending'}), 200

    token = generate_jwt(device.user_id, device_id)
    user  = User.query.get(device.user_id)
    return jsonify({'status': 'authorized', 'token': token, 'user': user.to_dict()}), 200


# ── Me / Settings / Devices ──────────────────────────────────────

@auth_bp.route('/me', methods=['GET'])
@token_required
def me(current_user, current_device):
    return jsonify({'user': current_user.to_dict()}), 200


@auth_bp.route('/settings', methods=['PUT'])
@token_required
def update_settings(current_user, current_device):
    data = request.get_json(silent=True) or {}
    settings = current_user.get_settings()
    if 'store_history' in data:
        settings['store_history'] = bool(data['store_history'])
    if 'session_mode' in data:
        settings['session_mode'] = bool(data['session_mode'])
    current_user.set_settings(settings)
    db.session.commit()
    return jsonify({'settings': settings}), 200


@auth_bp.route('/devices', methods=['GET'])
@token_required
def list_devices(current_user, current_device):
    devices = DeviceKey.query.filter_by(user_id=current_user.id, is_active=True).all()
    return jsonify({'devices': [d.to_dict() for d in devices]}), 200


@auth_bp.route('/devices/<string:dev_id>', methods=['DELETE'])
@token_required
def revoke_device(current_user, current_device, dev_id):
    device = DeviceKey.query.filter_by(
        user_id=current_user.id, device_id=dev_id
    ).first_or_404()
    device.is_active = False
    db.session.commit()
    return jsonify({'message': 'Device revoked'}), 200


@auth_bp.route('/logout', methods=['POST'])
@token_required
def logout(current_user, current_device):
    current_device.is_active = False
    db.session.commit()
    return jsonify({'message': 'Logged out successfully'}), 200
