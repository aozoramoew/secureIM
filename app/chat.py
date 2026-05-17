"""
Chat blueprint — REST API + SocketIO event handlers.

REST routes (all require Bearer JWT):
  GET  /api/chat/users                     — search/list users
  GET  /api/chat/users/<username>/keys     — get all active device keys for a user
  GET  /api/chat/messages/<user_id>        — load DM history
  DELETE /api/chat/messages/<msg_id>       — delete message (local or deep)
  POST /api/chat/sessions                  — initiate ECDH session
  GET  /api/chat/sessions/<id>             — get session info
  POST /api/chat/groups                    — create group
  GET  /api/chat/groups                    — list user's groups
  GET  /api/chat/groups/<id>/messages      — group message history
  POST /api/chat/contacts/<id>/verify      — mark contact as verified
  GET  /api/chat/contacts/verified         — list verified contacts

SocketIO events (authenticated via JWT in auth header):
  connect / disconnect
  send_message          {session_id, encrypted_payloads, msg_type='dm'|'group'}
  key_exchange_init     {recipient_id, ephemeral_pub}
  key_exchange_response {session_id, ephemeral_pub}
  key_rotation          {session_id, new_ephemeral_pub}
  delete_message        {message_id, delete_type='local'|'deep'}
  typing                {recipient_id or group_id}
"""
import json
from datetime import datetime, timedelta
from functools import wraps

from flask import Blueprint, request, jsonify, current_app
from flask_socketio import emit, join_room, leave_room

from app import db, socketio
from app.models import (
    User, DeviceKey, Message, Group, GroupMember,
    ChatSession, ContactVerification,
)
from app.crypto_utils import decode_jwt

chat_bp = Blueprint('chat', __name__)

# sid → {user_id, device_id}
_connected_sids: dict[str, dict] = {}


# ── JWT helper for REST ────────────────────────────────────────────

def _get_current_user_device():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None, None
    payload = decode_jwt(auth.split(' ', 1)[1])
    if not payload:
        return None, None
    user = User.query.get(int(payload['sub']))
    device = DeviceKey.query.filter_by(
        user_id=user.id if user else 0,
        device_id=payload.get('device_id'),
        is_active=True,
    ).first() if user else None
    return user, device


def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user, device = _get_current_user_device()
        if not user or not device:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(user, device, *args, **kwargs)
    return decorated


# ══════════════════════════════════════════════
#  REST ROUTES
# ══════════════════════════════════════════════

@chat_bp.route('/users', methods=['GET'])
@jwt_required
def list_users(current_user, current_device):
    q = request.args.get('q', '').strip().lower()
    query = User.query.filter(User.id != current_user.id, User.is_email_verified == True)
    if q:
        query = query.filter(User.username.ilike(f'%{q}%'))
    users = query.limit(30).all()

    # Attach verified status
    verified_ids = {
        cv.contact_id
        for cv in ContactVerification.query.filter_by(user_id=current_user.id).all()
    }
    result = []
    for u in users:
        d = u.to_dict()
        d['is_verified_by_me'] = u.id in verified_ids
        d['is_online'] = any(
            info['user_id'] == u.id for info in _connected_sids.values()
        )
        result.append(d)
    return jsonify({'users': result}), 200


@chat_bp.route('/users/<string:username>/keys', methods=['GET'])
@jwt_required
def get_user_keys(current_user, current_device, username):
    """Return all active device public keys for a user (needed for E2EE multi-device)."""
    user = User.query.filter_by(username=username).first_or_404()
    devices = DeviceKey.query.filter_by(user_id=user.id, is_active=True).all()
    return jsonify({
        'user_id':  user.id,
        'username': user.username,
        'devices':  [d.to_dict() for d in devices],
    }), 200


# ── DM History ────────────────────────────────────────────────────

@chat_bp.route('/messages/<int:contact_id>', methods=['GET'])
@jwt_required
def get_dm_history(current_user, current_device, contact_id):
    before_id = request.args.get('before_id', type=int)
    limit = min(int(request.args.get('limit', 50)), 100)

    q = Message.query.filter(
        Message.group_id == None,
        db.or_(
            db.and_(Message.sender_id == current_user.id,    Message.recipient_id == contact_id),
            db.and_(Message.sender_id == contact_id, Message.recipient_id == current_user.id),
        ),
    ).order_by(Message.timestamp.desc())

    if before_id:
        q = q.filter(Message.id < before_id)

    messages = q.limit(limit).all()
    result = []
    for m in reversed(messages):
        if current_user.id in m.get_deleted_for():
            continue  # Hidden for this user (delete-for-me)
        result.append(m.to_dict(requesting_user_id=current_user.id))
    return jsonify({'messages': result}), 200


# ── Message Deletion ──────────────────────────────────────────────

@chat_bp.route('/messages/<int:msg_id>', methods=['DELETE'])
@jwt_required
def delete_message(current_user, current_device, msg_id):
    delete_type = request.args.get('type', 'local')  # 'local' | 'deep'
    msg = Message.query.get_or_404(msg_id)

    # Only sender or recipient can delete
    if current_user.id not in (msg.sender_id, msg.recipient_id):
        if msg.group_id:
            member = GroupMember.query.filter_by(
                group_id=msg.group_id, user_id=current_user.id
            ).first()
            if not member:
                return jsonify({'error': 'Forbidden'}), 403
        else:
            return jsonify({'error': 'Forbidden'}), 403

    if delete_type == 'deep':
        msg.is_deep_deleted = True
        msg.deep_deleted_at = datetime.utcnow()
        msg.deep_deleted_by = current_user.id
        # Immediately wipe the ciphertext — server holds zero plaintext or payload.
        # The tombstone row (is_deep_deleted=True) remains so both clients
        # permanently display "🗑️ This message was deleted."
        msg.encrypted_payloads = '{}'
        db.session.commit()

        # Notify all parties via SocketIO
        _emit_to_user(msg.sender_id,    'message_deleted', {'message_id': msg_id, 'type': 'deep'})
        _emit_to_user(msg.recipient_id, 'message_deleted', {'message_id': msg_id, 'type': 'deep'})
    else:
        # Local delete — only hides for current user
        msg.add_deleted_for(current_user.id)
        db.session.commit()

    return jsonify({'message': 'Deleted', 'type': delete_type}), 200


# ── ECDH Session Management ───────────────────────────────────────

@chat_bp.route('/sessions', methods=['POST'])
@jwt_required
def create_session(current_user, current_device):
    """Alice calls this to start ECDH with Bob. Stores Alice's ephemeral pub key."""
    data = request.get_json(silent=True) or {}
    recipient_id   = data.get('recipient_id')
    ephemeral_pub  = data.get('ephemeral_pub')  # JWK JSON string
    ephemeral_sig  = data.get('ephemeral_sig')  # ECDSA P-384 signature (base64)

    if not recipient_id or not ephemeral_pub or not ephemeral_sig:
        return jsonify({'error': 'recipient_id, ephemeral_pub and ephemeral_sig required'}), 400

    # Deactivate old sessions between these two users
    ChatSession.query.filter(
        db.or_(
            db.and_(ChatSession.user_a_id == current_user.id, ChatSession.user_b_id == recipient_id),
            db.and_(ChatSession.user_a_id == recipient_id,    ChatSession.user_b_id == current_user.id),
        ),
        ChatSession.is_active == True,
    ).update({'is_active': False})

    session = ChatSession(
        user_a_id=current_user.id,
        user_b_id=recipient_id,
        ephemeral_pub_a=ephemeral_pub,
        ephemeral_sig_a=ephemeral_sig,
    )
    db.session.add(session)
    db.session.commit()

    # Notify Bob that Alice wants to start a session
    _emit_to_user(recipient_id, 'session_request', {
        'session_id':       session.id,
        'initiator_id':     current_user.id,
        'initiator':        current_user.username,
        'ephemeral_pub_a':  ephemeral_pub,
        'ephemeral_sig_a':  ephemeral_sig,   # Recipient must verify this signature
    })

    return jsonify({'session': session.to_dict()}), 201


@chat_bp.route('/sessions/<int:session_id>', methods=['GET', 'PUT'])
@jwt_required
def session_detail(current_user, current_device, session_id):
    sess = ChatSession.query.get_or_404(session_id)

    if request.method == 'GET':
        return jsonify({'session': sess.to_dict()}), 200

    # PUT — Bob submits his ephemeral pub key + signature to complete handshake
    data = request.get_json(silent=True) or {}
    sess.ephemeral_pub_b = data.get('ephemeral_pub')
    sess.ephemeral_sig_b = data.get('ephemeral_sig')
    db.session.commit()

    # Notify Alice that the handshake is complete
    _emit_to_user(sess.user_a_id, 'session_ready', {
        'session_id':      sess.id,
        'ephemeral_pub_b': sess.ephemeral_pub_b,
        'ephemeral_sig_b': sess.ephemeral_sig_b,  # Alice must verify this signature
    })

    return jsonify({'session': sess.to_dict()}), 200


# ── Group Chat ───────────────────────────────────────────────────

@chat_bp.route('/groups', methods=['POST'])
@jwt_required
def create_group(current_user, current_device):
    data = request.get_json(silent=True) or {}
    name       = (data.get('name') or '').strip()
    member_ids = data.get('member_ids', [])  # list of user IDs

    if not name:
        return jsonify({'error': 'Group name required'}), 400

    group = Group(name=name, created_by=current_user.id)
    db.session.add(group)
    db.session.flush()

    # Add creator as admin
    all_ids = list(set([current_user.id] + member_ids))
    for uid in all_ids:
        gm = GroupMember(
            group_id=group.id,
            user_id=uid,
            is_admin=(uid == current_user.id),
        )
        db.session.add(gm)
    db.session.commit()

    # Notify all members
    for uid in all_ids:
        _emit_to_user(uid, 'group_created', {
            'group': group.to_dict(),
            'members': all_ids,
        })

    return jsonify({'group': group.to_dict()}), 201


@chat_bp.route('/groups', methods=['GET'])
@jwt_required
def list_groups(current_user, current_device):
    memberships = GroupMember.query.filter_by(user_id=current_user.id).all()
    groups = [Group.query.get(m.group_id).to_dict() for m in memberships if Group.query.get(m.group_id)]
    return jsonify({'groups': groups}), 200


@chat_bp.route('/groups/<int:group_id>/messages', methods=['GET'])
@jwt_required
def get_group_history(current_user, current_device, group_id):
    member = GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if not member:
        return jsonify({'error': 'Not a member of this group'}), 403

    before_id = request.args.get('before_id', type=int)
    limit = min(int(request.args.get('limit', 50)), 100)

    q = Message.query.filter_by(group_id=group_id).order_by(Message.timestamp.desc())
    if before_id:
        q = q.filter(Message.id < before_id)

    messages = q.limit(limit).all()
    result = []
    for m in reversed(messages):
        if current_user.id in m.get_deleted_for():
            continue
        result.append(m.to_dict(requesting_user_id=current_user.id))
    return jsonify({'messages': result}), 200


@chat_bp.route('/groups/<int:group_id>/keys', methods=['PUT'])
@jwt_required
def update_group_keys(current_user, current_device, group_id):
    """Members submit their encrypted copies of the group key."""
    member = GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if not member:
        return jsonify({'error': 'Not a member'}), 403
    data = request.get_json(silent=True) or {}
    # data['encrypted_keys'] = {device_id: encrypted_group_key_base64}
    existing = json.loads(member.encrypted_group_keys or '{}')
    existing.update(data.get('encrypted_keys', {}))
    member.encrypted_group_keys = json.dumps(existing)
    db.session.commit()
    return jsonify({'message': 'Keys updated'}), 200


# ── Contact Verification ─────────────────────────────────────────

@chat_bp.route('/contacts/<int:contact_id>/verify', methods=['POST'])
@jwt_required
def verify_contact(current_user, current_device, contact_id):
    data = request.get_json(silent=True) or {}
    fingerprint = data.get('fingerprint', '')

    cv = ContactVerification.query.filter_by(
        user_id=current_user.id, contact_id=contact_id
    ).first()
    if cv:
        cv.verified_at = datetime.utcnow()
        cv.key_fingerprint = fingerprint
    else:
        cv = ContactVerification(
            user_id=current_user.id,
            contact_id=contact_id,
            key_fingerprint=fingerprint,
        )
        db.session.add(cv)
    db.session.commit()
    return jsonify({'verified': True, 'fingerprint': fingerprint}), 200


@chat_bp.route('/contacts/verified', methods=['GET'])
@jwt_required
def verified_contacts(current_user, current_device):
    cvs = ContactVerification.query.filter_by(user_id=current_user.id).all()
    return jsonify({
        'verified': [
            {'contact_id': cv.contact_id, 'fingerprint': cv.key_fingerprint,
             'verified_at': cv.verified_at.isoformat()}
            for cv in cvs
        ]
    }), 200


# ══════════════════════════════════════════════
#  SOCKET.IO EVENTS
# ══════════════════════════════════════════════

def _get_socket_user(environ_or_auth: str | None):
    """Decode JWT from SocketIO auth data."""
    if not environ_or_auth:
        return None, None
    if environ_or_auth.startswith('Bearer '):
        environ_or_auth = environ_or_auth.split(' ', 1)[1]
    payload = decode_jwt(environ_or_auth)
    if not payload:
        return None, None
    user = User.query.get(int(payload['sub']))
    device_id = payload.get('device_id')
    return user, device_id


def _emit_to_user(user_id: int, event: str, data: dict):
    """Emit an event to all active SocketIO connections of a user."""
    for sid, info in list(_connected_sids.items()):
        if info['user_id'] == user_id:
            socketio.emit(event, data, room=sid)


@socketio.on('connect')
def on_connect(auth):
    token = (auth or {}).get('token', '')
    user, device_id = _get_socket_user(token)
    if not user or not device_id:
        return False  # Reject connection

    _connected_sids[request.sid] = {'user_id': user.id, 'device_id': device_id}
    join_room(f'user_{user.id}')

    # Broadcast online status to all connected users
    socketio.emit('user_online', {'user_id': user.id, 'username': user.username}, broadcast=True)


@socketio.on('disconnect')
def on_disconnect():
    info = _connected_sids.pop(request.sid, None)
    if info:
        user_id = info['user_id']
        # Check if user has other active connections
        still_online = any(v['user_id'] == user_id for v in _connected_sids.values())
        if not still_online:
            user = User.query.get(user_id)
            username = user.username if user else 'unknown'
            socketio.emit('user_offline', {'user_id': user_id, 'username': username}, broadcast=True)
        leave_room(f'user_{user_id}')


@socketio.on('send_message')
def on_send_message(data):
    """
    data = {
      session_id: int,          # for DMs
      group_id: int,            # for groups
      encrypted_payloads: {},   # {device_id: {ciphertext, nonce, hmac}}
      msg_type: 'dm' | 'group'
    }
    The server stores only the encrypted payload and relays it.
    """
    info = _connected_sids.get(request.sid)
    if not info:
        return

    sender = User.query.get(info['user_id'])
    if not sender:
        return

    payloads_json = json.dumps(data.get('encrypted_payloads', {}))
    msg_type = data.get('msg_type', 'dm')

    if msg_type == 'group':
        group_id = data.get('group_id')
        member = GroupMember.query.filter_by(group_id=group_id, user_id=sender.id).first()
        if not member:
            return

        msg = Message(
            sender_id=sender.id,
            group_id=group_id,
            encrypted_payloads=payloads_json,
        )
        db.session.add(msg)

        # Increment session message count for key rotation tracking
        db.session.commit()

        msg_dict = msg.to_dict(requesting_user_id=sender.id)
        msg_dict['sender_username'] = sender.username

        # Deliver to all group members
        for gm in GroupMember.query.filter_by(group_id=group_id).all():
            _emit_to_user(gm.user_id, 'receive_message', msg_dict)

    else:  # DM
        session_id = data.get('session_id')
        sess = ChatSession.query.get(session_id)
        if not sess or not sess.is_active:
            return

        recipient_id = sess.user_b_id if sess.user_a_id == sender.id else sess.user_a_id

        msg = Message(
            sender_id=sender.id,
            recipient_id=recipient_id,
            encrypted_payloads=payloads_json,
        )
        db.session.add(msg)

        # Key rotation tracking
        sess.message_count += 1
        needs_rotation = sess.message_count >= current_app.config.get('KEY_ROTATION_THRESHOLD', 100)
        db.session.commit()

        msg_dict = msg.to_dict(requesting_user_id=sender.id)
        msg_dict['sender_username'] = sender.username

        _emit_to_user(sender.id,      'receive_message', msg_dict)
        _emit_to_user(recipient_id,   'receive_message', msg_dict)

        if needs_rotation:
            emit('key_rotation_required', {'session_id': session_id})
            _emit_to_user(recipient_id, 'key_rotation_required', {'session_id': session_id})


@socketio.on('typing')
def on_typing(data):
    info = _connected_sids.get(request.sid)
    if not info:
        return
    target = data.get('recipient_id') or data.get('group_id')
    if not target:
        return
    _emit_to_user(target, 'typing', {
        'user_id': info['user_id'],
        'is_typing': data.get('is_typing', True),
    })


@socketio.on('delete_message')
def on_delete_message(data):
    info = _connected_sids.get(request.sid)
    if not info:
        return
    msg_id     = data.get('message_id')
    delete_type = data.get('delete_type', 'local')
    user_id    = info['user_id']

    msg = Message.query.get(msg_id)
    if not msg:
        return
    if user_id not in (msg.sender_id, msg.recipient_id):
        return

    if delete_type == 'deep':
        msg.is_deep_deleted = True
        msg.deep_deleted_at = datetime.utcnow()
        msg.deep_deleted_by = user_id
        # Immediately wipe payload — tombstone stays for UI display
        msg.encrypted_payloads = '{}'
        db.session.commit()
        _emit_to_user(msg.sender_id,    'message_deleted', {'message_id': msg_id, 'type': 'deep'})
        _emit_to_user(msg.recipient_id, 'message_deleted', {'message_id': msg_id, 'type': 'deep'})
    else:
        msg.add_deleted_for(user_id)
        db.session.commit()
        emit('message_deleted', {'message_id': msg_id, 'type': 'local'})
