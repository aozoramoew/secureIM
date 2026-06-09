"""
Chat API router + SocketIO event handlers — FastAPI / python-socketio conversion.

REST routes (all require Bearer JWT):
  GET  /api/chat/users                    — search/list users
  GET  /api/chat/users/{username}/keys    — device public keys (E2EE multi-device)
  GET  /api/chat/messages/{contact_id}    — DM history
  DELETE /api/chat/messages/{msg_id}      — delete message
  POST   /api/chat/sessions               — initiate ECDH session
  GET|PUT /api/chat/sessions/{id}         — session info / complete handshake
  POST   /api/chat/groups                 — create group
  GET    /api/chat/groups                 — list user's groups
  GET    /api/chat/groups/{id}/messages   — group message history
  PUT    /api/chat/groups/{id}/keys       — update encrypted group keys
  POST   /api/chat/contacts/{id}/verify   — mark contact as verified
  GET    /api/chat/contacts/verified      — list verified contacts
  POST   /api/chat/messages/{id}/read     — mark read / send receipt
  GET    /api/chat/audit                  — user's own security audit log

SocketIO events (auth.token = Bearer JWT):
  connect / disconnect
  send_message    {session_id, encrypted_payloads, msg_type, expires_seconds}
  typing          {recipient_id, is_typing}
  delete_message  {message_id, delete_type}
"""
import json
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import or_, and_
from sqlalchemy.orm import Session

from app.database import get_db, SessionLocal
from app.models import (
    User, DeviceKey, Message, Group, GroupMember,
    ChatSession, ContactVerification, AuditLog,
)
from app.crypto_utils import decode_jwt
from app.socket_manager import sio
from app.auth import get_current_user_and_device
from config import settings

router = APIRouter()

# sid → {user_id, device_id}
_connected_sids: dict[str, dict] = {}


# ── SocketIO helpers ─────────────────────────────────────────────

async def _emit_to_user(user_id: int, event: str, data: dict):
    """Emit a SocketIO event to all active connections of a user."""
    for sid, info in list(_connected_sids.items()):
        if info['user_id'] == user_id:
            await sio.emit(event, data, room=sid)


def _get_socket_user(token: str | None):
    """Decode JWT from SocketIO auth dict. Returns (user, device_id) or (None, None)."""
    if not token:
        return None, None
    if token.startswith('Bearer '):
        token = token.split(' ', 1)[1]
    payload = decode_jwt(token)
    if not payload:
        return None, None
    db = SessionLocal()
    try:
        user = db.get(User, int(payload['sub']))
        device_id = payload.get('device_id')
        return user, device_id
    finally:
        db.close()


# ══════════════════════════════════════════════
#  SOCKET.IO EVENTS
# ══════════════════════════════════════════════

@sio.event
async def connect(sid, environ, auth):
    token = (auth or {}).get('token', '')
    user, device_id = _get_socket_user(token)
    if not user or not device_id:
        return False  # Reject connection

    _connected_sids[sid] = {'user_id': user.id, 'device_id': device_id}
    await sio.enter_room(sid, f'user_{user.id}')
    await sio.emit('user_online', {'user_id': user.id, 'username': user.username})

    db = SessionLocal()
    try:
        # 1. Replay pending session requests (handshake incomplete while offline).
        pending_sessions = db.query(ChatSession).filter(
            ChatSession.user_b_id == user.id,
            ChatSession.is_active == True,  # noqa: E712
            ChatSession.ephemeral_pub_b == None,  # noqa: E711
        ).all()
        for sess in pending_sessions:
            initiator = db.get(User, sess.user_a_id)
            if not initiator:
                continue
            initiator_device = db.query(DeviceKey).filter_by(
                user_id=initiator.id, is_active=True
            ).order_by(DeviceKey.last_seen.desc()).first()
            await sio.emit('session_request', {
                'session_id':         sess.id,
                'initiator_id':       initiator.id,
                'initiator':          initiator.username,
                'initiator_device_id': (
                    initiator_device.device_id if initiator_device else None
                ),
                'ephemeral_pub_a': sess.ephemeral_pub_a,
                'ephemeral_sig_a': sess.ephemeral_sig_a,
            }, room=sid)

        # 2. Push undelivered DM messages sent while this user was offline.
        # These are messages addressed to this user that were stored in DB but
        # not yet received over a socket (offline_delivery=true in payload means
        # they were encrypted with the static ECDH key — no session needed).
        # Only replay messages that were never delivered (recipient was offline when sent).
        # delivered_at=None means the recipient had not yet received the message.
        missed = db.query(Message).filter(
            Message.recipient_id == user.id,
            Message.is_deep_deleted == False,  # noqa: E712
            Message.group_id == None,          # noqa: E711  DM only
            Message.delivered_at == None,      # noqa: E711  not yet delivered
        ).order_by(Message.timestamp.asc()).limit(200).all()

        for msg in missed:
            payloads = json.loads(msg.encrypted_payloads or '{}')
            if device_id not in payloads:
                continue  # no copy encrypted for this device
            sender = db.get(User, msg.sender_id)
            msg_dict = msg.to_dict(requesting_user_id=user.id)
            msg_dict['sender_username'] = sender.username if sender else ''
            msg_dict['session_id'] = None  # client uses offline_delivery flag in payload
            await sio.emit('receive_message', msg_dict, room=sid)
            # Mark delivered now that we've pushed it to the socket
            msg.delivered_at = datetime.utcnow()

        db.commit()
    finally:
        db.close()


@sio.event
async def request_group_key(sid, data):
    """
    A member with a new device requests that other online members re-wrap
    the group key for their device_id. Server relays the request to other
    online members who have a bundle for this group and can re-wrap it.
    data = { group_id: int, device_id: str, ecdh_public_key: JWK str }
    """
    info = _connected_sids.get(sid)
    if not info:
        return
    group_id = data.get('group_id')
    requester_device_id = data.get('device_id')
    ecdh_pub = data.get('ecdh_public_key')
    if not group_id or not requester_device_id or not ecdh_pub:
        return

    db = SessionLocal()
    try:
        requester_user_id = info['user_id']
        member = db.query(GroupMember).filter_by(
            group_id=group_id, user_id=requester_user_id
        ).first()
        if not member:
            return

        # Broadcast to all OTHER online members of this group so one of them
        # can re-wrap and upload the key for the requester's device.
        all_members = db.query(GroupMember).filter_by(group_id=group_id).all()
        for gm in all_members:
            if gm.user_id == requester_user_id:
                continue
            if not gm.encrypted_group_keys:
                continue
            # Only relay to members who have at least one key bundle stored
            await _emit_to_user(gm.user_id, 'group_key_requested', {
                'group_id':       group_id,
                'requester_uid':  requester_user_id,
                'device_id':      requester_device_id,
                'ecdh_public_key': ecdh_pub,
            })
    finally:
        db.close()


@sio.event
async def disconnect(sid):
    info = _connected_sids.pop(sid, None)
    if info:
        user_id = info['user_id']
        still_online = any(v['user_id'] == user_id for v in _connected_sids.values())
        if not still_online:
            db = SessionLocal()
            try:
                user = db.get(User, user_id)
                username = user.username if user else 'unknown'
            finally:
                db.close()
            await sio.emit('user_offline', {'user_id': user_id, 'username': username})
        await sio.leave_room(sid, f'user_{user_id}')


@sio.event
async def send_message(sid, data):
    """
    data = {
      session_id: int,           # DM — ECDH session ID
      group_id: int,             # Group
      encrypted_payloads: {},    # {device_id: {ciphertext, nonce, hmac}}
      msg_type: 'dm' | 'group'
      expires_seconds: int|None  # Self-destruct timer
    }
    Server stores only ciphertext — never reads message content.
    """
    info = _connected_sids.get(sid)
    if not info:
        return

    db = SessionLocal()
    try:
        sender = db.get(User, info['user_id'])
        if not sender:
            return

        payloads_json = json.dumps(data.get('encrypted_payloads', {}))
        msg_type = data.get('msg_type', 'dm')

        if msg_type == 'group':
            group_id = data.get('group_id')
            member = db.query(GroupMember).filter_by(
                group_id=group_id, user_id=sender.id
            ).first()
            if not member:
                return

            msg = Message(
                sender_id=sender.id,
                group_id=group_id,
                encrypted_payloads=payloads_json,
            )
            db.add(msg)
            db.commit()

            msg_dict = msg.to_dict(requesting_user_id=sender.id)
            msg_dict['sender_username'] = sender.username
            msg_dict['session_id'] = f"grp_{group_id}"

            for gm in db.query(GroupMember).filter_by(group_id=group_id).all():
                await _emit_to_user(gm.user_id, 'receive_message', msg_dict)

        else:  # DM
            session_id = data.get('session_id')
            recipient_id = data.get('recipient_id')
            sess = db.get(ChatSession, session_id) if session_id else None

            # Resolve recipient: prefer session (authoritative), fall back to explicit id.
            if sess and sess.is_active:
                recipient_id = (
                    sess.user_b_id if sess.user_a_id == sender.id else sess.user_a_id
                )
            elif recipient_id:
                recipient_id = int(recipient_id)
            else:
                return  # no session and no recipient_id — reject

            expires_seconds = data.get('expires_seconds')
            expires_at = None
            if expires_seconds:
                expires_at = datetime.utcnow() + timedelta(seconds=int(expires_seconds))

            # Only mark delivered immediately if recipient is currently online.
            # If offline, leave delivered_at=None so the connect handler can
            # replay only undelivered messages (avoids duplicate delivery).
            recipient_is_online = any(
                v['user_id'] == recipient_id for v in _connected_sids.values()
            )
            msg = Message(
                sender_id=sender.id,
                recipient_id=recipient_id,
                encrypted_payloads=payloads_json,
                delivered_at=datetime.utcnow() if recipient_is_online else None,
                expires_at=expires_at,
            )
            db.add(msg)

            needs_rotation = False
            if sess and sess.is_active:
                sess.message_count += 1
                needs_rotation = sess.message_count >= settings.KEY_ROTATION_THRESHOLD

            db.commit()

            msg_dict = msg.to_dict(requesting_user_id=sender.id)
            msg_dict['sender_username'] = sender.username
            msg_dict['session_id'] = session_id

            await _emit_to_user(sender.id,    'receive_message', msg_dict)
            await _emit_to_user(recipient_id, 'receive_message', msg_dict)

            if needs_rotation:
                await sio.emit('key_rotation_required', {'session_id': session_id}, room=sid)
                await _emit_to_user(recipient_id, 'key_rotation_required',
                                    {'session_id': session_id})
    finally:
        db.close()


@sio.event
async def typing(sid, data):
    info = _connected_sids.get(sid)
    if not info:
        return
    target = data.get('recipient_id') or data.get('group_id')
    if not target:
        return
    await _emit_to_user(target, 'typing', {
        'user_id':  info['user_id'],
        'is_typing': data.get('is_typing', True),
    })


@sio.event
async def delete_message(sid, data):
    info = _connected_sids.get(sid)
    if not info:
        return

    db = SessionLocal()
    try:
        msg_id      = data.get('message_id')
        delete_type = data.get('delete_type', 'local')
        user_id     = info['user_id']

        msg = db.get(Message, msg_id)
        if not msg:
            return
        if user_id not in (msg.sender_id, msg.recipient_id):
            return

        if delete_type == 'deep':
            msg.is_deep_deleted    = True
            msg.deep_deleted_at    = datetime.utcnow()
            msg.deep_deleted_by    = user_id
            msg.encrypted_payloads = '{}'
            db.commit()
            await _emit_to_user(msg.sender_id,    'message_deleted',
                                 {'message_id': msg_id, 'type': 'deep'})
            await _emit_to_user(msg.recipient_id, 'message_deleted',
                                 {'message_id': msg_id, 'type': 'deep'})
        else:
            msg.add_deleted_for(user_id)
            db.commit()
            await sio.emit('message_deleted', {'message_id': msg_id, 'type': 'local'}, room=sid)
    finally:
        db.close()


# ══════════════════════════════════════════════
#  REST ROUTES
# ══════════════════════════════════════════════

@router.get('/users')
def list_users(
    q: str = '',
    auth=Depends(get_current_user_and_device),
    db: Session = Depends(get_db),
):
    current_user, _ = auth
    query = db.query(User).filter(
        User.id != current_user.id,
    )
    if q:
        query = query.filter(User.username.ilike(f'%{q}%'))
    users = query.limit(30).all()

    verified_ids = {
        cv.contact_id
        for cv in db.query(ContactVerification).filter_by(user_id=current_user.id).all()
    }
    result = []
    for u in users:
        d = u.to_dict()
        d['is_verified_by_me'] = u.id in verified_ids
        d['is_online'] = any(info['user_id'] == u.id for info in _connected_sids.values())
        result.append(d)
    return {'users': result}


@router.get('/users/by-id/{user_id}/keys')
def get_user_keys_by_id(
    user_id: int,
    auth=Depends(get_current_user_and_device),
    db: Session = Depends(get_db),
):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    devices = db.query(DeviceKey).filter_by(user_id=user.id, is_active=True).all()
    return {'user_id': user.id, 'username': user.username, 'devices': [d.to_dict() for d in devices]}


@router.get('/users/{username}/keys')
def get_user_keys(
    username: str,
    auth=Depends(get_current_user_and_device),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter_by(username=username).first()
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    devices = db.query(DeviceKey).filter_by(user_id=user.id, is_active=True).all()
    return {'user_id': user.id, 'username': user.username, 'devices': [d.to_dict() for d in devices]}


@router.get('/messages/{contact_id}')
def get_dm_history(
    contact_id: int,
    before_id: Optional[int] = None,
    limit: int = 50,
    auth=Depends(get_current_user_and_device),
    db: Session = Depends(get_db),
):
    current_user, _ = auth
    limit = min(limit, 100)
    q = db.query(Message).filter(
        Message.group_id == None,  # noqa: E711
        or_(
            and_(Message.sender_id == current_user.id, Message.recipient_id == contact_id),
            and_(Message.sender_id == contact_id,      Message.recipient_id == current_user.id),
        ),
    ).order_by(Message.timestamp.desc())
    if before_id:
        q = q.filter(Message.id < before_id)

    messages = q.limit(limit).all()
    result = []
    for m in reversed(messages):
        if current_user.id in m.get_deleted_for():
            continue
        result.append(m.to_dict(requesting_user_id=current_user.id))
    return {'messages': result}


@router.delete('/messages/{msg_id}')
def delete_message_rest(
    msg_id: int,
    type: str = 'local',
    auth=Depends(get_current_user_and_device),
    db: Session = Depends(get_db),
):
    current_user, _ = auth
    msg = db.get(Message, msg_id)
    if not msg:
        raise HTTPException(status_code=404, detail='Message not found')
    if current_user.id not in (msg.sender_id, msg.recipient_id):
        raise HTTPException(status_code=403, detail='Forbidden')

    import asyncio
    if type == 'deep':
        msg.is_deep_deleted    = True
        msg.deep_deleted_at    = datetime.utcnow()
        msg.deep_deleted_by    = current_user.id
        msg.encrypted_payloads = '{}'
        db.commit()
        asyncio.run(_emit_to_user(msg.sender_id,    'message_deleted', {'message_id': msg_id, 'type': 'deep'}))
        asyncio.run(_emit_to_user(msg.recipient_id, 'message_deleted', {'message_id': msg_id, 'type': 'deep'}))
    else:
        msg.add_deleted_for(current_user.id)
        db.commit()
    return {'message': 'Deleted', 'type': type}


# ── ECDH Sessions ────────────────────────────────────────────────

class CreateSessionBody(BaseModel):
    recipient_id:  int
    ephemeral_pub: str
    ephemeral_sig: str


class UpdateSessionBody(BaseModel):
    ephemeral_pub: str
    ephemeral_sig: str


@router.post('/sessions', status_code=201)
async def create_session(
    body: CreateSessionBody,
    auth=Depends(get_current_user_and_device),
    db: Session = Depends(get_db),
):
    current_user, _ = auth

    # Deactivate old sessions between these two users
    db.query(ChatSession).filter(
        or_(
            and_(ChatSession.user_a_id == current_user.id, ChatSession.user_b_id == body.recipient_id),
            and_(ChatSession.user_a_id == body.recipient_id, ChatSession.user_b_id == current_user.id),
        ),
        ChatSession.is_active == True,  # noqa: E712
    ).update({'is_active': False})

    session = ChatSession(
        user_a_id=current_user.id,
        user_b_id=body.recipient_id,
        ephemeral_pub_a=body.ephemeral_pub,
        ephemeral_sig_a=body.ephemeral_sig,
    )
    db.add(session)
    db.commit()

    initiator_device = db.query(DeviceKey).filter_by(
        user_id=current_user.id, is_active=True
    ).order_by(DeviceKey.last_seen.desc()).first()
    await _emit_to_user(body.recipient_id, 'session_request', {
        'session_id':      session.id,
        'initiator_id':    current_user.id,
        'initiator':       current_user.username,
        'initiator_device_id': initiator_device.device_id if initiator_device else None,
        'ephemeral_pub_a': body.ephemeral_pub,
        'ephemeral_sig_a': body.ephemeral_sig,
    })
    return {'session': session.to_dict()}


@router.get('/sessions/{session_id}')
def get_session(
    session_id: int,
    auth=Depends(get_current_user_and_device),
    db: Session = Depends(get_db),
):
    sess = db.get(ChatSession, session_id)
    if not sess:
        raise HTTPException(status_code=404, detail='Session not found')
    return {'session': sess.to_dict()}


@router.put('/sessions/{session_id}')
async def update_session(
    session_id: int,
    body: UpdateSessionBody,
    auth=Depends(get_current_user_and_device),
    db: Session = Depends(get_db),
):
    sess = db.get(ChatSession, session_id)
    if not sess:
        raise HTTPException(status_code=404, detail='Session not found')

    current_user, _ = auth
    sess.ephemeral_pub_b = body.ephemeral_pub
    sess.ephemeral_sig_b = body.ephemeral_sig
    db.commit()

    responder_device = db.query(DeviceKey).filter_by(
        user_id=current_user.id, is_active=True
    ).order_by(DeviceKey.last_seen.desc()).first()
    await _emit_to_user(sess.user_a_id, 'session_ready', {
        'session_id':         sess.id,
        'ephemeral_pub_b':    sess.ephemeral_pub_b,
        'ephemeral_sig_b':    sess.ephemeral_sig_b,
        'responder_device_id': responder_device.device_id if responder_device else None,
        'responder_id':       current_user.id,
        'responder_username': current_user.username,
    })
    return {'session': sess.to_dict()}


# ── Groups ───────────────────────────────────────────────────────

class CreateGroupBody(BaseModel):
    name:       str
    member_ids: list[int] = []


@router.post('/groups', status_code=201)
async def create_group(
    body: CreateGroupBody,
    auth=Depends(get_current_user_and_device),
    db: Session = Depends(get_db),
):
    current_user, _ = auth
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail='Group name required')

    group = Group(name=name, created_by=current_user.id)
    db.add(group)
    db.flush()

    all_ids = list(set([current_user.id] + body.member_ids))
    for uid in all_ids:
        db.add(GroupMember(
            group_id=group.id, user_id=uid,
            is_admin=(uid == current_user.id),
        ))
    db.commit()

    for uid in all_ids:
        await _emit_to_user(uid, 'group_created', {'group': group.to_dict(), 'members': all_ids})
    return {'group': group.to_dict()}


@router.delete('/groups/{group_id}')
async def delete_group(
    group_id: int,
    auth=Depends(get_current_user_and_device),
    db: Session = Depends(get_db),
):
    current_user, _ = auth
    member = db.query(GroupMember).filter_by(
        group_id=group_id, user_id=current_user.id
    ).first()
    if not member:
        raise HTTPException(status_code=403, detail='You are not a member of this group')

    group = db.get(Group, group_id)
    if not group:
        raise HTTPException(status_code=404, detail='Group not found')

    # Notify all members before deletion
    all_members = db.query(GroupMember).filter_by(group_id=group_id).all()
    member_ids = [m.user_id for m in all_members]

    # Delete messages, members, then group
    db.query(Message).filter_by(group_id=group_id).delete()
    db.query(GroupMember).filter_by(group_id=group_id).delete()
    db.delete(group)
    db.commit()

    for uid in member_ids:
        await _emit_to_user(uid, 'group_deleted', {'group_id': group_id})
    return {'message': 'Group deleted'}


@router.get('/groups')
def list_groups(
    auth=Depends(get_current_user_and_device),
    db: Session = Depends(get_db),
):
    current_user, _ = auth
    memberships = db.query(GroupMember).filter_by(user_id=current_user.id).all()
    groups = []
    for m in memberships:
        g = db.get(Group, m.group_id)
        if g:
            groups.append(g.to_dict())
    return {'groups': groups}


@router.get('/groups/{group_id}/messages')
def get_group_history(
    group_id: int,
    before_id: Optional[int] = None,
    limit: int = 50,
    auth=Depends(get_current_user_and_device),
    db: Session = Depends(get_db),
):
    current_user, _ = auth
    member = db.query(GroupMember).filter_by(group_id=group_id, user_id=current_user.id).first()
    if not member:
        raise HTTPException(status_code=403, detail='Not a member')

    limit = min(limit, 100)
    q = db.query(Message).filter_by(group_id=group_id).order_by(Message.timestamp.desc())
    if before_id:
        q = q.filter(Message.id < before_id)

    messages = q.limit(limit).all()
    result = [m.to_dict(requesting_user_id=current_user.id) for m in reversed(messages)
              if current_user.id not in m.get_deleted_for()]
    return {'messages': result}


@router.get('/groups/{group_id}/my-key')
def get_my_group_key(
    group_id: int,
    auth=Depends(get_current_user_and_device),
    db: Session = Depends(get_db),
):
    """Return the encrypted group key bundle for the caller's current device."""
    current_user, current_device = auth
    member = db.query(GroupMember).filter_by(group_id=group_id, user_id=current_user.id).first()
    if not member:
        raise HTTPException(status_code=403, detail='Not a member')
    keys = json.loads(member.encrypted_group_keys or '{}')
    bundle = keys.get(current_device.device_id)
    return {'bundle': bundle}


class UpdateGroupKeysBody(BaseModel):
    encrypted_keys: dict = {}


@router.put('/groups/{group_id}/keys')
def update_group_keys(
    group_id: int,
    body: UpdateGroupKeysBody,
    auth=Depends(get_current_user_and_device),
    db: Session = Depends(get_db),
):
    """
    Distribute encrypted group key bundles to each member's record.
    body.encrypted_keys = {device_id: bundle, ...}
    We look up which user owns each device_id and write the bundle into
    that user's GroupMember.encrypted_group_keys — so every member can
    retrieve their own bundle with GET /groups/{id}/my-key.
    """
    current_user, _ = auth
    # Caller must be a member
    if not db.query(GroupMember).filter_by(group_id=group_id, user_id=current_user.id).first():
        raise HTTPException(status_code=403, detail='Not a member')

    import logging
    logger = logging.getLogger(__name__)
    logger.info('[update_group_keys] group=%d received device_ids=%s', group_id, list(body.encrypted_keys.keys()))

    for device_id, bundle in body.encrypted_keys.items():
        device = db.query(DeviceKey).filter_by(device_id=device_id, is_active=True).first()
        if not device:
            logger.warning('[update_group_keys] device_id %s not found or inactive', device_id)
            continue
        member = db.query(GroupMember).filter_by(
            group_id=group_id, user_id=device.user_id
        ).first()
        if not member:
            logger.warning('[update_group_keys] no GroupMember for group=%d user=%d', group_id, device.user_id)
            continue
        existing = json.loads(member.encrypted_group_keys or '{}')
        existing[device_id] = bundle
        member.encrypted_group_keys = json.dumps(existing)
        logger.info('[update_group_keys] stored bundle for user=%d device=%s', device.user_id, device_id)

    db.commit()
    return {'message': 'Keys updated'}


# ── Contacts ─────────────────────────────────────────────────────

class VerifyContactBody(BaseModel):
    fingerprint: str


@router.post('/contacts/{contact_id}/verify')
def verify_contact(
    contact_id: int,
    body: VerifyContactBody,
    auth=Depends(get_current_user_and_device),
    db: Session = Depends(get_db),
):
    current_user, _ = auth
    cv = db.query(ContactVerification).filter_by(
        user_id=current_user.id, contact_id=contact_id
    ).first()
    if cv:
        cv.verified_at     = datetime.utcnow()
        cv.key_fingerprint = body.fingerprint
    else:
        cv = ContactVerification(
            user_id=current_user.id,
            contact_id=contact_id,
            key_fingerprint=body.fingerprint,
        )
        db.add(cv)
    db.commit()
    return {'verified': True, 'fingerprint': body.fingerprint}


@router.get('/contacts/verified')
def verified_contacts(
    auth=Depends(get_current_user_and_device),
    db: Session = Depends(get_db),
):
    current_user, _ = auth
    cvs = db.query(ContactVerification).filter_by(user_id=current_user.id).all()
    return {'verified': [
        {'contact_id': cv.contact_id, 'fingerprint': cv.key_fingerprint,
         'verified_at': cv.verified_at.isoformat()}
        for cv in cvs
    ]}


# ── Read Receipts ────────────────────────────────────────────────

@router.post('/messages/{msg_id}/read')
async def mark_message_read(
    msg_id: int,
    auth=Depends(get_current_user_and_device),
    db: Session = Depends(get_db),
):
    current_user, _ = auth
    msg = db.get(Message, msg_id)
    if not msg:
        raise HTTPException(status_code=404, detail='Message not found')
    if msg.recipient_id != current_user.id:
        raise HTTPException(status_code=403, detail='Forbidden')
    if not msg.read_at:
        msg.read_at = datetime.utcnow()
        db.commit()
        await _emit_to_user(msg.sender_id, 'message_read', {
            'message_id': msg_id,
            'read_at': msg.read_at.isoformat(),
        })
    return {'read_at': msg.read_at.isoformat()}


# ── Audit Log ────────────────────────────────────────────────────

@router.get('/audit')
def get_audit_log(
    auth=Depends(get_current_user_and_device),
    db: Session = Depends(get_db),
):
    current_user, _ = auth
    logs = db.query(AuditLog).filter_by(user_id=current_user.id)\
        .order_by(AuditLog.timestamp.desc()).limit(100).all()
    return {'audit': [l.to_dict() for l in logs]}
