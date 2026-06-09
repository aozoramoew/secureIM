"""
ORM models — converted from Flask-SQLAlchemy to pure SQLAlchemy 2.x.
The schema is identical to the previous version; only the base class
and import paths changed.
"""
from datetime import datetime
import json

from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text,
    ForeignKey, UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.database import Base


# ─────────────────────────────────────────────
#  User & Identity
# ─────────────────────────────────────────────

class User(Base):
    __tablename__ = 'users'

    id            = Column(Integer, primary_key=True)
    username      = Column(String(80),  unique=True, nullable=False, index=True)
    email         = Column(String(120), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)   # argon2id
    created_at    = Column(DateTime, default=datetime.utcnow)
    # JSON blob: {store_history: bool, session_mode: bool}
    settings          = Column(Text, default='{"store_history":true,"session_mode":false}')

    # Relationships
    devices           = relationship('DeviceKey', backref='user',      lazy='dynamic',
                                     foreign_keys='DeviceKey.user_id')
    sent_msgs         = relationship('Message',   backref='sender',    lazy='dynamic',
                                     foreign_keys='Message.sender_id')
    recv_msgs         = relationship('Message',   backref='recipient', lazy='dynamic',
                                     foreign_keys='Message.recipient_id')
    group_memberships = relationship('GroupMember', backref='user',    lazy='dynamic')

    def get_settings(self):
        return json.loads(self.settings or '{}')

    def set_settings(self, d: dict):
        self.settings = json.dumps(d)

    def to_dict(self):
        return {
            'id':       self.id,
            'username': self.username,
            'email':    self.email,
            'settings': self.get_settings(),
        }


class DeviceKey(Base):
    """One row per (user, device). Each device has its own crypto keys."""
    __tablename__ = 'device_keys'

    id               = Column(Integer, primary_key=True)
    user_id          = Column(Integer, ForeignKey('users.id'), nullable=False)
    device_id        = Column(String(64), unique=True, nullable=False, index=True)
    ecdsa_public_key = Column(Text, nullable=False)   # JWK JSON string (P-384, signing)
    ecdh_public_key  = Column(Text, nullable=False)   # JWK JSON string (P-256, key exchange)
    device_name      = Column(String(120), default='Unknown Device')
    last_seen        = Column(DateTime, default=datetime.utcnow)
    is_active        = Column(Boolean, default=True)
    created_at       = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'device_id':        self.device_id,
            'device_name':      self.device_name,
            'ecdsa_public_key': self.ecdsa_public_key,
            'ecdh_public_key':  self.ecdh_public_key,
            'last_seen':        self.last_seen.isoformat(),
            'is_active':        self.is_active,
        }


# ─────────────────────────────────────────────
#  Messaging
# ─────────────────────────────────────────────

class Message(Base):
    __tablename__ = 'messages'

    id           = Column(Integer, primary_key=True)
    sender_id    = Column(Integer, ForeignKey('users.id'), nullable=False)
    # For 1-on-1 chat
    recipient_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    # For group chat
    group_id     = Column(Integer, ForeignKey('groups.id'), nullable=True)

    # E2EE payload — JSON: {device_id: {ciphertext, nonce, hmac}, ...}
    # Server never stores plaintext.
    encrypted_payloads = Column(Text, nullable=False)

    timestamp       = Column(DateTime, default=datetime.utcnow, index=True)

    # Soft-delete tracking
    deleted_for     = Column(Text, default='[]')         # JSON list of user_ids
    is_deep_deleted = Column(Boolean, default=False)
    deep_deleted_at = Column(DateTime, nullable=True)
    cleanup_at      = Column(DateTime, nullable=True, index=True)
    deep_deleted_by = Column(Integer, ForeignKey('users.id'), nullable=True)

    # Self-destruct timer — null means no expiry
    expires_at      = Column(DateTime, nullable=True, index=True)

    # Read receipts
    delivered_at    = Column(DateTime, nullable=True)
    read_at         = Column(DateTime, nullable=True)

    def get_deleted_for(self):
        return json.loads(self.deleted_for or '[]')

    def add_deleted_for(self, user_id: int):
        lst = self.get_deleted_for()
        if user_id not in lst:
            lst.append(user_id)
        self.deleted_for = json.dumps(lst)

    def to_dict(self, requesting_user_id=None):
        deleted_for_list = self.get_deleted_for()
        return {
            'id':               self.id,
            'sender_id':        self.sender_id,
            'recipient_id':     self.recipient_id,
            'group_id':         self.group_id,
            'encrypted_payloads': json.loads(self.encrypted_payloads),
            'timestamp':        self.timestamp.isoformat(),
            'is_deep_deleted':  self.is_deep_deleted,
            'deleted_for_me':   (requesting_user_id in deleted_for_list) if requesting_user_id else False,
            'expires_at':       self.expires_at.isoformat() if self.expires_at else None,
            'delivered_at':     self.delivered_at.isoformat() if self.delivered_at else None,
            'read_at':          self.read_at.isoformat() if self.read_at else None,
        }


# ─────────────────────────────────────────────
#  Group Chat
# ─────────────────────────────────────────────

class Group(Base):
    __tablename__ = 'groups'

    id         = Column(Integer, primary_key=True)
    name       = Column(String(100), nullable=False)
    created_by = Column(Integer, ForeignKey('users.id'), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    # Increment when group key is rotated (new member joins / member leaves)
    key_version = Column(Integer, default=1)

    members  = relationship('GroupMember', backref='group', lazy='dynamic')
    messages = relationship('Message',     backref='group', lazy='dynamic')

    def to_dict(self):
        return {
            'id':          self.id,
            'name':        self.name,
            'created_by':  self.created_by,
            'created_at':  self.created_at.isoformat(),
            'key_version': self.key_version,
        }


class GroupMember(Base):
    __tablename__ = 'group_members'

    id        = Column(Integer, primary_key=True)
    group_id  = Column(Integer, ForeignKey('groups.id'), nullable=False)
    user_id   = Column(Integer, ForeignKey('users.id'),  nullable=False)
    is_admin  = Column(Boolean, default=False)
    joined_at = Column(DateTime, default=datetime.utcnow)
    # Encrypted copy of group AES key for this member, per device
    # JSON: {device_id: encrypted_group_key_base64, ...}
    encrypted_group_keys = Column(Text, default='{}')

    __table_args__ = (UniqueConstraint('group_id', 'user_id'),)


# ─────────────────────────────────────────────
#  ECDH Session Tracking
# ─────────────────────────────────────────────

class ChatSession(Base):
    """Tracks ECDH key-exchange sessions for forward secrecy & key rotation."""
    __tablename__ = 'chat_sessions'

    id              = Column(Integer, primary_key=True)
    user_a_id       = Column(Integer, ForeignKey('users.id'), nullable=False)
    user_b_id       = Column(Integer, ForeignKey('users.id'), nullable=False)
    ephemeral_pub_a = Column(Text, nullable=True)
    ephemeral_pub_b = Column(Text, nullable=True)
    ephemeral_sig_a = Column(Text, nullable=True)
    ephemeral_sig_b = Column(Text, nullable=True)
    message_count   = Column(Integer, default=0)
    created_at      = Column(DateTime, default=datetime.utcnow)
    is_active       = Column(Boolean, default=True)

    def to_dict(self):
        return {
            'id':              self.id,
            'user_a_id':       self.user_a_id,
            'user_b_id':       self.user_b_id,
            'ephemeral_pub_a': self.ephemeral_pub_a,
            'ephemeral_pub_b': self.ephemeral_pub_b,
            'ephemeral_sig_a': self.ephemeral_sig_a,
            'ephemeral_sig_b': self.ephemeral_sig_b,
            'message_count':   self.message_count,
            'created_at':      self.created_at.isoformat(),
        }


# ─────────────────────────────────────────────
#  Contact Verification (out-of-band key check)
# ─────────────────────────────────────────────

class ContactVerification(Base):
    __tablename__ = 'contact_verifications'

    id              = Column(Integer, primary_key=True)
    user_id         = Column(Integer, ForeignKey('users.id'), nullable=False)
    contact_id      = Column(Integer, ForeignKey('users.id'), nullable=False)
    verified_at     = Column(DateTime, default=datetime.utcnow)
    key_fingerprint = Column(String(128), nullable=False)

    __table_args__ = (UniqueConstraint('user_id', 'contact_id'),)


# ─────────────────────────────────────────────
#  Audit Log — security events only, never message content
# ─────────────────────────────────────────────

class AuditLog(Base):
    """
    Security event log. Records WHAT happened and WHO, never message content.
    """
    __tablename__ = 'audit_logs'

    id         = Column(Integer, primary_key=True)
    timestamp  = Column(DateTime, default=datetime.utcnow, index=True)
    user_id    = Column(Integer, ForeignKey('users.id'), nullable=True)
    event_type = Column(String(40), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(256), nullable=True)
    detail     = Column(Text, default='{}')   # JSON metadata, never plaintext

    def to_dict(self):
        return {
            'id':         self.id,
            'timestamp':  self.timestamp.isoformat(),
            'user_id':    self.user_id,
            'event_type': self.event_type,
            'ip_address': self.ip_address,
            'detail':     json.loads(self.detail or '{}'),
        }
