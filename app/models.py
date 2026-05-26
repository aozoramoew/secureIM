from datetime import datetime
import json
from app import db


# ─────────────────────────────────────────────
#  User & Identity
# ─────────────────────────────────────────────

class User(db.Model):
    __tablename__ = 'users'

    id                 = db.Column(db.Integer, primary_key=True)
    username           = db.Column(db.String(80),  unique=True, nullable=False, index=True)
    email              = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash      = db.Column(db.String(256), nullable=False)   # argon2id
    is_email_verified  = db.Column(db.Boolean, default=False)
    created_at         = db.Column(db.DateTime, default=datetime.utcnow)
    # JSON blob: {store_history: bool, session_mode: bool}
    settings           = db.Column(db.Text, default='{"store_history":true,"session_mode":false}')

    # Relationships
    devices      = db.relationship('DeviceKey',   backref='user', lazy='dynamic', foreign_keys='DeviceKey.user_id')
    sent_msgs    = db.relationship('Message',     backref='sender',  lazy='dynamic', foreign_keys='Message.sender_id')
    recv_msgs    = db.relationship('Message',     backref='recipient', lazy='dynamic', foreign_keys='Message.recipient_id')
    group_memberships = db.relationship('GroupMember', backref='user', lazy='dynamic')

    def get_settings(self):
        return json.loads(self.settings or '{}')

    def set_settings(self, d):
        self.settings = json.dumps(d)

    def to_dict(self):
        return {
            'id':       self.id,
            'username': self.username,
            'email':    self.email,
            'verified': self.is_email_verified,
            'settings': self.get_settings(),
        }


class DeviceKey(db.Model):
    """One row per (user, device). Each device has its own crypto keys."""
    __tablename__ = 'device_keys'

    id               = db.Column(db.Integer, primary_key=True)
    user_id          = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    device_id        = db.Column(db.String(64), unique=True, nullable=False, index=True)
    ecdsa_public_key = db.Column(db.Text, nullable=False)   # JWK JSON string (P-384, for identity/signing)
    ecdh_public_key  = db.Column(db.Text, nullable=False)   # JWK JSON string (P-256, for key exchange)
    device_name      = db.Column(db.String(120), default='Unknown Device')
    last_seen        = db.Column(db.DateTime, default=datetime.utcnow)
    is_active        = db.Column(db.Boolean, default=True)
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)

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
#  Email Verification & 2FA
# ─────────────────────────────────────────────

class EmailVerification(db.Model):
    __tablename__ = 'email_verifications'

    id                = db.Column(db.Integer, primary_key=True)
    user_id           = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token             = db.Column(db.String(128), unique=True, nullable=False, index=True)
    # 'email_verify' | '2fa_login'
    verification_type = db.Column(db.String(20), nullable=False)
    # For 2FA: which device is pending authorization
    device_id         = db.Column(db.String(64), nullable=True)
    expires_at        = db.Column(db.DateTime, nullable=False)
    is_used           = db.Column(db.Boolean, default=False)
    created_at        = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='verifications')

    def is_expired(self):
        return datetime.utcnow() > self.expires_at


# ─────────────────────────────────────────────
#  Messaging
# ─────────────────────────────────────────────

class Message(db.Model):
    __tablename__ = 'messages'

    id           = db.Column(db.Integer, primary_key=True)
    sender_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    # For 1-on-1 chat
    recipient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    # For group chat
    group_id     = db.Column(db.Integer, db.ForeignKey('groups.id'), nullable=True)

    # E2EE payload — JSON: {device_id: {ciphertext, nonce, hmac}, ...}
    # Server never stores plaintext.
    encrypted_payloads = db.Column(db.Text, nullable=False)

    timestamp       = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # Soft-delete tracking
    # JSON list of user_ids who did "delete for me"
    deleted_for     = db.Column(db.Text, default='[]')
    # Deep-delete: both sides see "This message was deleted"
    is_deep_deleted = db.Column(db.Boolean, default=False)
    deep_deleted_at = db.Column(db.DateTime, nullable=True)
    # After this time the background scheduler wipes encrypted_payloads → '{}'
    cleanup_at      = db.Column(db.DateTime, nullable=True, index=True)
    deep_deleted_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    # Self-destruct timer (A1) — null means no expiry
    expires_at      = db.Column(db.DateTime, nullable=True, index=True)

    # Read receipts (A2)
    delivered_at    = db.Column(db.DateTime, nullable=True)   # server received + relayed
    read_at         = db.Column(db.DateTime, nullable=True)   # recipient opened conversation

    def get_deleted_for(self):
        return json.loads(self.deleted_for or '[]')

    def add_deleted_for(self, user_id):
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

class Group(db.Model):
    __tablename__ = 'groups'

    id            = db.Column(db.Integer, primary_key=True)
    name          = db.Column(db.String(100), nullable=False)
    created_by    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    # Increment when group key is rotated (new member joins / member leaves)
    key_version   = db.Column(db.Integer, default=1)

    members  = db.relationship('GroupMember', backref='group', lazy='dynamic')
    messages = db.relationship('Message', backref='group', lazy='dynamic')

    def to_dict(self):
        return {
            'id':         self.id,
            'name':       self.name,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat(),
            'key_version': self.key_version,
        }


class GroupMember(db.Model):
    __tablename__ = 'group_members'

    id          = db.Column(db.Integer, primary_key=True)
    group_id    = db.Column(db.Integer, db.ForeignKey('groups.id'), nullable=False)
    user_id     = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    is_admin    = db.Column(db.Boolean, default=False)
    joined_at   = db.Column(db.DateTime, default=datetime.utcnow)
    # Encrypted copy of the group AES key for this member (encrypted in JS with their ECDH key)
    # JSON: {device_id: encrypted_group_key_base64, ...}
    encrypted_group_keys = db.Column(db.Text, default='{}')

    __table_args__ = (db.UniqueConstraint('group_id', 'user_id'),)


# ─────────────────────────────────────────────
#  Session Tracking (ECDH handshake records)
# ─────────────────────────────────────────────

class ChatSession(db.Model):
    """Tracks ECDH key-exchange sessions for forward secrecy & key rotation."""
    __tablename__ = 'chat_sessions'

    id             = db.Column(db.Integer, primary_key=True)
    user_a_id      = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user_b_id      = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    # Ephemeral ECDH public keys (JWK) submitted by each side
    ephemeral_pub_a = db.Column(db.Text, nullable=True)
    ephemeral_pub_b = db.Column(db.Text, nullable=True)
    # ECDSA signatures over the ephemeral pub keys — used to detect MitM
    # Signed with each party's long-term identity private key (ECDSA P-384)
    ephemeral_sig_a = db.Column(db.Text, nullable=True)
    ephemeral_sig_b = db.Column(db.Text, nullable=True)
    # How many messages have been sent in this key epoch
    message_count  = db.Column(db.Integer, default=0)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    is_active      = db.Column(db.Boolean, default=True)

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

class ContactVerification(db.Model):
    __tablename__ = 'contact_verifications'

    id              = db.Column(db.Integer, primary_key=True)
    user_id         = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    contact_id      = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    verified_at     = db.Column(db.DateTime, default=datetime.utcnow)
    # SHA-256 fingerprint of the contact's ECDSA public key at verification time
    key_fingerprint = db.Column(db.String(128), nullable=False)

    __table_args__ = (db.UniqueConstraint('user_id', 'contact_id'),)


# ─────────────────────────────────────────────
#  Audit Log (A5) — security events only, never message content
# ─────────────────────────────────────────────

class AuditLog(db.Model):
    """
    Security event log. Records WHAT happened and WHO, never message content.
    Event types: login_ok, login_fail, register, email_verified,
                 device_add, device_revoke, key_rotation,
                 deep_delete, contact_verify
    """
    __tablename__ = 'audit_logs'

    id         = db.Column(db.Integer, primary_key=True)
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    event_type = db.Column(db.String(40), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=True)    # IPv4 or IPv6
    user_agent = db.Column(db.String(256), nullable=True)
    detail     = db.Column(db.Text, default='{}')           # JSON metadata, never plaintext

    def to_dict(self):
        return {
            'id':         self.id,
            'timestamp':  self.timestamp.isoformat(),
            'user_id':    self.user_id,
            'event_type': self.event_type,
            'ip_address': self.ip_address,
            'detail':     json.loads(self.detail or '{}'),
        }
