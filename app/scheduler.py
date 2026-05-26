"""
Background scheduler — runs cleanup jobs independent of web requests.

Jobs:
  1. cleanup_expired_messages  — runs every 5 minutes.
     Finds Messages where expires_at <= now (self-destruct timer fired).
     Immediately wipes encrypted_payloads and sets is_deep_deleted=True.
     Emits 'message_deleted' SocketIO event so live clients react instantly.

  2. (Optional) Any future periodic cleanup jobs go here.
"""
import logging
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

log = logging.getLogger(__name__)
_scheduler = BackgroundScheduler(timezone='UTC')


def _cleanup_expired_messages(app):
    """Wipe self-destructed messages whose expires_at has passed."""
    with app.app_context():
        from app import db
        from app.models import Message

        now = datetime.utcnow()
        expired = Message.query.filter(
            Message.expires_at <= now,
            Message.is_deep_deleted == False,   # noqa: E712
        ).all()

        if expired:
            from app import socketio as _io
            from app.chat import _connected_sids  # read-only

            for m in expired:
                m.is_deep_deleted   = True
                m.deep_deleted_at   = now
                m.encrypted_payloads = '{}'
                # Notify live clients
                for sid, info in list(_connected_sids.items()):
                    if info['user_id'] in (m.sender_id, m.recipient_id):
                        _io.emit('message_deleted', {
                            'message_id': m.id,
                            'type': 'expired',
                        }, room=sid)

            db.session.commit()
            log.info('[Scheduler] Self-destructed %d expired messages', len(expired))


def start_scheduler(app):
    """Call once from app factory after db.create_all()."""
    if _scheduler.running:
        return

    _scheduler.add_job(
        func=_cleanup_expired_messages,
        trigger=IntervalTrigger(minutes=5),
        args=[app],
        id='cleanup_expired',
        replace_existing=True,
    )
    _scheduler.start()
    log.info('[Scheduler] Started — self-destruct check runs every 5 minutes')
