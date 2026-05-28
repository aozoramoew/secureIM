"""
Background scheduler — runs cleanup jobs independent of web requests.
Converted from Flask context to pure SQLAlchemy session.

Jobs:
  1. cleanup_expired_messages — runs every 5 minutes.
     Wipes encrypted_payloads from messages where expires_at <= now.
     Emits 'message_deleted' SocketIO event to live clients.
"""
import logging
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

log = logging.getLogger(__name__)
_scheduler = BackgroundScheduler(timezone='UTC')


def _cleanup_expired_messages():
    """Wipe self-destructed messages whose expires_at has passed."""
    from app.database import SessionLocal
    from app.models import Message
    from app.socket_manager import sio
    # Import the connected-sids dict from chat (populated at runtime)
    try:
        from app.chat import _connected_sids
    except ImportError:
        _connected_sids = {}

    db = SessionLocal()
    try:
        now = datetime.utcnow()
        expired = db.query(Message).filter(
            Message.expires_at <= now,
            Message.is_deep_deleted == False,  # noqa: E712
        ).all()

        if expired:
            import asyncio
            loop = asyncio.new_event_loop()

            for m in expired:
                m.is_deep_deleted    = True
                m.deep_deleted_at    = now
                m.encrypted_payloads = '{}'

                # Notify live clients
                for sid, info in list(_connected_sids.items()):
                    if info.get('user_id') in (m.sender_id, m.recipient_id):
                        loop.run_until_complete(
                            sio.emit('message_deleted', {
                                'message_id': m.id,
                                'type': 'expired',
                            }, room=sid)
                        )
            loop.close()
            db.commit()
            log.info('[Scheduler] Self-destructed %d expired messages', len(expired))
    except Exception as e:
        log.error('[Scheduler] Error in cleanup: %s', e)
        db.rollback()
    finally:
        db.close()


def start_scheduler():
    """Call once from app factory."""
    if _scheduler.running:
        return
    _scheduler.add_job(
        func=_cleanup_expired_messages,
        trigger=IntervalTrigger(minutes=5),
        id='cleanup_expired',
        replace_existing=True,
    )
    _scheduler.start()
    log.info('[Scheduler] Started — self-destruct check runs every 5 minutes')
