"""
Background scheduler — runs cleanup jobs independent of web requests.

Job: cleanup_deleted_payloads
  Runs every hour. Finds Messages where:
    - is_deep_deleted = True
    - cleanup_at <= now  (24h grace period has elapsed)
    - encrypted_payloads != '{}'  (payload not yet wiped)
  Sets encrypted_payloads = '{}' to physically remove the ciphertext.
  The tombstone row (is_deep_deleted=True) is kept forever so the UI
  always shows "This message was deleted" correctly.

Why 24h grace?
  Offline recipients need time to receive the deep-delete tombstone event.
  For 24h they can reconnect and see is_deep_deleted=True in history.
  After 24h the ciphertext is wiped. The payload was already cryptographically
  useless (server can't decrypt it), but this eliminates any residual storage.
"""
import logging
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

log = logging.getLogger(__name__)
_scheduler = BackgroundScheduler(timezone='UTC')


def _cleanup_deleted_payloads(app):
    with app.app_context():
        from app import db
        from app.models import Message

        now = datetime.utcnow()
        msgs = Message.query.filter(
            Message.is_deep_deleted == True,       # noqa: E712
            Message.cleanup_at  <= now,
            Message.encrypted_payloads != '{}',
        ).all()

        if msgs:
            for m in msgs:
                m.encrypted_payloads = '{}'
            db.session.commit()
            log.info('[Scheduler] Wiped payloads from %d deep-deleted messages', len(msgs))


def start_scheduler(app):
    """Call once from app factory after db.create_all()."""
    if _scheduler.running:
        return

    _scheduler.add_job(
        func=_cleanup_deleted_payloads,
        trigger=IntervalTrigger(hours=1),
        args=[app],
        id='cleanup_payloads',
        replace_existing=True,
    )
    _scheduler.start()
    log.info('[Scheduler] Started — payload cleanup runs every hour')
