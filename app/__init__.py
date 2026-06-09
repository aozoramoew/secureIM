"""
FastAPI application factory.
Replaces Flask create_app() — returns a python-socketio ASGIApp
that wraps the FastAPI app (handles both HTTP and WebSocket traffic).
"""
import os
import socketio as _sio_lib

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.socket_manager import sio

_static_dir    = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'static')
_templates_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'templates')


def _migrate_schema(engine):
    """Add any columns that may be missing from tables created before schema updates."""
    import logging
    import sqlalchemy as _sa
    log = logging.getLogger(__name__)
    is_pg = 'postgresql' in str(engine.url)
    ts_type = 'TIMESTAMP' if is_pg else 'DATETIME'
    try:
        insp = _sa.inspect(engine)
        with engine.connect() as conn:
            # groups.key_version — added after initial deploy
            if 'groups' in insp.get_table_names():
                cols = {c['name'] for c in insp.get_columns('groups')}
                if 'key_version' not in cols:
                    conn.execute(_sa.text('ALTER TABLE groups ADD COLUMN key_version INTEGER DEFAULT 1'))
                    conn.commit()
                    log.info('[migrate] Added groups.key_version')
            # messages.cleanup_at — added for self-destruct cleanup tracking
            if 'messages' in insp.get_table_names():
                cols = {c['name'] for c in insp.get_columns('messages')}
                if 'cleanup_at' not in cols:
                    conn.execute(_sa.text(f'ALTER TABLE messages ADD COLUMN cleanup_at {ts_type}'))
                    conn.commit()
                    log.info('[migrate] Added messages.cleanup_at')
    except Exception as e:
        log.error('[migrate] Schema migration error (non-fatal): %s', e)


def create_app():
    # ── Create tables ──────────────────────────────────────────────
    from app.database import engine, Base
    import app.models  # registers all ORM classes  # noqa: F401
    Base.metadata.create_all(bind=engine)
    _migrate_schema(engine)

    # ── FastAPI app ────────────────────────────────────────────────
    app = FastAPI(
        title='SecureIM',
        description='Zero-trust E2EE messaging system',
        version='2.0.0',
        docs_url=None,    # disable Swagger in all envs (security)
        redoc_url=None,
    )

    # CORS — restrict in production via env vars
    app.add_middleware(
        CORSMiddleware,
        allow_origins=['*'],
        allow_credentials=True,
        allow_methods=['*'],
        allow_headers=['*'],
    )

    # Security headers
    from app.security import SecurityHeadersMiddleware
    app.add_middleware(SecurityHeadersMiddleware)

    # Static files (/static/*)
    app.mount('/static', StaticFiles(directory=_static_dir), name='static')

    # Rate limiter
    from app.limiter import limiter
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Routers
    from app.auth  import router as auth_router
    from app.chat  import router as chat_router   # also registers sio events
    from app.routes import router as routes_router

    app.include_router(auth_router,   prefix='/api/auth', tags=['auth'])
    app.include_router(chat_router,   prefix='/api/chat', tags=['chat'])
    app.include_router(routes_router, tags=['pages'])

    # Health check
    @app.get('/api/health')
    def health():
        return {'status': 'ok', 'service': 'SecureIM'}

    # ── Background scheduler ───────────────────────────────────────
    from app.scheduler import start_scheduler
    start_scheduler()

    # ── Wrap with python-socketio ASGI app ─────────────────────────
    # The socketio ASGIApp intercepts /socket.io/* requests;
    # everything else is passed through to FastAPI.
    asgi_app = _sio_lib.ASGIApp(sio, other_asgi_app=app, socketio_path='/socket.io')
    return asgi_app
