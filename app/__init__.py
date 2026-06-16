"""
FastAPI application factory.
Replaces Flask create_app() — returns a python-socketio ASGIApp
that wraps the FastAPI app (handles both HTTP and WebSocket traffic).
"""
import os
import socketio as _sio_lib

from config import settings

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.socket_manager import sio

_static_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'static')


def create_app():
    # ── Create tables ──────────────────────────────────────────────
    from app.database import engine, Base
    import app.models  # registers all ORM classes  # noqa: F401
    Base.metadata.create_all(bind=engine)

    # ── FastAPI app ────────────────────────────────────────────────
    app = FastAPI(
        title='SecureIM',
        description='Zero-trust E2EE messaging system',
        version='2.0.0',
        docs_url=None,    # disable Swagger in all envs (security)
        redoc_url=None,
    )

    # CORS — restrict origins; configure via ALLOWED_ORIGINS env var
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allow_headers=['Authorization', 'Content-Type'],
    )

    # Security headers
    from app.security import SecurityHeadersMiddleware
    app.add_middleware(SecurityHeadersMiddleware)

    # ML-WAF — enabled via MLWAF_ENABLED=true env var
    if settings.MLWAF_ENABLED:
        from app.waf import MLWafMiddleware
        app.add_middleware(MLWafMiddleware)

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

    # Temporary debug endpoint — remove after WAF IP debugging
    if settings.DEBUG:
        from fastapi import Request as _Request
        @app.get('/api/debug/headers')
        async def debug_headers(request: _Request):
            return {
                'client': request.client,
                'headers': dict(request.headers),
            }

    # ── Background scheduler ───────────────────────────────────────
    from app.scheduler import start_scheduler
    start_scheduler()

    # ── Wrap with python-socketio ASGI app ─────────────────────────
    # The socketio ASGIApp intercepts /socket.io/* requests;
    # everything else is passed through to FastAPI.
    asgi_app = _sio_lib.ASGIApp(sio, other_asgi_app=app, socketio_path='/socket.io')
    return asgi_app
