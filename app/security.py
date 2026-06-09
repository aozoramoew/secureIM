"""
Security middleware — injects HTTP security headers on every response.

Implemented as a pure ASGI middleware (not BaseHTTPMiddleware) to avoid
Starlette's known issue where BaseHTTPMiddleware swallows exceptions and
returns a plain-text 500 with no Content-Type header, breaking JSON error
responses from FastAPI.
"""

CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "connect-src 'self' ws: wss:; "
    "img-src 'self' data: blob:; "
    "media-src 'self' blob:; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self';"
)

_SECURITY_HEADERS = [
    (b'content-security-policy',  CSP.encode()),
    (b'x-content-type-options',   b'nosniff'),
    (b'x-frame-options',          b'DENY'),
    (b'x-xss-protection',         b'0'),
    (b'referrer-policy',          b'strict-origin-when-cross-origin'),
    (b'permissions-policy',       b'geolocation=(), camera=(), microphone=()'),
]

_HSTS = (b'strict-transport-security', b'max-age=63072000; includeSubDomains; preload')


class SecurityHeadersMiddleware:
    """Pure ASGI middleware — wraps the app without touching BaseHTTPMiddleware."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] not in ('http', 'websocket'):
            await self.app(scope, receive, send)
            return

        is_https = scope.get('scheme') in ('https', 'wss')

        async def send_with_headers(message):
            if message['type'] == 'http.response.start':
                headers = list(message.get('headers', []))
                headers.extend(_SECURITY_HEADERS)
                if is_https:
                    headers.append(_HSTS)
                message = {**message, 'headers': headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)
