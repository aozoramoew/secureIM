"""
Security middleware — injects HTTP security headers on every response.
Converted from Flask after_request hook to a FastAPI ASGI middleware class.

The Content-Security-Policy enforces that:
  - Only our own JS files execute (script-src 'self')
  - No inline scripts or eval() (default, no 'unsafe-inline' or 'unsafe-eval')
  - No iframes (frame-ancestors 'none') — blocks clickjacking
  - WebSocket connections to self allowed (connect-src 'self' ws: wss:)
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "connect-src 'self' ws: wss:; "
    "img-src 'self' data:; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self';"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers['Content-Security-Policy']  = CSP
        response.headers['X-Content-Type-Options']   = 'nosniff'
        response.headers['X-Frame-Options']          = 'DENY'
        response.headers['X-XSS-Protection']         = '0'
        response.headers['Referrer-Policy']          = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy']       = 'geolocation=(), camera=(), microphone=()'
        if request.url.scheme == 'https':
            response.headers['Strict-Transport-Security'] = (
                'max-age=63072000; includeSubDomains; preload'
            )
        return response
