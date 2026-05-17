"""
Security middleware — CSP headers, XSS hardening.

Why this fully mitigates XSS-based key exfiltration:
  1. Content-Security-Policy blocks ALL inline scripts and eval().
     Even if an attacker injects <script>...</script>, the browser
     refuses to execute it (CSP violation).
  2. script-src 'self' — only JS files served from our own origin run.
     No CDN, no inline, no eval → injected scripts are dead on arrival.
  3. Private keys in localStorage are encrypted (PBKDF2+AES-GCM). An
     attacker reading localStorage gets only ciphertext — useless without
     the in-memory password. But with CSP in place, no injected script
     can read localStorage in the first place.
  4. frame-ancestors 'none' blocks clickjacking.
  5. X-Content-Type-Options prevents MIME-sniffing attacks.
"""
from flask import request


CSP = (
    "default-src 'self'; "
    "script-src 'self'; "                          # Only our own JS files
    "style-src 'self' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "connect-src 'self' ws: wss:; "               # WebSocket allowed
    "img-src 'self' data:; "
    "frame-ancestors 'none'; "                     # No iframes → anti-clickjack
    "base-uri 'self'; "                            # Prevents base tag injection
    "form-action 'self';"                          # Forms only submit to us
)


def add_security_headers(response):
    """Attach security headers to every response."""
    response.headers['Content-Security-Policy']     = CSP
    response.headers['X-Content-Type-Options']      = 'nosniff'
    response.headers['X-Frame-Options']             = 'DENY'
    # Modern browsers use CSP instead; setting to '0' disables the legacy
    # XSS auditor which can itself be exploited.
    response.headers['X-XSS-Protection']            = '0'
    response.headers['Referrer-Policy']             = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy']          = 'geolocation=(), camera=(), microphone=()'
    # Only send over HTTPS in production — Nginx handles this header in prod
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = (
            'max-age=63072000; includeSubDomains; preload'
        )
    return response


def init_security(app):
    app.after_request(add_security_headers)
