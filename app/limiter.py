"""
Rate limiter singleton using SlowAPI (FastAPI-compatible Flask-Limiter replacement).
"""
from slowapi import Limiter


def _real_client_ip(request) -> str:
    """
    Resolve the real client IP for rate-limiting.
    On Railway/Fly/Heroku, request.client.host is the internal proxy address
    (e.g. 100.64.x.x, different per-request) — the actual client IP arrives
    in X-Forwarded-For. Falls back to request.client.host when absent (local dev).
    """
    xff = request.headers.get('x-forwarded-for', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.client.host if request.client else '0.0.0.0'


limiter = Limiter(
    key_func=_real_client_ip,
    default_limits=['200/day', '50/hour'],
)
