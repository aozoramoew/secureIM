"""
Rate limiter singleton.
Imported by __init__.py and auth.py to apply per-endpoint limits.
"""
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",   # override with Redis URL in production
)
