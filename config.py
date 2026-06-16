"""
Application configuration — reads from environment variables with safe defaults.
Set these as Railway environment variables (or a local .env file) for production.
"""
import logging
import os
import secrets as _secrets
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()
_log = logging.getLogger(__name__)


def _fix_db_url(url: str) -> str:
    # Railway provides postgres:// but SQLAlchemy 2.x requires postgresql://
    if url and url.startswith('postgres://'):
        return url.replace('postgres://', 'postgresql://', 1)
    return url


def _get_secret(env_var: str) -> str:
    """Return the secret from env, or generate a random one and warn loudly."""
    value = os.environ.get(env_var)
    if not value:
        value = _secrets.token_hex(32)
        _log.warning(
            "⚠️  %s is not set! Using a random secret — sessions will be "
            "invalidated on every restart. Set %s in your environment for production.",
            env_var, env_var,
        )
    return value


class Settings:
    # ── Core secrets — generate with: python -c "import secrets; print(secrets.token_hex(32))"
    SECRET_KEY     = _get_secret('SECRET_KEY')
    JWT_SECRET_KEY = _get_secret('JWT_SECRET_KEY')
    DEBUG          = os.environ.get('DEBUG', 'false').lower() == 'true'

    # ── Database — defaults to local SQLite, set DATABASE_URL for PostgreSQL on Railway
    DATABASE_URL = _fix_db_url(
        os.environ.get('DATABASE_URL', 'sqlite:///instance/secureIM.db')
    )

    # ── Server
    BASE_URL = os.environ.get('BASE_URL', 'http://localhost:8000')
    PORT     = int(os.environ.get('PORT', 8000))

    # ── CORS — comma-separated origins; defaults to self only
    ALLOWED_ORIGINS = [
        o.strip() for o in
        os.environ.get('ALLOWED_ORIGINS', f'http://localhost:{os.environ.get("PORT", 8000)}').split(',')
        if o.strip()
    ]

    # ── JWT lifetime
    JWT_EXPIRY = timedelta(days=7)

    # ── E2EE session — rotate keys every N messages for forward secrecy
    KEY_ROTATION_THRESHOLD = int(os.environ.get('KEY_ROTATION_THRESHOLD', 100))

    # ── Rate limiting
    RATELIMIT_AUTH_LOGIN    = os.environ.get('RATELIMIT_AUTH_LOGIN',    '10/minute')
    RATELIMIT_AUTH_REGISTER = os.environ.get('RATELIMIT_AUTH_REGISTER', '5/hour')

    # ── ML-WAF sidecar
    MLWAF_URL = os.environ.get('MLWAF_URL', 'http://localhost:8001')
    MLWAF_ENABLED = (
        os.environ.get('MLWAF_ENABLED', 'false').lower() == 'true'
    )
    MLWAF_TIMEOUT = float(os.environ.get('MLWAF_TIMEOUT', '0.5'))


settings = Settings()
