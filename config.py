"""
Application configuration — reads from environment variables with safe defaults.
Set these as Railway environment variables (or a local .env file) for production.
"""
import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


def _fix_db_url(url: str) -> str:
    # Railway provides postgres:// but SQLAlchemy 2.x requires postgresql://
    if url and url.startswith('postgres://'):
        return url.replace('postgres://', 'postgresql://', 1)
    return url


class Settings:
    # ── Core secrets — generate with: python -c "import secrets; print(secrets.token_hex(32))"
    SECRET_KEY     = os.environ.get('SECRET_KEY',     'CHANGE-ME-IN-PRODUCTION')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'CHANGE-ME-JWT-IN-PRODUCTION')
    DEBUG          = os.environ.get('DEBUG', 'true').lower() == 'true'

    # ── Database — defaults to local SQLite, set DATABASE_URL for PostgreSQL on Railway
    DATABASE_URL = _fix_db_url(
        os.environ.get('DATABASE_URL', 'sqlite:///instance/secureIM.db')
    )

    # ── Server
    BASE_URL = os.environ.get('BASE_URL', 'http://localhost:8000')
    PORT     = int(os.environ.get('PORT', 8000))

    # ── JWT lifetime
    JWT_EXPIRY = timedelta(days=30)

    # ── E2EE session — rotate keys every N messages for forward secrecy
    KEY_ROTATION_THRESHOLD = int(os.environ.get('KEY_ROTATION_THRESHOLD', 100))

    # ── Rate limiting
    RATELIMIT_AUTH_LOGIN    = os.environ.get('RATELIMIT_AUTH_LOGIN',    '10/minute')
    RATELIMIT_AUTH_REGISTER = os.environ.get('RATELIMIT_AUTH_REGISTER', '5/hour')


settings = Settings()
