"""
Application configuration — framework-agnostic settings singleton.
All values read from environment variables with safe defaults.
"""
import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


def _fix_db_url(url: str) -> str:
    """Railway provides postgres:// but SQLAlchemy 2.x needs postgresql://"""
    if url and url.startswith('postgres://'):
        return url.replace('postgres://', 'postgresql://', 1)
    return url


class Settings:
    # ── Core ─────────────────────────────────────────────────────────
    SECRET_KEY     = os.environ.get('SECRET_KEY', 'CHANGE-ME-IN-PRODUCTION-USE-SECRETS-TOKEN')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'CHANGE-ME-JWT-USE-SECRETS-TOKEN')
    DEBUG          = os.environ.get('DEBUG', 'true').lower() == 'true'

    # ── Database ──────────────────────────────────────────────────────
    DATABASE_URL = _fix_db_url(
        os.environ.get('DATABASE_URL', 'sqlite:///instance/secureIM.db')
    )

    # ── Email: Resend API (recommended — free 3 000 emails/month) ─────
    # Sign up at https://resend.com → API Keys → Create
    # Set RESEND_API_KEY=re_xxxx in your .env / Railway env vars.
    RESEND_API_KEY    = os.environ.get('RESEND_API_KEY', '')
    RESEND_FROM_EMAIL = os.environ.get('RESEND_FROM_EMAIL', 'onboarding@resend.dev')

    # ── Email: SMTP fallback (e.g. Gmail) ─────────────────────────────
    MAIL_SERVER         = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT           = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USERNAME       = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD       = os.environ.get('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.environ.get(
        'MAIL_DEFAULT_SENDER', 'SecureIM <noreply@secureim.local>'
    )

    # MAIL_SUPPRESS_SEND=true → print links to console only (dev mode)
    # MAIL_SUPPRESS_SEND=false → use Resend → SMTP → fallback log
    MAIL_SUPPRESS_SEND = os.environ.get('MAIL_SUPPRESS_SEND', 'true').lower() == 'true'

    # ── Token Expiry ──────────────────────────────────────────────────
    JWT_EXPIRY                = timedelta(days=30)
    VERIFICATION_TOKEN_EXPIRY = timedelta(minutes=15)
    EMAIL_VERIFY_TOKEN_EXPIRY = timedelta(hours=24)

    # ── Server ────────────────────────────────────────────────────────
    BASE_URL = os.environ.get('BASE_URL', 'http://localhost:8000')
    PORT     = int(os.environ.get('PORT', 8000))

    # ── Security ──────────────────────────────────────────────────────
    KEY_ROTATION_THRESHOLD = int(os.environ.get('KEY_ROTATION_THRESHOLD', 100))

    # ── Rate Limiting ─────────────────────────────────────────────────
    RATELIMIT_AUTH_LOGIN    = os.environ.get('RATELIMIT_AUTH_LOGIN',    '10/minute')
    RATELIMIT_AUTH_REGISTER = os.environ.get('RATELIMIT_AUTH_REGISTER', '5/hour')


settings = Settings()
