import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:
    # ── Core ────────────────────────────────────────────────────
    SECRET_KEY     = os.environ.get('SECRET_KEY', 'CHANGE-ME-IN-PRODUCTION-USE-SECRETS-TOKEN')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'CHANGE-ME-JWT-USE-SECRETS-TOKEN')

    # ── Database ─────────────────────────────────────────────────
    SQLALCHEMY_DATABASE_URI     = os.environ.get('DATABASE_URL', 'sqlite:///secureIM.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ── Mail ─────────────────────────────────────────────────────
    MAIL_SERVER         = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT           = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS        = True
    MAIL_USERNAME       = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD       = os.environ.get('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'SecureIM <noreply@secureim.local>')
    # True = print links to console (dev). False = send real email (prod).
    MAIL_SUPPRESS_SEND  = os.environ.get('MAIL_SUPPRESS_SEND', 'true').lower() == 'true'

    # ── Tokens ───────────────────────────────────────────────────
    JWT_EXPIRY                = timedelta(days=30)
    VERIFICATION_TOKEN_EXPIRY = timedelta(minutes=15)
    EMAIL_VERIFY_TOKEN_EXPIRY = timedelta(hours=24)

    # ── SocketIO / Server ─────────────────────────────────────────
    # Use 'gevent' for production (gunicorn gevent worker).
    # Use 'threading' for dev (werkzeug).
    SOCKETIO_ASYNC_MODE = os.environ.get('SOCKETIO_ASYNC_MODE', 'threading')

    BASE_URL = os.environ.get('BASE_URL', 'http://localhost:5000')

    # ── Security ──────────────────────────────────────────────────
    KEY_ROTATION_THRESHOLD = int(os.environ.get('KEY_ROTATION_THRESHOLD', 100))

    # ── Rate Limiting ─────────────────────────────────────────────
    RATELIMIT_STORAGE_URL         = os.environ.get('RATELIMIT_STORAGE_URL', 'memory://')
    RATELIMIT_DEFAULT             = '200 per day;50 per hour'
    RATELIMIT_AUTH_LOGIN          = os.environ.get('RATELIMIT_AUTH_LOGIN', '10 per minute')
    RATELIMIT_AUTH_REGISTER       = os.environ.get('RATELIMIT_AUTH_REGISTER', '5 per hour')

    # ── CSP / Headers ─────────────────────────────────────────────
    # Populated dynamically in security.py
    SEND_FILE_MAX_AGE_DEFAULT = timedelta(days=365)


class ProductionConfig(Config):
    DEBUG   = False
    TESTING = False
    SOCKETIO_ASYNC_MODE = 'gevent'
    # Override MAIL_SUPPRESS_SEND so emails are actually sent
    MAIL_SUPPRESS_SEND = os.environ.get('MAIL_SUPPRESS_SEND', 'false').lower() == 'true'


class DevelopmentConfig(Config):
    DEBUG = True
    SOCKETIO_ASYNC_MODE = 'threading'


config_map = {
    'production':  ProductionConfig,
    'development': DevelopmentConfig,
    'default':     DevelopmentConfig,
}
