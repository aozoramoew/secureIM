import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Core
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-CHANGE-in-production-32chars!')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-CHANGE-in-production-32c!')

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///secureIM.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Mail — set MAIL_SUPPRESS_SEND=false and fill SMTP details to send real emails
    MAIL_SERVER   = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT     = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS  = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'SecureIM <noreply@secureim.local>')
    # When True, emails are printed to the console (development mode)
    MAIL_SUPPRESS_SEND = os.environ.get('MAIL_SUPPRESS_SEND', 'true').lower() == 'true'

    # Token lifetimes
    JWT_EXPIRY                  = timedelta(days=30)
    VERIFICATION_TOKEN_EXPIRY   = timedelta(minutes=15)   # 2FA link
    EMAIL_VERIFY_TOKEN_EXPIRY   = timedelta(hours=24)     # account activation link

    # SocketIO
    SOCKETIO_ASYNC_MODE = 'threading'

    # Public base URL (used to build email links)
    BASE_URL = os.environ.get('BASE_URL', 'http://localhost:5000')

    # Key-rotation threshold: rotate session key after this many messages
    KEY_ROTATION_THRESHOLD = 100
