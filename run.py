"""
SecureIM entry point — uvicorn / gunicorn.

Development:
    python run.py
    OR: uvicorn run:app --reload --port 8000

Production (Railway / Docker):
    gunicorn run:app -k uvicorn.workers.UvicornWorker -w 1 -b 0.0.0.0:$PORT
"""
import os

from app import create_app
from config import settings

app = create_app()

if __name__ == '__main__':
    import uvicorn
    print('=' * 60)
    print('  SecureIM — Zero-Trust E2EE Messaging')
    print(f'  Environment : {"development" if settings.DEBUG else "production"}')
    print(f'  Running at  : http://localhost:{settings.PORT}')
    print('  Email links : check terminal (MAIL_SUPPRESS_SEND=true)')
    print('=' * 60)
    uvicorn.run(
        'run:app',
        host='0.0.0.0',  # nosec B104 - intended for containerized deployment (Docker/Railway)
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level='info',
    )
