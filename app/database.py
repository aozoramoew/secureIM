"""
SQLAlchemy database engine, session factory, and declarative base.
Replaces Flask-SQLAlchemy — no Flask app context required.
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

from config import settings

# Ensure the instance directory exists for SQLite
if 'sqlite' in settings.DATABASE_URL:
    os.makedirs('instance', exist_ok=True)

# SQLite needs check_same_thread=False for multi-threaded ASGI use
_connect_args = {'check_same_thread': False} if 'sqlite' in settings.DATABASE_URL else {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=_connect_args,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""
    pass


# FastAPI dependency — yields a DB session, closes after request
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
