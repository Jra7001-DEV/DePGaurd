"""Database engine and session helpers."""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from depguard.config import get_settings
from depguard.db.models import Base

DATABASE_URL = get_settings().database_url
_engine_options = (
    {"connect_args": {"check_same_thread": False}} if DATABASE_URL.startswith("sqlite") else {}
)
engine = create_engine(DATABASE_URL, pool_pre_ping=True, **_engine_options)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db() -> None:
    """Create missing tables for local first-run use."""
    Base.metadata.create_all(bind=engine)


def get_session() -> Iterator[Session]:
    """Yield a database session and always close it."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
