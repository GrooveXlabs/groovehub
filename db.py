"""Database initialization and session management."""

from __future__ import annotations

from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from groovehub.models import Base

DEFAULT_DB_PATH = Path.home() / ".groovehub" / "groovehub.db"

_engine = None
_SessionLocal = None


def init_db(db_path: Path | str | None = None) -> None:
    """Initialize the database engine and create tables."""
    global _engine, _SessionLocal

    if db_path is None:
        DEFAULT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        db_path = DEFAULT_DB_PATH

    db_url = f"sqlite:///{db_path}" if db_path != ":memory:" else "sqlite:///:memory:"
    connect_args = {"check_same_thread": False} if db_path == ":memory:" else {}
    poolclass = StaticPool if db_path == ":memory:" else None

    _engine = create_engine(
        db_url,
        echo=False,
        connect_args=connect_args,
        poolclass=poolclass,
    )
    _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)
    Base.metadata.create_all(bind=_engine)


def get_session() -> Generator[Session, None, None]:
    """Yield a database session."""
    if _SessionLocal is None:
        init_db()

    session = _SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_engine():
    if _engine is None:
        init_db()
    return _engine
