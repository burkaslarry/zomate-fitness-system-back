"""
SQLAlchemy database session for Zomate Fitness backend.

Connection:
- DATABASE_URL (Render / eventxp External URL); normalises ``postgres://`` to
  ``postgresql+psycopg2://`` for SQLAlchemy 2.
- Optional SSL: DATABASE_SSLMODE, DATABASE_SSL, or host hints (e.g. render.com).

Exports: ``engine``, ``SessionLocal``, ``Base``, ``get_db`` dependency.
Persistence tables use prefix ``zomate_fs_*`` (see ``models.py``).
"""

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import settings

load_dotenv()


def _normalize_database_url(url: str) -> str:
    """
    SQLAlchemy 2 + psycopg2 expects postgresql+psycopg2://...
    Render / Heroku often provide postgres:// which must be rewritten.
    """
    u = url.strip()
    if u.startswith("postgres://"):
        u = "postgresql+psycopg2://" + u[len("postgres://") :]
    elif u.startswith("postgresql://") and "+psycopg2" not in u.split("://", 1)[0]:
        u = "postgresql+psycopg2://" + u[len("postgresql://") :]
    return u


def _connect_args(url: str) -> dict:
    """SSL for managed Postgres (Render, Neon, AWS RDS, etc.)."""
    if settings.database_sslmode:
        return {"sslmode": settings.database_sslmode}
    lower = url.lower()
    if "render.com" in lower or "sslmode=require" in lower:
        return {"sslmode": "require"}
    if settings.database_ssl.lower() in ("1", "true", "yes"):
        return {"sslmode": "require"}
    return {}


_raw_url = settings.database_url
DATABASE_URL = _normalize_database_url(_raw_url)

_ca = _connect_args(_raw_url)
_engine_kwargs = {"pool_pre_ping": True}
if _ca:
    _engine_kwargs["connect_args"] = _ca

engine = create_engine(DATABASE_URL, **_engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
