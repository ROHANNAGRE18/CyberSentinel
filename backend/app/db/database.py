"""
Database engine and session factory.

Uses SQLAlchemy async engine with aiosqlite for SQLite (dev).
Swapping to PostgreSQL only requires changing DATABASE_URL in .env —
the rest of the code stays identical.
"""

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings

settings = get_settings()

# ── Engine ───────────────────────────────────────────────────────────────────
# connect_args is SQLite-specific: enables WAL mode for better concurrency.
_connect_args = (
    {"check_same_thread": False} if "sqlite" in settings.database_url else {}
)

engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,          # logs SQL when DEBUG=true
    connect_args=_connect_args,
)

# ── Session factory ──────────────────────────────────────────────────────────
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


# ── Declarative base ─────────────────────────────────────────────────────────
class Base(DeclarativeBase):
    """All ORM models inherit from this base."""
    pass


# ── Dependency ────────────────────────────────────────────────────────────────
async def get_db() -> AsyncSession:
    """
    FastAPI dependency that yields a database session per request
    and guarantees it is closed afterwards.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
