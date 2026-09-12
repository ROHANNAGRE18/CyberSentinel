"""
Database initialisation.

Creates all tables defined in the ORM models if they do not already exist.
Called once at application startup via the FastAPI lifespan handler.

For schema migrations in production, use Alembic instead of this module.
"""

import logging

from app.db.database import Base, engine

# Import all models so SQLAlchemy's metadata is aware of every table
# before we call create_all. Without these imports the tables won't be created.
import app.models.scan  # noqa: F401

logger = logging.getLogger(__name__)


async def init_db() -> None:
    """Create database tables on first run (idempotent — safe to call repeatedly)."""
    logger.info("Initialising database...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database initialisation complete.")
