"""
Alembic migration environment.

Configured for async SQLAlchemy (aiosqlite / asyncpg).
The database URL is read from the application settings so it stays
in sync with the .env file — no need to edit alembic.ini.
"""

import asyncio
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# ── Load app settings & models ────────────────────────────────────────────────
# These imports make Alembic aware of all mapped tables.
from app.core.config import get_settings
from app.db.database import Base
import app.models.scan  # noqa: F401 – registers ORM metadata

settings = get_settings()

# ── Alembic config ────────────────────────────────────────────────────────────
config = context.config

# Override the sqlalchemy.url from alembic.ini with the value from .env
config.set_main_option("sqlalchemy.url", settings.database_url)

# Interpret the config file for Python logging if present
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


# ── Offline migrations ────────────────────────────────────────────────────────

def run_migrations_offline() -> None:
    """Run migrations without a live database connection (generates SQL script)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


# ── Online migrations ─────────────────────────────────────────────────────────

def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


# ── Entry point ───────────────────────────────────────────────────────────────

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
