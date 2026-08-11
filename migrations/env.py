from __future__ import annotations

import asyncio

from logging.config import (
    fileConfig,
)

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    create_async_engine,
)

from gateway.app.database.base import (
    Base,
)
from gateway.app.database.config import (
    DatabaseSettings,
)

# Import required so SQLAlchemy registers every ORM
# table in Base.metadata before autogeneration.
from gateway.app.database import (
    models as database_models,
)


config = context.config


if config.config_file_name is not None:
    fileConfig(
        config.config_file_name
    )


target_metadata = Base.metadata


def configure_context(
    connection: object,
) -> None:
    """
    Configure Alembic against an existing
    synchronous facade of the async connection.
    """

    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
        include_schemas=False,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """
    Execute migrations through SQLAlchemy asyncpg.
    """

    settings = (
        DatabaseSettings.from_environment()
    )

    engine = create_async_engine(
        settings.url,
        poolclass=pool.NullPool,
        echo=False,
        connect_args={
            "timeout": (
                settings
                .connect_timeout_seconds
            ),
            "server_settings": {
                "application_name": (
                    "secure-api-gateway-migrations"
                ),
            },
        },
    )

    try:
        async with engine.connect() as connection:
            await connection.run_sync(
                configure_context
            )
    finally:
        await engine.dispose()


def run_migrations_online() -> None:
    """
    Run online migrations.

    This project intentionally executes migrations
    against the real PostgreSQL database rather than
    silently creating schema through ORM create_all().
    """

    asyncio.run(
        run_async_migrations()
    )


if context.is_offline_mode():
    raise RuntimeError(
        "Offline migrations are disabled for "
        "this project."
    )

run_migrations_online()
