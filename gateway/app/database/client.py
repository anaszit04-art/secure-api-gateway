from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from gateway.app.database.config import (
    DatabaseSettings,
)


DatabaseSessionFactory = async_sessionmaker[
    AsyncSession
]


def create_database_engine(
    settings: DatabaseSettings,
) -> AsyncEngine:
    """
    Create the asynchronous SQLAlchemy engine.

    No connection is opened immediately. Connections are
    acquired lazily from the pool when required.
    """
    return create_async_engine(
        settings.url,
        echo=False,
        pool_pre_ping=True,
        pool_size=settings.pool_size,
        max_overflow=settings.max_overflow,
        pool_timeout=(
            settings.pool_timeout_seconds
        ),
        connect_args={
            "timeout": (
                settings.connect_timeout_seconds
            ),
            "server_settings": {
                "application_name": (
                    settings.application_name
                ),
            },
        },
    )


def create_database_session_factory(
    engine: AsyncEngine,
) -> DatabaseSessionFactory:
    """
    Create the shared asynchronous session factory.
    """
    return async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )


async def verify_database_connection(
    engine: AsyncEngine,
) -> None:
    """
    Validate that PostgreSQL can execute a minimal query.
    """
    async with engine.connect() as connection:
        result = await connection.execute(
            text("SELECT 1")
        )

        value = result.scalar_one()

        if value != 1:
            raise RuntimeError(
                "Unexpected PostgreSQL "
                "verification result."
            )


async def close_database_engine(
    engine: AsyncEngine,
) -> None:
    """
    Dispose of all connections owned by the engine.
    """
    await engine.dispose()
