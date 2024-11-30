import asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from fastapi import FastAPI
import pytest
from db import tables
from sqlalchemy.orm import sessionmaker

async_engine=create_async_engine(
    url='postgresql+asyncpg://postgres:1234@localhost:5434/test_table',
    echo=True,
)

@pytest.fixture(scope='session')
async def async_db_engine():
    async with async_engine.begin() as conn:
        await conn.run_sync(tables.Base.metadata.create_all)

    yield async_engine

    async with async_engine.begin() as conn:
        await conn.run_sync(tables.Base.metadata.drop_all)

@pytest.fixture(scope='function')
async def async_db(async_db_engine):
    async_session = sessionmaker(
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
        bind=async_db_engine,
        class_=AsyncSession,
    )

    async with async_session() as session:
        await session.begin()

        yield session


        for table in reversed(tables.Base.metadata.sorted_tables):
            await session.execute(f'TRUNCATE {table.name} CASCADE;')
            await session.commit()

@pytest.fixture(scope="session")
async def async_client():
    async with AsyncClient(app=FastAPI(), base_url="http://localhost") as client:
        return client


@pytest.fixture(scope='session')
def event_loop():
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()
