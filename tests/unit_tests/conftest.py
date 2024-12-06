import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from db_setup import Base, engine, TestingSessionLocal

@pytest_asyncio.fixture(scope="function")
async def setup_database():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
        
@pytest_asyncio.fixture(scope="function")
async def session() -> AsyncSession:
    async with TestingSessionLocal() as session:
        yield session