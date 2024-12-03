import asyncio

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from ..main import app
from database import get_session
from db.tables import Base, User

TEST_DATABASE_URL = "postgresql+asyncpg://postgres_test:1234@localhost:5433/test_db"
test_engine = create_async_engine(TEST_DATABASE_URL, echo=False)
TestSessionLocal = sessionmaker(bind=test_engine, class_=AsyncSession, expire_on_commit=False)

@pytest.fixture(scope="module", autouse=True)
async def prepare_database():
    """Создает тестовую базу данных перед тестами"""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

@pytest_asyncio.fixture
async def test_session():
    """Создает и возвращает тестовую сессию"""
    async with TestSessionLocal() as session:
        yield session

@pytest_asyncio.fixture
async def override_get_async_session(test_session):
    """Переопределяет зависимость FastAPI на тестовую сессию"""
    async def _override_session():
        yield test_session
    app.dependency_overrides[get_session] = _override_session

@pytest_asyncio.fixture
async def client(override_get_async_session):
    """Запускает сервер FastAPI в фоновом процессе для асинхронных тестов"""
    async with AsyncClient(base_url="http://localhost:5433") as ac:
        yield ac

@pytest.mark.asyncio
async def test_sign_up_success(client: AsyncClient, test_session: AsyncSession):
    payload = {
        "email": "popovvroma054@gmail.com",
        "username": "testuser",
        "phone_number": "89956705235",
        "password": "Ge896189098909&",
    }
    response = await client.post("/auth/sign-up", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == payload["email"]
    assert data["username"] == payload["username"]
