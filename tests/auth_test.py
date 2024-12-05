import pytest

from fastapi import Depends
from sqlalchemy import Column, Integer, String, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.future import select

import models
from services.auth import AuthService
from settings import settings

TEST_DATABASE_URL = settings.test_database_url

Base = declarative_base()
engine = create_async_engine(TEST_DATABASE_URL, echo=True)

TestingSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

class User(Base):
    __tablename__ = "Users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True)
    email = Column(String, unique=True)
    phone_number = Column(String)
    password_hash = Column(Text)
    is_active = Column(Boolean, default=False)
    role = Column(String, default="user")
    is_2fa = Column(Boolean, default=False)
    secret = Column(String)

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

@pytest.fixture(scope="function")
async def setup_database():
    await init_db()
    async with TestingSessionLocal() as session:
        yield session
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

@pytest.mark.asyncio
async def test_register(setup_database):
    async with TestingSessionLocal() as session:
        service = AuthService(session=session)

        user_data = models.auth.UserRegistration(
            email="tutikosnov@gmail.com",
            username="tutik77",
            password="AAaa1234!!",
            phone_number="89528723878",
        )
        
        result = await service.register(user_data)
        
        assert result.status_code == 201

        db_user = await session.execute(
            select(User).filter(User.email == user_data.email)
        )
        db_user = db_user.scalars().first()

        assert db_user is not None
        assert db_user.email == user_data.email
        assert db_user.username == user_data.username
        assert db_user.phone_number == user_data.phone_number
        assert db_user.password != user_data.password
        assert db_user.is_active is False
        assert db_user.role == "user"
        assert db_user.is_2fa is False
        assert db_user.secret is None
