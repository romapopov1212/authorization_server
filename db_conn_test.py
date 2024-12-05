from sqlalchemy import create_engine, Integer, String, Column, text, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
import asyncio
from settings import settings

Base = declarative_base()

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


engine = create_async_engine(settings.test_database_url, echo=True)

SessionTest = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("Таблицы успешно созданы")

async def check_database():
    try:
        await init_db()
    except Exception as e:
        print(f"Произошла ошибка: {e}")

if __name__ == "__main__":
    asyncio.run(check_database())
