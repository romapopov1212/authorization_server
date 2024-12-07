from contextlib import nullcontext as does_not_raise
from unittest.mock import AsyncMock, Mock
import pytest
from sqlalchemy.future import select
from services.token import TokenService
import models
from models.auth import Token
from services.auth import AuthService
from db_setup import User

class MockTokenService:
    def create_access_token(self, data):
        return "mock_access_token"

class TestAuthService:

    @pytest.mark.parametrize(
        "email, username, password, phone_number, expectation",
        [
            ("test@test.com", "test", "AAaa1234!!", "89005553535", does_not_raise()),
            ("plohoyemail", "test", "AAaa1234!!", "89005553535", pytest.raises(ValueError)),
            ("test@test.com", "test", "AAaa", "89005553535", pytest.raises(ValueError)),
            ("test@test.com", "test", "AAaa1234!!", "22822822828", pytest.raises(ValueError)),
        ])
    def test_RegisterModel(self, email, username, password, phone_number, expectation):
        with expectation:
            models.auth.UserRegistration(
                email=email,
                username=username,
                password=password,
                phone_number=phone_number,
            )
        assert True

    # 
    # @pytest.mark.asyncio
    # async def test_register(self, setup_database, session):
    #     service = AuthService(session=session)
    #
    #     user_data = models.auth.UserRegistration(
    #         email="test@test.com",
    #         username="tutik77",
    #         password="AAaa1234!!",
    #         phone_number="89528723878",
    #     )
    #
    #     result = await service.register(user_data)
    #
    #     assert result.status_code == 201
    #
    #     db_user = await session.execute(
    #         select(User).filter(User.email == user_data.email)
    #     )
    #     db_user = db_user.scalars().first()
    #
    #     assert db_user is not None

    @pytest.mark.asyncio
    async def test_login(self, setup_database, session):
        token_service = TokenService()
        service = AuthService(session=session, token_service=token_service)
        user_data_to_register = models.auth.UserRegistration(
            email="test@test.com",
            username="tutik77",
            password="AAaa1234!!",
            phone_number="89528723878",
        )
        await service.register(user_data_to_register)
        user = await service.get_user_by_email(user_data_to_register.email)
        user.is_active = True
        session.add(user)
        await session.commit()
        email = "test@test.com"
        password = "AAaa1234!!"
        code = "string"

        result = await service.authenticate_user(email, password, code)
        assert result is not None
        assert isinstance(result, Token)
        #assert result.status_code == 200
