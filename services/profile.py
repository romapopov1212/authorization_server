from fastapi import Depends
from argon2.exceptions import VerifyMismatchError
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy.future import select

from celery_tasks import send_email_to_confirm
from services.auth import ph

from database import get_session
from db import tables
from logger import logger


class ProfileService:

    def __init__(self, session: Session = Depends(get_session)):
        self.session = session


    async def get_user_by_id(self, user_id):
        user_id = int(user_id)
        stmt = select(tables.User).filter(tables.User.id == user_id)
        result = await self.session.execute(stmt)
        user = result.scalars().first()
        return user


    async def change_password(self, user_id, data):
        user = await self.get_user_by_id(user_id)
        if not self.verify_passwords(data.password, user.password_hash):
            logger.warning(f"Unsuccessful attempt to change password by user with user id: {user_id}. Incorrect password")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect password",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )
        user.password_hash = self.hash_password(data.new_password)
        await self.session.commit()
        return


    async def change_email(self, user_id, data):
        existing_user = await self.get_user_by_email(data.new_email)

        if existing_user:
            logger.error("Unsuccessful attempt to change email by user with user id: {user_id}. User with this email: {data.new_email} already exists")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )

        user = await self.get_user_by_id(user_id)
        if not self.verify_passwords(data.password, user.password_hash):
            logger.error(f"Incorrect password for user {user_id}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect password",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )
        user.email = data.new_email
        user.is_active = False
        await self.session.commit()
        
        await send_email_to_confirm(data.new_email)
        logger.info(f"Successful request to confirm email {user.email}")
        return JSONResponse(
            content={
                "message": "На вашу почту отправлена инструкция для подтверждения почты",
            },
            status_code=status.HTTP_200_OK,
        )


    async def change_username(self, user_id, data):
        existing_user = await self.get_user_by_username(data.new_username)

        if existing_user:
            logger.error(f"Unsuccessful attempt to change username by user with user id: {user_id}. User with this username: {data.new_username} already exists")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this username already exists",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )
        
        user = await self.get_user_by_id(user_id)
        user.username = data.new_username
        await self.session.commit()
        return


    def verify_passwords(self, plain_password, hashed_password):
        try:
            ph.verify(hashed_password, plain_password)
            return True
        except VerifyMismatchError:
            return False


    def hash_password(self, password: str) -> str:
        return ph.hash(password)


    async def get_user_by_email(
            self,
            email: str
    ):
        stmt = select(tables.User).filter(tables.User.email == email)
        result = await self.session.execute(stmt)
        user = result.scalars().first()
        return user


    async def get_user_by_username(
            self,
            username: str
    ):
        stmt = select(tables.User).filter(tables.User.username == username)
        result = await self.session.execute(stmt)
        user = result.scalars().first()
        return user