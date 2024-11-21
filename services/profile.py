from fastapi import Depends
from argon2.exceptions import VerifyMismatchError
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from fastapi.responses import JSONResponse

from celery_tasks import send_email_to_confirm
from services.auth import ph

from database import get_session
from db import tables
from logger import logger
from settings import settings


class ProfileService:

    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    def get_profile(self, user_id):
        user = self.session.query(
            tables.User.username,
            tables.User.email,
            tables.User.role
        ).filter_by(id=user_id).first()
        return {"username": user.username, "email": user.email, "role": user.role}

    async def change_email(self, user_id, data):
        existing_user = self.session.query(tables.User).filter(tables.User.email == data.new_email).first()

        if existing_user:
            logger.error("Unsuccessful attempt to change email by user with user id: {user_id}. User with this email: {data.new_email} already exists")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )

        user = self.session.query(tables.User).filter_by(id=user_id).first()
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
        self.session.commit()

        
        await send_email_to_confirm(data.new_email)
        logger.info(f"Successful request to confirm email {user.email}")
        return JSONResponse(
            content={
                "message": "На вашу почту отправлена инструкция для подтверждения почты",
            },
            status_code=status.HTTP_200_OK,
        )


    def change_username(self, user_id, data):
        existing_user = self.session.query(tables.User).filter(tables.User.username == data.new_username).first()

        if existing_user:
            logger.error(f"Unsuccessful attempt to change username by user with user id: {user_id}. User with this username: {data.new_username} already exists")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this username already exists",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )

        
        user = self.session.query(tables.User).filter_by(id=user_id).first()
        user.username = data.new_username
        self.session.commit()
        return

    def change_password(self, user_id, data):
        user = self.session.query(tables.User).filter_by(id=user_id).first()
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
        self.session.commit()
        return

    def set_role(self, data):
        if data.owner_password != settings.OWNER_PASSWORD:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect password",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )
        user = self.get_user_by_email(data.email)
        user.role = data.role
        self.session.commit()
        return

    def verify_passwords(self, plain_password, hashed_password):
        try:
            ph.verify(hashed_password, plain_password)
            return True
        except VerifyMismatchError:
            return False

    def hash_password(self, password: str) -> str:
        return ph.hash(password)

    def get_user_by_email(
        self,
        email: str
    ):
        user = self.session.query(tables.User).filter(tables.User.email == email).first()
        return user