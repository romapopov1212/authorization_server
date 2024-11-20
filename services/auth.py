from __future__ import annotations
from datetime import timedelta

from fastapi import Depends
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy.orm import Session
from fastapi import HTTPException
from fastapi import status
from fastapi.responses import JSONResponse
from sqlalchemy import or_

from database import get_session
from db import tables
from models.auth import Token, UserRegistration, PasswordResetConfirmModel
from settings import settings
from services.token import TokenService as TS
from logger import logger
from utils import create_url_safe_token, decode_url_safe_token
from celery_tasks import send_email

ph = PasswordHasher()

class AuthService:

    def __init__(self, session: Session = Depends(get_session), token_service: TS=Depends()):
        self.session = session
        self.token_service = token_service


    def register(
            self,
            user_data: UserRegistration,
    ):

        existing_user = self.session.query(tables.User).filter(
            or_(
                tables.User.email == user_data.email,
                tables.User.username == user_data.username
            )
        ).first()

        if existing_user:
            logger.error("User with this email: {user_data.email} or username: {user_data.username} already exists")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email or username already exists",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )

        self.send_email_to_confirm(user_data.email)

        user = tables.User(
            email = user_data.email,
            username = user_data.username,
            password_hash = self.hash_password(user_data.password),
            is_active = False
        )

        self.session.add(user)
        self.session.commit()
        logger.info(f"User with email: \"{user_data.email}\" and username \"{user_data.username}\" registered successfully")
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={"message": "User registered successfully", "user": user_data.dict()}
        )

    def send_email_to_confirm(self, email):
        token = create_url_safe_token({"email": email})
        link = f"http://localhost/auth/email_confirm?token={token}"
        html_message = f'Инструкция для подтверждения почты: <p>{link}</p>'
        subject = "Email Confirm Instructions"
        send_email([email], subject, html_message)

    def authenticate_user(
            self,
            user_email: str,
            password: str
    ) -> Token:

        user = self.get_user_by_email(user_email)
        access_token_expires = timedelta(seconds=settings.jwt_expiration)
        if not user or not self.verify_passwords(password, user.password_hash):
            logger.warning(f"Unsuccessful login attempt for user {user.id}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect email or password",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )
        if user.is_active is False:
            logger.warning(f"Unsuccessful login attempt for user {user.id}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Confirm your email",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )
        if user is not None:
            password_valid = self.verify_passwords(password, user.password_hash)
            if password_valid:
                access_token = self.token_service.create_access_token(
                    data={"sub": str(user.id)},
                    expires_delta=access_token_expires
                )
                refresh_token = self.token_service.create_access_token(
                    data={"sub": str(user.id)},
                    expires_delta=timedelta(days=settings.refresh_token_expire),
                    #refresh = True,
                )
                logger.info(f"Successful login attempt for user {user.email}")
                return Token(access_token=access_token, refresh_token=refresh_token)
        logger.warning(f"Unsuccessful login attempt for user {user.id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )


    def update_user(
            self,
            user: tables.User,
            user_data: dict
    ):
        for k, v in user_data.items():
            setattr(user, k, v)

        self.session.commit()

        return user


    #повторяется, вынес в функцию
    def get_user_by_email(
            self,
            email: str
    ):
        user = self.session.query(tables.User).filter(tables.User.email == email).first()
        return user


    def hash_password(
            self,
            password: str
    ) -> str:
        return ph.hash(password)


    def reset_password(
            self,
            token: str,
            password: PasswordResetConfirmModel,
    ):
        new_password = password.new_password
        confirm_password = password.confirm_new_password
        if new_password != confirm_password:
            logger.warning("Unsuccessful reset password for user")
            raise HTTPException(
                detail="Passwords don't match",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        token_data = decode_url_safe_token(token)
        user_email = token_data.get("email")

        if user_email:
            user = self.get_user_by_email(user_email)
            if not user:
                logger.warning(f"Unsuccessful reset password for user {user.email}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )
            passwd_hash = self.hash_password(new_password)
            self.update_user(user, {"password_hash": passwd_hash})
            logger.info(f"Successful reset password for user {user.email}")
            return JSONResponse(
                content={"message": "Password reset Successfully"},
                status_code=status.HTTP_200_OK,
            )
        logger.warning(f"Unsuccessful reset password {user_email}")
        return JSONResponse(
            content={"message": "Error occured during password reset."},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


    def verify_passwords(self, plain_password, hashed_password):
        try:
            ph.verify(hashed_password, plain_password)
            return True
        except VerifyMismatchError:
            return False


    def activate_user(self, token: str):
        token_data = decode_url_safe_token(token)
        user_email = token_data.get("email")
        if user_email:
            user = self.get_user_by_email(user_email)
            if not user:
                logger.warning(f"Unsuccessful activation for user {user.email}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )
            self.update_user(user, {"is_active": True})
            logger.info(f"Successful activation for user {user.email}")
            return JSONResponse(
                content={"message": "User Activated Successfully"},
                status_code=status.HTTP_200_OK,
            )
        logger.warning(f"Unsuccessful activation for user {user_email}")
        return JSONResponse(
            content={"message": "Error occured during activation."},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
