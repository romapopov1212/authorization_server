from datetime import datetime, timedelta, timezone

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
from models.auth import Token, UserRegistration
from settings import settings
from services.token import TokenService as TS

ph = PasswordHasher()

class ProfileService:

    def __init__(self, session: Session = Depends(get_session), token_service: TS=Depends()):
        self.session = session
        self.token_service = token_service

    def register(self, user_data: UserRegistration):
        existing_user = self.session.query(tables.User).filter(
            or_(
                tables.User.email == user_data.email,
                tables.User.username == user_data.username
            )
        ).first()

        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email or username already exists",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )

        user = tables.User(
            email = user_data.email,
            username = user_data.username,
            password_hash = self.hash_password(user_data.password)
        )
        self.session.add(user)
        self.session.commit()
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={"message": "User registered successfully", "user": user_data.dict()}
        )

    def authenticate_user(self, username: str, password: str) -> Token:
        user = self.session.query(tables.User).filter(tables.User.username == username).first()
        access_token_expires = timedelta(minutes=settings.jwt_expiration)
        if not user or not self.verify_passwords(password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect email or password",
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
                    refresh = True,
                )
                return Token(access_token=access_token, refresh_token=refresh_token)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )



    def hash_password(self, password: str) -> str:
        return ph.hash(password)

    def verify_passwords(self, plain_password, hashed_password):
        try:
            ph.verify(hashed_password, plain_password)
            return True
        except VerifyMismatchError:
            return False

