from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy.orm import Session
from fastapi import HTTPException
from fastapi import status
from fastapi.responses import JSONResponse
from sqlalchemy import or_
from jwt.exceptions import InvalidTokenError


from database import get_session
from db import tables
from models.auth import Token, UserRegistration
from settings import settings
from services.token import TokenService


oauth2_scheme = OAuth2PasswordBearer(tokenUrl='auth/sign-in')
ph = PasswordHasher()

class AuthService:

    def __init__(self, session: Session = Depends(get_session), token_service: TokenService=Depends()):
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
        if not user or not self.verify_passwords(password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect email or password",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )
        access_token_expires = timedelta(minutes=settings.jwt_expiration)
        access_token = self.create_access_token(
            data={"sub": user.username}, expires_delta=access_token_expires
        )
        return Token(access_token=access_token, token_type="bearer")

    def hash_password(self, password: str) -> str:
        return ph.hash(password)

    def verify_passwords(self, plain_password, hashed_password):
        try:
            ph.verify(hashed_password, plain_password)
            return True
        except VerifyMismatchError:
            return False

    def get_current_user(self,token: Annotated[str, Depends(oauth2_scheme)]):
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        try:
            payload = jwt.decode(token, settings.jwt_secret, algorithms=settings.jwt_algorithm)
            user_id: str = payload.get("sub")
            if user_id is None:
                raise credentials_exception
        except InvalidTokenError:
            raise credentials_exception
        return user_id

    def create_access_token(self, data: dict, expires_delta: timedelta | None = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, settings.jwt_secret, algorithm=settings.jwt_algorithm)
        return encoded_jwt