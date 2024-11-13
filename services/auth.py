from datetime import datetime, timedelta

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from jose import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy.orm import Session
from fastapi import HTTPException
from fastapi import status
from sqlalchemy import or_

from database import get_session
from db import tables
from models.auth import Token, User, UserRegistration
from settings import settings


oauth2_scheme = OAuth2PasswordBearer(tokenUrl='auth/sign-in')
ph = PasswordHasher()

class AuthService:

    @staticmethod
    def hash_password(password: str) -> str:
        return ph.hash(password)

    @staticmethod
    def create_token(user: tables.User) -> Token:
        user_data = User.from_orm(user)
        now = datetime.utcnow()

        payload = {
            'iat' : now,
            'nbf' : now,
            'exp' : now + timedelta(seconds=settings.jwt_expiration),
            'sub' : str(user_data.id),
            'user' : user_data.dict()
        }

        token = jwt.encode(
            payload,
            settings.jwt_secret,
            algorithm=settings.jwt_algorithm,
        )
        return Token(access_token=token)

    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    def register(self, user_data: UserRegistration) -> Token:
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
        # return self.create_token(user)

    @staticmethod
    def verify_passwords(plain_password, hashed_password):
        try:
            ph.verify(hashed_password, plain_password)
            return True
        except VerifyMismatchError:
            return False

    def authenticate_user(self, email: str, password: str) -> Token:
        user = self.session.query(tables.User).filter(tables.User.email == email).first()
        if not user or not self.verify_passwords(password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect email or password",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )
        return self.create_token(user)