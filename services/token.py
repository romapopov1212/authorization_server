from datetime import datetime, timedelta
from typing import Annotated

from fastapi import Depends
from jose import jwt, JWTError
from jwt import ExpiredSignatureError
from sqlalchemy.orm import Session
from fastapi import HTTPException
from fastapi import status
from jwt.exceptions import InvalidTokenError
from fastapi.security import OAuth2PasswordBearer

from database import get_session
from db import tables
from models.auth import User, Token
from settings import settings


oauth2_scheme = OAuth2PasswordBearer(tokenUrl='auth/sign-in')

class TokenService:

    def __init__(self, session: Session=Depends(get_session)):
        self.session = session

    def create_refresh_token(self, user: tables.User) -> str:
        user_data = User.from_orm(user)
        now = datetime.utcnow()
        payload = {
            'iat': now,
            'nbf': now,
            'exp': now + timedelta(seconds=settings.refresh_token_expire),
            'sub': str(user_data.id),

        }

        refresh_token = jwt.encode(
            payload,
            settings.jwt_secret,
            algorithm=settings.jwt_algorithm,
        )
        return refresh_token

    @staticmethod
    def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
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

    def refresh_token(self, refresh_token: str):
        try:
            payload = jwt.decode(refresh_token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
            user_id: str = payload.get('sub')
            if user_id is None:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token.')

            user = self.session.query(tables.User).get(user_id)
            if user is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found.')

            new_access_token = self.create_access_token(user)
            return Token(access_token=new_access_token)
        except ExpiredSignatureError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Expired token.')
        except JWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token.')
