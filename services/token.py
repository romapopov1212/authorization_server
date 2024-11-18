from datetime import datetime, timedelta
from typing import Annotated
from datetime import datetime, timedelta, timezone

from fastapi import Depends
from jose import jwt, JWTError
from jwt import ExpiredSignatureError
from sqlalchemy.orm import Session
from fastapi import HTTPException
from fastapi import status
from jwt.exceptions import InvalidTokenError
from fastapi.security import OAuth2PasswordBearer

from database import get_session
from settings import settings
import jwt
import logging

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='auth/sign-in')

class TokenService:

    def __init__(self, session: Session=Depends(get_session)):
        self.session = session

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
        except ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except InvalidTokenError:
            raise credentials_exception

        return user_id

    def create_access_token(self, data: dict, expires_delta: timedelta | None = None, refresh: bool = False):
        payload = {}
        payload['sub'] = data
        payload['exp'] = datetime.now() + (expires_delta if expires_delta is not None else timedelta(seconds=settings.jwt_expiration))
        payload['refresh'] = refresh

        token = jwt.encode(payload, key=settings.jwt_secret, algorithm=settings.jwt_algorithm)
        return token

    def decode_token(self, token:str) ->dict:
        try:
            token_data = jwt.decode(token, key=settings.jwt_secret, algorithms=[settings.jwt_algorithm])
            return token_data
        except jwt.PyJWTError as e:
            logging.exception(e)
            return None
