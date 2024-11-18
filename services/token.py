from datetime import datetime, timedelta
from typing import Annotated
from datetime import datetime, timedelta, timezone

import jwt
import logging
from jwt import ExpiredSignatureError
from sqlalchemy.orm import Session
from fastapi import HTTPException, Security, Depends, status
from jwt.exceptions import InvalidTokenError
from fastapi.security import HTTPBearer

from database import get_session
from settings import settings

http_bearer = HTTPBearer(auto_error=False)

class TokenService:

    def __init__(self, session: Session=Depends(get_session)):
        self.session = session

    @staticmethod
    def get_current_user(credentials=Depends(http_bearer)):
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token = credentials.credentials
        try:
            payload = jwt.decode(token, key=settings.jwt_secret, algorithms=settings.jwt_algorithm)
            user_id: str = payload.get("sub")
            if user_id is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token",
                )
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
            )
        except jwt.PyJWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )
        return user_id

    # def create_access_token(self, data: dict, expires_delta: timedelta | None = None, refresh: bool = False):
    #     payload = {}
    #     payload['sub'] = data
    #     payload['exp'] = datetime.now() + (expires_delta if expires_delta is not None else timedelta(seconds=settings.jwt_expiration))
    #     payload['refresh'] = refresh
    #
    #     token = jwt.encode(payload, key=settings.jwt_secret, algorithm=settings.jwt_algorithm)
    #     return token

    def create_access_token(self, data: dict, expires_delta: timedelta | None = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, settings.jwt_secret, algorithm=settings.jwt_algorithm)
        return encoded_jwt

    def decode_token(self, token:str) ->dict:
        try:
            token_data = jwt.decode(token, key=settings.jwt_secret, algorithms=[settings.jwt_algorithm])
            return token_data
        except jwt.PyJWTError as e:
            logging.exception(e)
            return None

# class AccessTokenBearer(TokenService):
#     def verify_token(self, token_data: dict) -> None:
#         if token_data and token_data['refresh']:
#             raise HTTPException(
#                 status_code=status.HTTP_403_FORBIDDEN,
#                 detail="Please provide an access token",
#             )
#
# class RefreshTokenBearer(TokenService):
#     def verify_token(self, token_data: dict) -> None:
#         if token_data and not token_data['refresh']:
#             raise HTTPException(
#                 status_code=status.HTTP_403_FORBIDDEN,
#                 detail="Please provide a refresh token",
#            )