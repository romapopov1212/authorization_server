
from typing import Annotated

from fastapi.responses import JSONResponse
from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi import status

from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from database import get_session
from models.auth import Token, PasswordResetConfirmModel
from models.auth import UserRegistration
from services.auth import AuthService
from models.auth import PasswordResetRequestModel
from models.auth import OAuth2EmailPasswordRequestForm
from services.token import RefreshTokenBearer
from services.token import TokenService
router = APIRouter(
    prefix='/auth'
)

@router.post('/sign-up')
async def sign_up(
        user_data: UserRegistration,
        service: AuthService = Depends(),
):
    return await service.register(user_data)


@router.post('/sign-in', response_model=Token)
def sign_in(
        form_data: Annotated[OAuth2EmailPasswordRequestForm, Depends()],
        service: AuthService = Depends(),
) -> Token:
    return service.authenticate_user(form_data.email, form_data.password)

@router.post('/password-reset-request')
async def password_reset_request(
        email_data:PasswordResetRequestModel,
        service: AuthService = Depends(),
):
    return await service.password_reset_request(email_data)


@router.post('/reset-password')
def reset_password(
        token,
        password: PasswordResetConfirmModel,
        service: AuthService = Depends(),
):
    return service.reset_password(token, password)

@router.get("/email-confirm")
def email_confirm(
        token,
        service: AuthService = Depends(),
):
    return service.verify_user_account(token)

@router.get("/refresh_token")
def get_new_refresh_token(
        token_detail: dict = Depends(RefreshTokenBearer()),
        service: TokenService = Depends(),
):

    expiry_timestamp = token_detail['exp']

    if datetime.fromtimestamp(expiry_timestamp) > datetime.now():
        new_access_token = service.create_access_token(
            data={
                "sub": str(token_detail['id']),
            },
        )

        return JSONResponse({'access_token': new_access_token})
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid or expired Token')

