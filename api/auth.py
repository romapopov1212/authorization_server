from typing import Annotated

from fastapi import APIRouter
from fastapi import Depends

from models.auth import Token, PasswordResetConfirmModel
from models.auth import UserRegistration
from services.auth import AuthService
from models.auth import PasswordResetRequestModel
from models.auth import OAuth2EmailPasswordRequestForm


router = APIRouter(
    prefix='/auth'
)

@router.post('/sign-up')
async def sign_up(
        user_data : UserRegistration,
        service : AuthService = Depends(),
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


@router.post('/reset-password/{token}')
def reset_password(
        token,
        password: PasswordResetConfirmModel,
        service: AuthService = Depends(),
):
    return service.reset_password(token, password)

@router.get("/email_confirm/{token}")
def email_confirm(
        token,
        service: AuthService = Depends(),
):
    return service.verify_user_account(token)