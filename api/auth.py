from typing import Annotated
from fastapi.security import OAuth2PasswordRequestForm

from fastapi import APIRouter, status
from fastapi import Depends
from starlette.responses import JSONResponse

from models.auth import Token, PasswordResetConfirmModel

from utils import create_url_safe_token
from models.auth import UserRegistration
from services.auth import AuthService
from models.auth import PasswordResetRequestModel
router = APIRouter(
    prefix='/auth'
)

@router.post('/sign-up')
def sign_up(
        user_data : UserRegistration,
        service : AuthService = Depends(),
):
    return service.register(user_data)


@router.post('/sign-in', response_model=Token)
def sign_in(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
        service: AuthService = Depends(),
) -> Token:
    return service.authenticate_user(form_data.username, form_data.password)

###############тоже пока в процессе
@router.post('/password-reset-request')
def password_reset_request(
        email_data:PasswordResetRequestModel,
        service: AuthService = Depends(),
):
    email = email_data.email
    token = create_url_safe_token({"email": email})
    link = f"http://localhost/auth/reset-password?token={token}"
    html_message = f'<p>{link}</p>'
    subject = "Reset Your Password"

    return JSONResponse(
        content = {
            "message": "На вашу почту отправлена инструкция для смены пароля",
        },
        status_code = status.HTTP_200_OK,
    )

@router.post('/reset-password/{token}')
def reset_password(
        token,
        password: PasswordResetConfirmModel,
        service: AuthService = Depends(),
):
    pass
############################################