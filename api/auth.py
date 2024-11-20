from typing import Annotated

from fastapi import APIRouter, status
from fastapi import Depends
from starlette.responses import JSONResponse
from celery_tasks import send_email
from models.auth import Token, PasswordResetConfirmModel

from logger import logger
from models.auth import UserRegistration
from services.auth import AuthService
from models.auth import PasswordResetRequestModel
from models.auth import OAuth2EmailPasswordRequestForm
from utils import create_url_safe_token

router = APIRouter(
    prefix='/auth'
)

@router.post('/sign-up')
def sign_up(user_data: UserRegistration, service: AuthService = Depends()):
    service.register(user_data)

@router.patch('/email_confirm/{token}')
def confirm_email(token: str, service: AuthService = Depends()):
    return service.activate_user(token)

@router.post('/sign-in', response_model=Token)
def sign_in(
        form_data: Annotated[OAuth2EmailPasswordRequestForm, Depends()],
        service: AuthService = Depends(),
) -> Token:
    return service.authenticate_user(form_data.email, form_data.password)

#пока не получилось перенести реализацию в сервисы, скоро это сделаю
@router.post('/password-reset-request')
async def password_reset_request(
        email_data:PasswordResetRequestModel,
        #service: AuthService = Depends(),
):
    email = email_data.email
    token = create_url_safe_token({"email": email})
    link = f"http://localhost/auth/reset-password?token={token}"
    html_message = f'Инструкция для сброса пароля: <p>{link}</p>'
    subject = "Reset Your Password"
    await send_email([email], subject, html_message)
    logger.info(f"Successful reset password for user {email}")
    return JSONResponse(
        content = {
            "message": "На вашу почту отправлена инструкция для сброса пароля",
        },
        status_code = status.HTTP_200_OK,
    )

@router.post('/reset-password/{token}')
def reset_password(
        token,
        password: PasswordResetConfirmModel,
        service: AuthService = Depends(),
):
    return service.reset_password(token, password)
