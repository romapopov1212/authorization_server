from typing import Annotated
from fastapi.security import OAuth2PasswordRequestForm

from fastapi import APIRouter
from fastapi import Depends
from models.auth import Token

from models.auth import UserRegistration
from services.auth import ProfileService

router = APIRouter(
    prefix='/auth'
)

@router.post('/sign-up')
def sign_up(user_data : UserRegistration, service : ProfileService = Depends()):
    return service.register(user_data)


@router.post('/sign-in', response_model=Token)
def sign_in(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], service: ProfileService = Depends()
) -> Token:
    return service.authenticate_user(form_data.username, form_data.password)

