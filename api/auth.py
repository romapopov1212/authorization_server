from fastapi import APIRouter
from fastapi import Depends

from models.auth import Token, UserRegistration, UserLogin, RefToken
from services.auth import AuthService

router = APIRouter(
    prefix='/auth'
)

@router.post('/sign-up')
def sign_up(user_data : UserRegistration, service : AuthService = Depends()):
    return service.register(user_data)


@router.post('/sign-in', response_model=RefToken)
def sign_in(user_data : UserLogin, service : AuthService = Depends()):
    return service.authenticate_user(user_data.email, user_data.password)

