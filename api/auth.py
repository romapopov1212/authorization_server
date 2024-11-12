from fastapi import APIRouter
from fastapi import Depends
from fastapi.security import OAuth2PasswordRequestForm

from models.auth import Token, UserRegistration
from services.auth import AuthService

router = APIRouter(
    prefix='/auth'
)

@router.post('/sign-un', response_model=Token)
def sign_in(user_data : UserRegistration, service : AuthService = Depends()):
    return service.register(user_data)