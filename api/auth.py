from fastapi import APIRouter
from fastapi import Depends

from models.auth import Token, UserRegistration
from services.auth import AuthService

router = APIRouter(
    prefix='/auth'
)

@router.post('/sign-up', response_model=Token)
def sign_up(user_data : UserRegistration, service : AuthService = Depends()):
    return service.register(user_data)