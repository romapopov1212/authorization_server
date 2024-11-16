from fastapi import APIRouter
from fastapi import Depends

from models.profile import ProfileOut, ToChangeEmail, ToChangePassword, ToChangeUsername
from services.profile import ProfileService
from services.token import TokenService


router = APIRouter(
    prefix='/profile'
)

@router.get('/', response_model = ProfileOut)
def _get_profile(
    current_user: str = Depends(TokenService.get_current_user),
    service : ProfileService = Depends()
):
    return service.get_profile(current_user)

@router.patch('/change_password')
def _change_password(
    data:  ToChangePassword,
    current_user: str = Depends(TokenService.get_current_user),
    service : ProfileService = Depends()
):
    service.change_password(current_user, data)

@router.patch('/change_email')
def _change_email(
    data: ToChangeEmail,
    current_user: str = Depends(TokenService.get_current_user),
    service : ProfileService = Depends()
):
    service.change_email(current_user, data)

@router.patch('/change_username')
def _change_username(
    data: ToChangeUsername,
    current_user: str = Depends(TokenService.get_current_user),
    service : ProfileService = Depends()
):
    service.change_username(current_user, data)