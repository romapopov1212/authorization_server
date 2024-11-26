from fastapi import APIRouter
from fastapi import Depends

from models.profile import ProfileOut, ToChangeEmail, ToChangePassword, ToChangeUsername
from services.profile import ProfileService
from services.token import TokenService


router = APIRouter(
    prefix='/profile'
)

@router.get('/', response_model = ProfileOut)
async def get_profile(
    current_user: str = Depends(TokenService.get_current_user),
    service : ProfileService = Depends()
):
    user = await service.get_user_by_id(current_user)
    return ProfileOut(username=user.username, email=user.email)

@router.patch('/change-password')
async def change_password(
    data:  ToChangePassword,
    current_user: str = Depends(TokenService.get_current_user),
    service : ProfileService = Depends()
):
    await service.change_password(current_user, data)

@router.patch('/change-email')
async def change_email(
    data: ToChangeEmail,
    current_user: str = Depends(TokenService.get_current_user),
    service : ProfileService = Depends()
):
    await service.change_email(current_user, data)

@router.patch('/change-username')
async def change_username(
    data: ToChangeUsername,
    current_user: str = Depends(TokenService.get_current_user),
    service : ProfileService = Depends()
):
    await service.change_username(current_user, data)

