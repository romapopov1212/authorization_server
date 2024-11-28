from fastapi import APIRouter
from fastapi import Depends
from services.token import TokenService
from models.auth import UserTwoFa
from services.profile import ProfileService
from services.twoFactorAuth import TwoFactorAuthService


router = APIRouter()


@router.post("/enable_twoFactorAuth")
async def enable_topt(
        current_user: str = Depends(TokenService.get_current_user),
        service: TwoFactorAuthService = Depends(),
        profile_service: ProfileService = Depends()

):
    user_data = await profile_service.get_user_by_id(current_user)
    return service.enable_otp(user_data)