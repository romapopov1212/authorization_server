from fastapi import APIRouter
from fastapi import Depends

from services.token import TokenService
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
    return await service.enable_otp(user_data)



@router.post("/sign-in/verify-2fa")
async def verify_2fa_code(
        code: str,
        current_user: str = Depends(TokenService.get_current_user),
        service: TwoFactorAuthService = Depends(),
        profile_service: ProfileService = Depends(),

):
    user_data = await profile_service.get_user_by_id(current_user)
    return await service.verify_2fa_code(user_data.email, code)