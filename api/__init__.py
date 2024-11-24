from fastapi import APIRouter

from api.auth import router as auth_router
from api.profile import router as profile_router
from api.owner import router as owner_router
#from api.optUser import router as opt_user_router

router = APIRouter()


router.include_router(auth_router)
router.include_router(profile_router)
router.include_router(owner_router)
#router.include_router(opt_user_router)