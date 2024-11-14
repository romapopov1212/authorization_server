from fastapi import APIRouter

from api.auth import router as auth_router
from api.token import router as token_router
from api.profile import router as profile_router


router = APIRouter()


router.include_router(auth_router)
router.include_router(token_router)
router.include_router(profile_router)