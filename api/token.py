from fastapi import APIRouter
from fastapi import Depends


from services.token import TokenService
from models.auth import Token

router = APIRouter(
    prefix="/auth",
)

@router.post("/token", response_model=Token)
def refresh(token: str, service: TokenService = Depends()):
    return service.refresh_token(token)