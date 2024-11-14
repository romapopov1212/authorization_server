from fastapi import APIRouter
from fastapi import Depends

from sqlalchemy.orm import Session

from services.token import TokenService
from database import get_session
from models.auth import Token

router = APIRouter(
    prefix="/auth",
)

@router.post("/token", response_model=Token)
def refresh(token: str, service: TokenService = Depends()):
    return service.refresh_token(token)