#добавить логи
import pyotp
import qrcode
from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_session
from services.token import TokenService as TS
from models.auth import UserTwoFa
from settings import settings
from fastapi.responses import JSONResponse
from fastapi import status
from db.tables import User
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession

class TwoFactorAuthService:

    def __init__(self, session: Session = Depends(get_session), token_service: TS = Depends()):
        self.session = session
        self.token_service = token_service

    async def enable_otp(self, user_data: UserTwoFa):
        if user_data.is_2fa is False:
            secret = pyotp.random_base32()
            user_data.secret = secret
            uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user_data.username, issuer_name="App")
            qrcode.make(uri).save(f"{user_data.username}_qrcode.png")
            user_data.is_2fa = True
            self.session.add(user_data)
            await self.session.commit()
            return JSONResponse(
                content={"message": "Qr created successfully"},
                status_code=status.HTTP_200_OK,
            )
        else:
            return JSONResponse(
                content={"message": "Failed! 2fa is already enabled"},
                status_code=status.HTTP_400_BAD_REQUEST,

            )

    async def verify_2fa_code(self, email: str, code: str):
        stmt = select(User).where(User.email == email)
        result = await self.session.execute(stmt)
        user = result.scalars().first()

        if not user:
            return JSONResponse(
                content={"message": "User not found"},
                status_code=status.HTTP_404_NOT_FOUND,
            )

        totp = pyotp.TOTP(user.secret)
        if totp.verify(code):
            return JSONResponse(
                content={"message": "2FA verification succeeded"},
                status_code=status.HTTP_200_OK,
            )
        else:
            return JSONResponse(
                content={"message": "Invalid 2FA code"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )




