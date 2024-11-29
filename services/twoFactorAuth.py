import pyotp
import qrcode
from fastapi import Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from fastapi import status
from sqlalchemy.future import select

from services.token import TokenService as TS
from models.auth import UserTwoFa
from database import get_session
from db.tables import User
from logger import logger


class TwoFactorAuthService:

    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    async def enable_otp(self, user_data: UserTwoFa):
        if user_data.is_2fa is False:
            secret = pyotp.random_base32()
            user_data.secret = secret
            uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user_data.username, issuer_name="App")
            qrcode.make(uri).save(f"{user_data.username}_qrcode.png")
            user_data.is_2fa = True
            self.session.add(user_data)
            await self.session.commit()
            logger.info({
                "action": "enable 2fa",
                "status": "success",
                "user_data": f"email: {user_data.email}",
                "message": "Enable 2fa successfully"
            })
            return JSONResponse(
                content={"message": "Qr created successfully"},
                status_code=status.HTTP_200_OK,
            )
        else:
            logger.error({
                "action": "enable 2fa",
                "status": "failed",
                "user_data": f"email: {user_data.email}",
                "message": "2fa is already enabled"
            })
            return JSONResponse(
                content={"message": "Failed! 2fa is already enabled"},
                status_code=status.HTTP_400_BAD_REQUEST,

            )

    async def verify_2fa_code(self, email: str, code: str):
        stmt = select(User).where(User.email == email)
        result = await self.session.execute(stmt)
        user = result.scalars().first()

        if not user:
            logger.error({
                "action": "verify 2fa",
                "status": "failed",
                "user_data": f"email: {user.email}",
                "message": "User not found"
            })
            return JSONResponse(
                content={"message": "User not found"},
                status_code=status.HTTP_404_NOT_FOUND,
            )

        totp = pyotp.TOTP(user.secret)
        if totp.verify(code):
            logger.info({
                "action": "verify 2fa",
                "status": "success",
                "user_data": f"email: {user.email}",
                "message": "2FA verification succeeded"
            })
            return JSONResponse(
                content={"message": "2FA verification succeeded"},
                status_code=status.HTTP_200_OK,
            )
        else:
            logger.error({
                "action": "verify 2fa",
                "status": "failed",
                "user_data": f"email: {user.email}",
                "message": "Invalid 2fa code"
            })
            return JSONResponse(
                content={"message": "Invalid 2FA code"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )




