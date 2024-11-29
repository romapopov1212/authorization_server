#добавить логи
import pyotp
import qrcode
from fastapi import Depends
from sqlalchemy.orm import Session
from database import get_session
from services.token import TokenService as TS
from models.auth import UserTwoFa
from settings import settings
from fastapi.responses import JSONResponse
from fastapi import status


class TwoFactorAuthService:

    def __init__(self, session: Session = Depends(get_session), token_service: TS = Depends()):
        self.session = session
        self.token_service = token_service

    async def enable_otp(self, user_data: UserTwoFa, ):
        if user_data.is_2fa is False:
            uri = pyotp.totp.TOTP(settings.TOTP_SECRET).provisioning_uri(name=user_data.username,
                                                                         issuer_name="App")
            qrcode.make(uri).save("qrcode.png")
            user_data.is_2fa = True
            self.session.add(user_data)
            await self.session.commit()
            return JSONResponse(
                content={
                    "message": "Qr created successfully",
                },
                status_code=status.HTTP_200_OK,
            )
        else:
            return JSONResponse(
                content={
                    "message": "Failed! 2fa is already enabled",
                },
                status_code=status.HTTP_401_UNAUTHORIZED,
            )