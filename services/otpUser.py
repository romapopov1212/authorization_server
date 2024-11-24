# import pyotp
#
# from database import get_session
#
# from services.auth import AuthService
# from models.auth import UserRequestSchema
# from models.auth import Otp
# from fastapi import APIRouter, status, HTTPException, Depends
# from sqlalchemy.orm import Session
#
# class UserOtpService:
#     def __init__(self, authservice: AuthService = Depends(), session: Session = Depends(get_session)):
#         self.authservice = authservice
#         self.session = session
#
#     def generate_otp(self, payload: UserRequestSchema):
#         otp_base32 = pyotp.random_base32()
#         otp_auth_url = pyotp.TOTP(otp_base32).provisioning_uri(
#             name="admin@admin.com",
#             issuer_name="admin",
#         )
#         user = Otp.find_one_and_update(
#             {"_id" : str(payload.user_id)},
#             {'$set': {"otp_auth_url": otp_auth_url, "otp_base32": otp_base32}},
#
#         )
#         if not user:
#             raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
#                                 detail=f'No user with this id: {payload.user_id} found')
#         return {'base32': otp_base32, "otpauth_url": otp_auth_url}
#
#
#     # def generate_otp(self, payload: UserRequestSchema):
#     #     otp_base32 = pyotp.random_base32()
#     #     otp_auth_url = pyotp.totp.TOTP(otp_base32).provisioning_uri(
#     #         name="admin@admin.com", issuer_name="codevoweb.com"
#     #     )
#     #
#     #     user = self.session.query(Otp).filter(Otp.id == payload.user_id).first()
#     #     if not user:
#     #         raise HTTPException(
#     #             status_code=status.HTTP_404_NOT_FOUND,
#     #             detail=f'Пользователь с ID {payload.user_id} не найден'
#     #         )
#     #
#     #
#     #     user.otp_auth_url = otp_auth_url
#     #     user.otp_base32 = otp_base32
#     #     self.session.commit()
#     #     self.session.refresh(user)
#     #
#     #     return {"base32": otp_base32, "otpauth_url": otp_auth_url}