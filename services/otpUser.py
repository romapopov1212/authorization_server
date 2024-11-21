import pyotp
from auth import AuthService
from models.auth import UserRequestSchema


class UserOtpService:
    def __init__(self, authservice: AuthService):
        self.authservice = authservice


    # def generate_otp(self, payload: UserRequestSchema):
    #     otb_base32 = pyotp.random_base32()
    #     otp_auth_url = pyotp.TOTP(otb_base32).provisioning_uri(
    #         name="admin@admin.com",
    #         issuer_name="admin",
    #     )
    #     user = self.authservice.get_user_by_email(email = payload.email)
