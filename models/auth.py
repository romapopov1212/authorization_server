from __future__ import annotations
from typing import Optional
from fastapi import Form
from pydantic import EmailStr, BaseModel, field_validator


class OAuth2EmailPasswordRequestForm:
    def __init__(
        self,
        email: str = Form(...),
        password: str = Form(...),
    ):
        self.email = email
        self.password = password

class BaseUser(BaseModel):
    email: EmailStr
    username: str

class UserRegistration(BaseUser):
    password: str

    @field_validator("password")
    def password_complexity(cls, v):
        return PasswordValidator.validate_password(v)

class User(BaseUser):
    id: Optional[int] = None

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    refresh_token: str
    type_token: str = 'bearer'

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Otp(BaseUser):
    otp_enabled: bool = False
    otp_verified: bool = False

    otp_base32: str | None = None
    otp_auth_url: str | None = None

class PasswordResetRequestModel(BaseModel):
    email: str


class PasswordResetConfirmModel(BaseModel):
    new_password: str
    confirm_new_password: str

    @field_validator("new_password")
    def password_complexity(cls, v):
        return PasswordValidator.validate_password(v)

class UserRequestSchema(BaseModel):
    user_id: str
    token: str | None = None

class PasswordValidator:
    @staticmethod
    def validate_password(v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password should be at least 8 characters long")
        if not any(char.isdigit() for char in v):
            raise ValueError("Password should contain at least one number")
        if not any(char.isupper() for char in v):
            raise ValueError("Password should contain at least one capital letter")
        if not any(char.islower() for char in v):
            raise ValueError("Password should contain at least one small letter")
        if not any(char in '!@#$%^&*()_+-=' for char in v):
            raise ValueError("Password should contain at least one special character")
        return v