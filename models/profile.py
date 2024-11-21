from pydantic import BaseModel, EmailStr, field_validator

from models.auth import PasswordValidator

class ToChangeData(BaseModel):
    password: str

class ToChangeEmail(ToChangeData):
    new_email: EmailStr

class ToChangeUsername(BaseModel):
    new_username: str

class ToChangePassword(ToChangeData):
    new_password: str

    @field_validator("new_password")
    def password_complexity(cls, v):
        return PasswordValidator.validate_password(v)

class ProfileOut(BaseModel):
    username: str
    email: str