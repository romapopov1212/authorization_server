from typing import Optional
from fastapi import Form
from pydantic import EmailStr, BaseModel


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

class PasswordResetRequestModel(BaseModel):
    email: str


class PasswordResetConfirmModel(BaseModel):
    new_password: str
    confirm_new_password: str


