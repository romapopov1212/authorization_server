from typing import Optional

from pydantic import EmailStr, BaseModel


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
    type_token: str = 'bearer'

class RefToken(Token):
    refresh_token: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str