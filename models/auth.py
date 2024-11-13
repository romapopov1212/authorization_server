from typing import Optional

from pydantic import BaseModel, EmailStr

class BaseUser(BaseModel):
    email: EmailStr
    username: str

class UserRegistration(BaseUser):
    password: str

class User(BaseUser):
    id: Optional[int] = None

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    type_token: str = 'bearer'

class UserLogin(BaseModel):
    email: EmailStr
    password: str