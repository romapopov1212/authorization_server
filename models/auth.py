from typing import Optional

from pydantic import BaseModel

class BaseUser(BaseModel):
    email: str
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