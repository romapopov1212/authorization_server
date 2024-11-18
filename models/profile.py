from pydantic import BaseModel, EmailStr

class ToChangeData(BaseModel):
    password: str

class ToChangeEmail(ToChangeData):
    new_email: EmailStr

class ToChangeUsername(BaseModel):
    new_username: str

class ToChangePassword(ToChangeData):
    new_password: str

class ProfileOut(BaseModel):
    username: str
    email: str