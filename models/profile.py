from pydantic import BaseModel

class ToChangeData(BaseModel):
    password: str

class ToChangeEmail(ToChangeData):
    new_email: str

class ToChangeUsername(BaseModel):
    new_username: str

class ToChangePassword(ToChangeData):
    new_password: str

class ProfileOut(BaseModel):
    username: str
    email: str