from pydantic import BaseModel, EmailStr, field_validator

class OwnerRequest(BaseModel):
    owner_password: str

class OwnerGetProfile(OwnerRequest):
    email: EmailStr

class SetRoleModel(OwnerRequest):
    email: EmailStr
    role: str

    @field_validator("role")
    def validate_role(cls, v):
        allowed_roles = ["user", "admin", "owner", "partner", "customer"]
        if v not in allowed_roles:
            raise ValueError("Invalid role")
        return v

class ProfileOut(BaseModel):
    username: str
    email: str
    role: str
    is_active: bool