from fastapi import APIRouter
from fastapi import Depends

from models.owner import ProfileOut, SetRoleModel, OwnerGetProfile, OwnerRequest
from services.owner import OwnerService, owner_check


router = APIRouter(
    prefix='/owner'
)

@router.patch("/set-role")
def set_role(
    data: SetRoleModel,
    service: OwnerService = Depends(),
):
    owner_check(data.owner_password)
    return service.set_role(data)

@router.get("/get-profile", response_model=ProfileOut)
def get_profile(
    owner_password: str,
    user_email: str,
    service: OwnerService = Depends(),
):  
    owner_check(owner_password)
    return service.get_profile(user_email)

@router.get("/get-profiles", response_model=list[ProfileOut])
def get_profiles(
    owner_password: str,
    service: OwnerService = Depends(),
):
    owner_check(owner_password)
    return service.get_users()

@router.delete("/delete-user")
def delete_user(
    data: OwnerGetProfile,
    service: OwnerService = Depends(),
):
    owner_check(data.owner_password)
    return service.delete_user(data.email)