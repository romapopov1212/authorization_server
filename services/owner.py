from fastapi import HTTPException, Depends, status 
from sqlalchemy.orm import Session  

from db import tables
from database import get_session
from settings import settings
from models.owner import SetRoleModel

def owner_check(password):
    if password != settings.OWNER_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect password",
            headers={
                'WWW-Authenticate': 'Bearer'
            },
        )

class OwnerService():

    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    def get_user_by_email(
            self,
            email: str
    ):
        user = self.session.query(tables.User).filter(tables.User.email == email).first()
        return user

    def update_user(
            self,
            user: tables.User,
            user_data: dict
    ):
        for k, v in user_data.items():
            setattr(user, k, v)

        self.session.commit()
        return user

    def get_profile(self, email):
        user = self.get_user_by_email(email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )
        return user

    def get_users(self):
        users = self.session.query(tables.User).all()
        if not users:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Users not found",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )
        return users
 
    def set_role(self, data: SetRoleModel):
        if data.owner_password != settings.OWNER_PASSWORD:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect password",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )
        user = self.get_user_by_email(data.email)
        self.update_user(user, {"role": data.role})
        return user

    def delete_user(self, email):
        user = self.get_user_by_email(email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )
        self.session.delete(user)
        self.session.commit()
        return

    
