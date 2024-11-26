from fastapi import HTTPException, Depends, status 
from sqlalchemy.orm import Session
from sqlalchemy.future import select

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


    async def set_role(self, data: SetRoleModel):
        if data.owner_password != settings.OWNER_PASSWORD:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect password",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )
        user = await self.get_user_by_email(data.email)
        await self.update_user(user, {"role": data.role})
        return user


    async def get_user_by_email(
            self,
            email: str
    ):
        stmt = select(tables.User).filter(tables.User.email == email)
        result = await self.session.execute(stmt)
        user = result.scalars().first()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )
        return user


    async def get_users(self):
        stmt = select(tables.User)
        result = await self.session.execute(stmt)
        users = result.scalars().all()

        if not users:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Users not found",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )
        return users
 

    async def delete_user(self, email):
        user = await self.get_user_by_email(email)

        await self.session.delete(user)
        await self.session.commit()
        return


    async def update_user(
            self,
            user: tables.User,
            user_data: dict
    ):
        for k, v in user_data.items():
            setattr(user, k, v)

        await self.session.commit()
        return user
    
