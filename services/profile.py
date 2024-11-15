from fastapi import Depends
from argon2.exceptions import VerifyMismatchError
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from services.auth import ph

from database import get_session
from db import tables

class ProfileService:

    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    def get_profile(self, user_id):
        user = self.session.query(
            tables.User.username,
            tables.User.email
        ).filter_by(id=user_id).first()
        return {"username": user.username, "email": user.email}

    def change_email(self, user_id, data):
        user = self.session.query(tables.User).filter_by(id=user_id).first()
        if not self.verify_passwords(data.password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect password",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )
        user.email = data.new_email
        self.session.commit()
        return

    def change_username(self, user_id, data):
        user = self.session.query(tables.User).filter_by(id=user_id).first()
        user.username = data.new_username
        self.session.commit()
        return

    def change_password(self, user_id, data):
        user = self.session.query(tables.User).filter_by(id=user_id).first()
        if not self.verify_passwords(data.password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect password",
                headers={
                    'WWW-Authenticate': 'Bearer'
                },
            )
        user.password_hash = self.hash_password(data.new_password)
        self.session.commit()
        return

    def verify_passwords(self, plain_password, hashed_password):
        try:
            ph.verify(hashed_password, plain_password)
            return True
        except VerifyMismatchError:
            return False

    def hash_password(self, password: str) -> str:
        return ph.hash(password)