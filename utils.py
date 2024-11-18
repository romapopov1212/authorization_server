###потом куда нибудь перенесу, тут это лежить временно
# import logging

# from sqlmodel import select
# from itsdangerous import URLSafeTimedSerializer
# from sqlmodel.ext.asyncio.session import AsyncSession


# from models.auth import User
# from settings import settings

# serializer = URLSafeTimedSerializer(
#     secret_key=settings.jwt_secret, salt="email-configuration"
# )

# def create_url_safe_token(data: dict):

#     token = serializer.dumps(data)

#     return token


# def decode_url_safe_token(token: str):
#     try:
#         token_data = serializer.loads(token)

#         return token_data

#     except Exception as e:
#         logging.error(str(e))

# def get_user_by_email(self, email: str, session: AsyncSession):
#     statement = select(User).where(User.email == email)

#     result = session.exec(statement)

#     user = result.first()

#     return user

# def update_user(self, user: User, user_data: dict, session: AsyncSession):
#     for k, v in user_data.items():
#         setattr(user, k, v)

#     session.commit()

#     return user