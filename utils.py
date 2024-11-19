##потом куда нибудь перенесу, тут это лежит времено

from itsdangerous import URLSafeTimedSerializer



from logger import logger
from settings import settings

serializer = URLSafeTimedSerializer(
    secret_key=settings.jwt_secret, salt="email-configuration"
)

def create_url_safe_token(data: dict):

    token = serializer.dumps(data)

    return token


def decode_url_safe_token(token: str):
    try:
        token_data = serializer.loads(token)

        return token_data

    except Exception as e:
        logger.error(str(e))



