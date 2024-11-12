from pydantic import BaseSettings


class Settings(BaseSettings):
    database_url: str
    jwt_secret: str
    jwt_algorithm: str = 'HS256'
    jwt_expiration = 3600

settings = Settings(
    _env_file='.env',
    _env_file_encoding='utf-8',

)