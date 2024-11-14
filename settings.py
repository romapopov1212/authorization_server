from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str
    jwt_secret: str
    jwt_algorithm: str = 'HS256'
    jwt_expiration: int = 3600
    refresh_token_expire: int = 8640 *7 # неделя

    class Config:
        env_file = '.env'
        env_file_encoding = 'utf-8'

settings = Settings(

)