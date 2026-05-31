from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    google_client_id: str
    google_client_secret: str
    session_secret: str
    jwt_private_key_path: str
    allowed_emails_path: str

    base_url: str = "https://auth.sa6bju.se"
    issuer: str = "https://auth.sa6bju.se"
    audience: str = "sa6bju.se"
    cookie_domain: str = ".sa6bju.se"
    cookie_name: str = "sa6bju_session"
    cookie_max_age: int = 315360000  # ~10 år, i praktiken beständig


@lru_cache
def get_settings() -> Settings:
    return Settings()
