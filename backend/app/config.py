from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "IdentityLens AI"
    secret_key: str = "identitylens-dev-secret-change-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 480
    database_url: str = "postgresql://identitylens:identitylens@localhost:5432/identitylens"
    openai_api_key: str = ""
    use_openai: bool = False

    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()
