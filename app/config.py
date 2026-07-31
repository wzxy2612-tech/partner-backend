from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Three connection strings for the three-role privilege model.
    owner_database_url: str = (
        "postgresql+psycopg://app_owner:owner_pw@localhost:5432/partner_backend")
    runtime_database_url: str = (
        "postgresql+psycopg://app_runtime:runtime_pw@localhost:5432/partner_backend")
    platform_database_url: str = (
        "postgresql+psycopg://app_platform:platform_pw@localhost:5432/partner_backend")


settings = Settings()
