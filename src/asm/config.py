"""Centralized config. All secrets and environment-dependent values flow through here."""
from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # Application
    app_env: str = Field(default="development")
    log_level: str = Field(default="INFO")
    api_key: str = Field(...)  # required — fail fast if missing

    # Storage
    database_url: str = Field(...)
    mlflow_tracking_uri: str = Field(default="http://localhost:5000")

    # External feeds
    nvd_api_key: str | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
