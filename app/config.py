from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SentinelRAG"
    app_mode: str = "demo"
    openai_api_key: str | None = None
    openai_model: str = "gpt-6-astra"
    openai_embedding_model: str = "text-embedding-3-small"
    database_path: Path = Path("security_analyst.db")
    log_level: str = "INFO"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
