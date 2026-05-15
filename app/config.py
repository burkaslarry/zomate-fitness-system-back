"""[F007][S004]
Feature: Backend platform (FastAPI & PostgreSQL)
Step: (see Logic)
Logic: Pydantic-settings: DATABASE_URL, CORS, keepalive, logging, uploads.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

load_dotenv()


def _default_database_url() -> str:
    return os.environ.get("DATABASE_URL") or "postgresql+psycopg2:///zomate_fitness_system"


class Settings(BaseSettings):
    database_url: str = Field(default_factory=_default_database_url, alias="DATABASE_URL")
    strict_database_url: bool = Field(default=False, alias="STRICT_DATABASE_URL")
    uploads_dir: Path = Field(default=Path("./uploads"), alias="UPLOADS_DIR")
    active_member_days: int = Field(default=30, alias="ACTIVE_MEMBER_DAYS")
    frontend_origin: str = Field(default="", alias="FRONTEND_ORIGIN")
    cors_allowed_origins: str = Field(default="", alias="CORS_ALLOWED_ORIGINS")
    database_sslmode: str | None = Field(default=None, alias="DATABASE_SSLMODE")
    database_ssl: str = Field(default="", alias="DATABASE_SSL")
    public_base_url: str = Field(default="", alias="PUBLIC_BASE_URL")
    keepalive_enabled: bool = Field(default=False, alias="KEEPALIVE_ENABLED")
    keepalive_interval_seconds: int = Field(default=600, alias="KEEPALIVE_INTERVAL_SECONDS")
    keepalive_timeout_seconds: float = Field(default=5.0, alias="KEEPALIVE_TIMEOUT_SECONDS")
    keepalive_jitter_seconds: float = Field(default=30.0, alias="KEEPALIVE_JITTER_SECONDS")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", populate_by_name=True)

    @model_validator(mode="after")
    def _validate_database_url(self) -> Settings:
        if self.strict_database_url:
            raw = os.environ.get("DATABASE_URL", "").strip()
            if not raw:
                raise ValueError("DATABASE_URL must be set in the environment when STRICT_DATABASE_URL=1")
        return self

    @property
    def cors_origins(self) -> list[str]:
        raw = self.frontend_origin or self.cors_allowed_origins
        defaults = [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:3001",
            "http://127.0.0.1:3001",
            "https://zomate-fitness-system-front.vercel.app",
        ]
        if not raw.strip():
            return defaults
        parsed = [item.strip() for item in raw.split(",") if item.strip()]
        return parsed or defaults


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
