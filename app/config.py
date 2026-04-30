from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

load_dotenv()


class Settings(BaseSettings):
    database_url: str = Field(default="postgresql+psycopg2:///zomate_fitness_system", alias="DATABASE_URL")
    uploads_dir: Path = Field(default=Path("./uploads"), alias="UPLOADS_DIR")
    active_member_days: int = Field(default=30, alias="ACTIVE_MEMBER_DAYS")
    frontend_origin: str = Field(default="", alias="FRONTEND_ORIGIN")
    cors_allowed_origins: str = Field(default="", alias="CORS_ALLOWED_ORIGINS")
    database_sslmode: str | None = Field(default=None, alias="DATABASE_SSLMODE")
    database_ssl: str = Field(default="", alias="DATABASE_SSL")

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", populate_by_name=True)

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
