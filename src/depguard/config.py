"""Environment-driven application settings."""

from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Validated runtime configuration loaded from environment variables."""

    model_config = SettingsConfigDict(env_prefix="DEPGUARD_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./depguard.db"
    secret_key: str = Field(default_factory=lambda: secrets.token_urlsafe(48), min_length=32)
    cookie_secure: bool = False
    allow_private_targets: bool = False
    cache_path: Path = Path.home() / ".cache" / "depguard" / "cache.sqlite3"
    cache_ttl_seconds: int = Field(default=86_400, ge=60, le=31_536_000)
    request_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_manifest_bytes: int = Field(default=2_000_000, ge=1_024, le=20_000_000)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide validated settings instance."""
    return Settings()
