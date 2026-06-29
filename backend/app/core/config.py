"""
MAP — Core Configuration

Pydantic Settings for environment-based configuration.
"""

from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ---------- API ----------
    app_name: str = "MAP — Malware Analysis Platform"
    app_version: str = "0.1.0"
    api_prefix: str = "/api/v1"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    debug: bool = True
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # ---------- Database ----------
    database_url: str = "postgresql+asyncpg://map_user:map_secret_password@db:5432/map_db"

    # ---------- Redis ----------
    redis_url: str = "redis://redis:6379/0"

    # ---------- Celery ----------
    celery_broker_url: str = "redis://redis:6379/0"
    celery_result_backend: str = "redis://redis:6379/1"

    # ---------- MinIO ----------
    minio_endpoint: str = "minio:9000"
    minio_root_user: str = "map_minio_admin"
    minio_root_password: str = "map_minio_secret"
    minio_bucket_samples: str = "map-samples"
    minio_use_ssl: bool = False

    # ---------- JWT ----------
    jwt_secret_key: str = "dev-secret-key-change-in-production"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 60

    # ---------- Storage ----------
    storage_path: str = "/app/storage"
    max_upload_size_mb: int = 500

    # ---------- Analysis ----------
    floss_binary_path: str = "/usr/local/bin/floss"
    volatility3_symbols_path: str = "/app/symbols"

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: str | list[str]) -> list[str]:
        if isinstance(v, str):
            import json

            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return [origin.strip() for origin in v.split(",")]
        return v

    @property
    def sync_database_url(self) -> str:
        """Return synchronous database URL for Alembic."""
        return self.database_url.replace("+asyncpg", "")


@lru_cache
def get_settings() -> Settings:
    """Cached settings instance."""
    return Settings()
