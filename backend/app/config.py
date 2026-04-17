from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Настройки приложения, загружаемые из переменных окружения."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    database_url: str

    jwt_secret_key: str
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 30

    minio_endpoint: str
    minio_access_key: str
    minio_secret_key: str
    minio_bucket_name: str
    minio_use_ssl: bool = False

    backend_cors_origins: str = "http://localhost:3000"
    backend_host: str = "0.0.0.0"
    backend_port: int = 8000
    debug: bool = False

    cookie_secure: bool = False
    cookie_samesite: str = "strict"
    csrf_allowed_origins: str = "http://localhost:3000"

    initial_admin_username: str = "admin"
    initial_admin_email: str = "admin@example.com"
    initial_admin_password: str = "admin"

    audit_log_backend: str = "clickhouse"
    clickhouse_host: str = "clickhouse"
    clickhouse_port: int = 8123
    clickhouse_database: str = "pcf"
    clickhouse_username: str = "default"
    clickhouse_password: str = ""
    clickhouse_secure: bool = False

    rabbitmq_url: str = "amqp://guest:guest@rabbitmq/"
    mail_queue_name: str = "pcf.mail"
    mail_enabled: bool = True
    smtp_host: str = "mailpit"
    smtp_port: int = 1025
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = False
    smtp_from_email: str = "noreply@example.com"
    smtp_from_name: str = "PCF"

    @field_validator("jwt_secret_key")
    @classmethod
    def validate_secret_key(cls, value: str) -> str:
        """Проверяет минимальную длину JWT-секрета."""
        if len(value) < 32:
            raise ValueError("JWT_SECRET_KEY должен содержать минимум 32 символа")
        return value

    @property
    def cors_origins(self) -> list[str]:
        """Возвращает список разрешённых CORS-источников."""
        return [origin.strip() for origin in self.backend_cors_origins.split(",") if origin.strip()]

    @property
    def csrf_origins(self) -> list[str]:
        """Возвращает список разрешённых Origin для CSRF-проверки."""
        return [origin.strip() for origin in self.csrf_allowed_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    """Возвращает кешированный объект настроек."""
    return Settings()
