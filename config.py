from pathlib import Path

from pydantic import RedisDsn
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Режим отладки
    debug: bool = False

    # Сеть
    app_host: str = "127.0.0.1"
    app_port: int = 5001

    # Redis (автоматически проверит, что это валидный URL)
    redis_url: RedisDsn
    key_prefix: str = "sihatod:"

    # Пути к секретам (по умолчанию /run/secrets, но можно переопределить через ENV)
    secrets_dir: Path = Path("/run/secrets")

    # Безопасность
    algorithm: str = "EdDSA"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # Настройки загрузки (.env файл имеет приоритет)
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    @property
    def certs_path(self) -> Path:
        """Хелпер для быстрого доступа к сертификатам"""
        return self.secrets_dir


# Глобальный объект настроек
settings = Settings()
