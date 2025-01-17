from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    # Configurações JWT
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Configurações de Banco de Dados
    DATABASE_URL: str = "sqlite:///usuarios.db"

    # Configurações Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Configurações de Ambiente
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"

    # Configurações ViaCEP
    VIACEP_BASE_URL: str = "https://viacep.com.br/ws"
    VIACEP_TIMEOUT_SECONDS: int = 5

    # Configurações Rate Limiting
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_MINUTES: int = 1

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()