import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "NetGuard"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./netguard.db"

    # JWT
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "netguard-secret-change-in-production")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Redis / Celery
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    CELERY_BROKER_URL: str = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
    CELERY_RESULT_BACKEND: str = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")

    # NVD API
    NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Scanner paths
    NMAP_PATH: str = os.getenv("NMAP_PATH", "/usr/bin/nmap")
    MASSCAN_PATH: str = os.getenv("MASSCAN_PATH", "/usr/bin/masscan")
    FPING_PATH: str = os.getenv("FPING_PATH", "/usr/bin/fping")

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()
