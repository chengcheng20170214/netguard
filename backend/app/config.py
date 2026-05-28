import os
import sys
import logging
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    APP_NAME: str = "NetGuard"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./netguard.db"

    # JWT
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "")
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

    # SYN full-port scan tuning (防中断、防遗漏)
    SCAN_CHUNK_SIZE: int = int(os.getenv("SCAN_CHUNK_SIZE", "5000"))  # 每块端口数
    SCAN_MAX_RETRIES: int = int(os.getenv("SCAN_MAX_RETRIES", "6"))   # 最大重传次数
    SCAN_MIN_RATE: int = int(os.getenv("SCAN_MIN_RATE", "300"))       # 最低发包速率/秒
    SCAN_HOST_TIMEOUT_MIN: int = int(os.getenv("SCAN_HOST_TIMEOUT_MIN", "60"))  # 单主机超时(分钟)
    SCAN_CHUNK_MAX_RETRIES: int = int(os.getenv("SCAN_CHUNK_MAX_RETRIES", "3"))  # 失败块最大重试次数

    # 并发控制
    SCAN_MAX_CONCURRENT: int = int(os.getenv("SCAN_MAX_CONCURRENT", "4"))  # 最大并发 nmap 进程数
    SCAN_HOST_DISCOVERY_TIMEOUT: int = int(os.getenv("SCAN_HOST_DISCOVERY_TIMEOUT", "30"))  # 主机发现单阶段超时(分钟)

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()

if not settings.JWT_SECRET_KEY:
    logger.critical("JWT_SECRET_KEY is not set! Refusing to start with empty secret.")
    sys.exit(1)
