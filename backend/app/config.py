import os
import sys
import logging
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    APP_NAME: str = "NetGuard"
    APP_VERSION: str = "1.2.0"
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

    # --- 加密密钥 (用于加密存储 sudo 密码等敏感配置) ---
    # 机器绑定: ENCRYPT_KEY + /etc/machine-id → PBKDF2 → AES-256 密钥
    # 空值时首次访问自动生成并写入 .env
    ENCRYPT_KEY: str = os.getenv("ENCRYPT_KEY", "")

    # --- sudo 提权配置 ---
    # 启用后，nmap 执行 OS 识别等需要 root 权限的操作时通过 sudo 提权
    NMAP_SUDO_ENABLED: bool = os.getenv("NMAP_SUDO_ENABLED", "false").lower() == "true"

    # TCP端口扫描参数（无需root权限，全部使用 -sT）
    SCAN_CHUNK_SIZE: int = int(os.getenv("SCAN_CHUNK_SIZE", "5000"))  # 每块端口数
    SCAN_CHUNK_MAX_RETRIES: int = int(os.getenv("SCAN_CHUNK_MAX_RETRIES", "2"))  # 失败端口块最大重试次数

    # --- Top1000端口发现参数（阶段2：快速扫描已知存活主机） ---
    # 目标少（1000端口）、已确认存活，可激进超时
    SCAN_TOP_PORTS: int = int(os.getenv("SCAN_TOP_PORTS", "1000"))  # --top-ports 数量
    SCAN_TOP_HOST_TIMEOUT_SEC: int = int(os.getenv("SCAN_TOP_HOST_TIMEOUT_SEC", "60"))  # 单主机超时(秒)
    SCAN_TOP_MAX_RETRIES: int = int(os.getenv("SCAN_TOP_MAX_RETRIES", "2"))  # 重传次数
    SCAN_TOP_MIN_RATE: int = int(os.getenv("SCAN_TOP_MIN_RATE", "500"))  # 最低发包速率/秒

    # --- 全端口扫描参数（服务发现：65535端口×端口块并发） ---
    # 端口多、耗时长，需平衡速度与准确性
    SCAN_FULL_HOST_TIMEOUT_SEC: int = int(os.getenv("SCAN_FULL_HOST_TIMEOUT_SEC", "0"))  # 单主机超时(秒)，0=不超时
    SCAN_FULL_MAX_RETRIES: int = int(os.getenv("SCAN_FULL_MAX_RETRIES", "3"))  # 重传次数（全端口需更多重传）
    SCAN_FULL_MIN_RATE: int = int(os.getenv("SCAN_FULL_MIN_RATE", "300"))  # 最低发包速率/秒

    # --- RTT 超时参数（内网优化） ---
    # nmap 文档：内网 --max-rtt-timeout 100ms 合理；路由网络不超过 1000ms
    # --initial-rtt-timeout 建议为典型 RTT 的 2 倍
    # --max-rtt-timeout 建议为典型 RTT 的 3-4 倍
    SCAN_MAX_RTT_TIMEOUT_MS: int = int(os.getenv("SCAN_MAX_RTT_TIMEOUT_MS", "500"))  # --max-rtt-timeout 毫秒
    SCAN_INITIAL_RTT_TIMEOUT_MS: int = int(os.getenv("SCAN_INITIAL_RTT_TIMEOUT_MS", "200"))  # --initial-rtt-timeout 毫秒
    SCAN_MAX_SCAN_DELAY_MS: int = int(os.getenv("SCAN_MAX_SCAN_DELAY_MS", "10"))  # --max-scan-delay 毫秒（T4=10ms）

    # --- 进程级总超时 ---
    SCAN_HOST_DISCOVERY_TIMEOUT: int = int(os.getenv("SCAN_HOST_DISCOVERY_TIMEOUT", "30"))  # 主机发现单阶段超时(分钟)

    # --- 并发控制 ---
    SCAN_MAX_CONCURRENT: int = int(os.getenv("SCAN_MAX_CONCURRENT", "4"))  # 最大并发 nmap 进程数

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()

if not settings.JWT_SECRET_KEY:
    logger.critical("JWT_SECRET_KEY is not set! Refusing to start with empty secret.")
    sys.exit(1)


def ensure_encrypt_key() -> str:
    """确保 ENCRYPT_KEY 存在，不存在则自动生成并写入 .env

    Returns:
        ENCRYPT_KEY 字符串
    """
    if settings.ENCRYPT_KEY:
        return settings.ENCRYPT_KEY

    # 自动生成
    from app.utils.crypto import generate_encryption_key
    new_key = generate_encryption_key()
    settings.ENCRYPT_KEY = new_key

    # 写入 .env
    env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
    try:
        lines = []
        if os.path.exists(env_path):
            with open(env_path, "r") as f:
                lines = f.readlines()

        # 检查是否已有 ENCRYPT_KEY 行
        found = False
        for i, line in enumerate(lines):
            if line.strip().startswith("ENCRYPT_KEY="):
                lines[i] = f"ENCRYPT_KEY={new_key}\n"
                found = True
                break

        if not found:
            # 在文件末尾追加
            if lines and not lines[-1].endswith("\n"):
                lines[-1] += "\n"
            lines.append(f"ENCRYPT_KEY={new_key}\n")

        with open(env_path, "w") as f:
            f.writelines(lines)

        logger.info("ENCRYPT_KEY 已自动生成并写入 .env")
    except Exception as e:
        logger.warning(f"无法写入 ENCRYPT_KEY 到 .env: {e}，请手动设置")

    return new_key
