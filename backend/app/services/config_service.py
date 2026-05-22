from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.models import SystemConfig
from app.config import settings
from datetime import datetime, timezone

CONFIG_DEFAULTS = {
    "database_url": {"value": "sqlite+aiosqlite:///./netguard.db", "description": "Database connection URL", "is_secret": False},
    "redis_url": {"value": "redis://localhost:6379/0", "description": "Redis connection URL", "is_secret": False},
    "celery_broker_url": {"value": "redis://localhost:6379/0", "description": "Celery broker URL", "is_secret": False},
    "celery_result_backend": {"value": "redis://localhost:6379/0", "description": "Celery result backend URL", "is_secret": False},
    "jwt_secret_key": {"value": "netguard-secret-change-in-production", "description": "JWT secret key", "is_secret": True},
    "jwt_algorithm": {"value": "HS256", "description": "JWT algorithm", "is_secret": False},
    "access_token_expire_minutes": {"value": "30", "description": "Access token expiry (minutes)", "is_secret": False},
    "refresh_token_expire_days": {"value": "7", "description": "Refresh token expiry (days)", "is_secret": False},
    "nvd_api_key": {"value": "", "description": "NVD API key (optional, increases rate limit)", "is_secret": True},
    "nvd_api_url": {"value": "https://services.nvd.nist.gov/rest/json/cves/2.0", "description": "NVD API endpoint", "is_secret": False},
    "nmap_path": {"value": "/usr/bin/nmap", "description": "nmap binary path", "is_secret": False},
    "masscan_path": {"value": "/usr/bin/masscan", "description": "masscan binary path", "is_secret": False},
    "fping_path": {"value": "/usr/bin/fping", "description": "fping binary path", "is_secret": False},
    "cors_origins": {"value": "http://localhost:5173,http://localhost:3000", "description": "CORS allowed origins (comma separated)", "is_secret": False},
    "debug": {"value": "true", "description": "Debug mode", "is_secret": False},
    "scan_default_timeout": {"value": "3600", "description": "Default scan timeout (seconds)", "is_secret": False},
    "scan_max_concurrent": {"value": "3", "description": "Max concurrent scans", "is_secret": False},
    "nvd_rate_limit_interval": {"value": "6", "description": "NVD API request interval (seconds, without key)", "is_secret": False},
}

async def ensure_defaults(db: AsyncSession):
    for key, cfg in CONFIG_DEFAULTS.items():
        result = await db.execute(select(SystemConfig).where(SystemConfig.key == key))
        if not result.scalar_one_or_none():
            entry = SystemConfig(key=key, value=cfg["value"], description=cfg["description"], is_secret=cfg["is_secret"])
            db.add(entry)
    await db.commit()

async def get_all_config(db: AsyncSession) -> list[SystemConfig]:
    await ensure_defaults(db)
    result = await db.execute(select(SystemConfig).order_by(SystemConfig.key))
    return result.scalars().all()

async def get_config(db: AsyncSession, key: str) -> SystemConfig | None:
    result = await db.execute(select(SystemConfig).where(SystemConfig.key == key))
    return result.scalar_one_or_none()

async def set_config(db: AsyncSession, key: str, value: str) -> SystemConfig:
    result = await db.execute(select(SystemConfig).where(SystemConfig.key == key))
    entry = result.scalar_one_or_none()
    if entry:
        entry.value = value
        entry.updated_at = datetime.now(timezone.utc)
    else:
        entry = SystemConfig(key=key, value=value, description=key, is_secret=False)
        db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return entry

async def get_effective_config(db: AsyncSession, key: str) -> str | None:
    entry = await get_config(db, key)
    if entry:
        return entry.value
    return CONFIG_DEFAULTS.get(key, {}).get("value")
