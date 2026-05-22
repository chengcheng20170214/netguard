from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.models.models import User, UserRole
from app.middleware.auth import require_role
from app.services.config_service import get_all_config, get_config, set_config, CONFIG_DEFAULTS
from app.schemas.settings import ConfigUpdate, ConfigResponse

router = APIRouter(prefix="/settings", tags=["系统设置"])

@router.get("/")
async def list_settings(db: AsyncSession = Depends(get_db), current_user: User = Depends(require_role(UserRole.admin))):
    configs = await get_all_config(db)
    items = []
    for c in configs:
        val = c.value if not c.is_secret else "********"
        items.append({"key": c.key, "value": val, "real_value": c.value, "description": c.description, "is_secret": c.is_secret, "updated_at": str(c.updated_at) if c.updated_at else None})
    return {"items": items}

@router.get("/{key}")
async def get_setting(key: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(require_role(UserRole.admin))):
    entry = await get_config(db, key)
    if not entry:
        raise HTTPException(status_code=404, detail="配置项不存在")
    val = entry.value if not entry.is_secret else "********"
    return {"key": entry.key, "value": val, "real_value": entry.value, "description": entry.description, "is_secret": entry.is_secret}

@router.put("/{key}")
async def update_setting(key: str, data: ConfigUpdate, db: AsyncSession = Depends(get_db), current_user: User = Depends(require_role(UserRole.admin))):
    entry = await set_config(db, key, data.value)
    return {"key": entry.key, "value": "********" if entry.is_secret else entry.value, "description": entry.description, "is_secret": entry.is_secret, "message": "配置已更新"}

@router.post("/reset/{key}")
async def reset_setting(key: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(require_role(UserRole.admin))):
    default = CONFIG_DEFAULTS.get(key)
    if not default:
        raise HTTPException(status_code=404, detail="配置项不存在")
    entry = await set_config(db, key, default["value"])
    return {"key": entry.key, "value": "********" if entry.is_secret else entry.value, "message": "已重置为默认值"}
