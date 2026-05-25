
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.database import get_db
from app.models.models import Vulnerability, Asset, User
from app.schemas.vuln import VulnScanRequest, VulnAutoScanConfig
from app.middleware.auth import get_current_user, require_role
from app.models.models import UserRole
from datetime import datetime, timezone

router = APIRouter(prefix="/vulns", tags=["漏洞检测"])


@router.get("/")
async def list_vulns(
    severity: str | None = None, asset_id: int | None = None,
    cve_id: str | None = None, skip: int = 0, limit: int = 50,
    db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
):
    query = select(Vulnerability)
    if severity:
        query = query.where(Vulnerability.severity == severity)
    if asset_id:
        query = query.where(Vulnerability.asset_id == asset_id)
    if cve_id:
        query = query.where(Vulnerability.cve_id.contains(cve_id))
    result = await db.execute(query.order_by(Vulnerability.created_at.desc()).offset(skip).limit(limit))
    total_q = await db.execute(select(func.count()).select_from(Vulnerability))
    total = total_q.scalar()
    items = result.scalars().all()
    return {"total": total, "items": items}


@router.get("/db-status")
async def vuln_db_status(current_user: User = Depends(get_current_user)):
    from app.services.vuln_service import get_vuln_db_status
    return await get_vuln_db_status()


@router.post("/scan")
async def scan_vulns(req: VulnScanRequest, current_user: User = Depends(get_current_user)):
    from app.services.vuln_service import scan_asset_vulns
    found = await scan_asset_vulns(req.asset_id)
    return {"message": f"发现 {len(found)} 个漏洞", "cves": found}


@router.post("/scan-all")
async def scan_all(current_user: User = Depends(get_current_user)):
    from app.services.vuln_service import scan_all_assets
    result = await scan_all_assets()
    return result


@router.post("/update-db/full")
async def update_vuln_db_full(current_user: User = Depends(require_role(UserRole.admin))):
    import asyncio
    from app.services.vuln_service import update_vuln_db_full as _update
    asyncio.create_task(_update())
    return {"message": "全量更新已启动，请通过 /vulns/update-db/progress 查看进度"}


@router.post("/update-db/incremental")
async def update_vuln_db_incremental(current_user: User = Depends(require_role(UserRole.admin))):
    import asyncio
    from app.services.vuln_service import update_vuln_db_incremental as _update
    asyncio.create_task(_update())
    return {"message": "增量更新已启动，请通过 /vulns/update-db/progress 查看进度"}


@router.get("/update-db/progress")
async def get_update_progress(current_user: User = Depends(get_current_user)):
    from app.services.vuln_service import get_update_progress
    return get_update_progress()


@router.put("/auto-scan")
async def configure_auto_scan(
    config: VulnAutoScanConfig,
    current_user: User = Depends(require_role(UserRole.admin))
):
    from app.services.vuln_service import (
        vuln_scheduler, VULN_AUTO_ENABLED_KEY, VULN_SCAN_INTERVAL_KEY,
        _set_config_value
    )

    await _set_config_value(VULN_AUTO_ENABLED_KEY, "true" if config.enabled else "false")
    await _set_config_value(VULN_SCAN_INTERVAL_KEY, str(config.interval_hours))

    if config.enabled:
        await vuln_scheduler.restart(config.interval_hours)
    else:
        await vuln_scheduler.stop()

    return {"message": f"自动扫描已{'启用' if config.enabled else '停用'}", "interval_hours": config.interval_hours}


@router.get("/{vuln_id}")
async def get_vuln(vuln_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    return vuln


@router.put("/{vuln_id}/false-positive")
async def mark_false_positive(vuln_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    vuln.is_false_positive = True
    await db.commit()
    return {"message": "已标记为误报"}
