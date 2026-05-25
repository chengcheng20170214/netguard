
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.database import get_db
from app.models.models import Asset, AssetChange, AssetSnapshot, User
from app.schemas.asset import AssetUpdate, AssetChangeResponse, AssetSnapshotResponse, AssetImportItem
from app.middleware.auth import get_current_user
import json, io, csv, ipaddress, logging

logger = logging.getLogger(__name__)
MAX_IMPORT_SIZE = 5 * 1024 * 1024

router = APIRouter(prefix="/assets", tags=["资产管理"])

@router.get("/")
async def list_assets(ip: str | None = None, group: str | None = None, is_online: bool | None = None, skip: int = 0, limit: int = 50, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = select(Asset)
    if ip:
        query = query.where(Asset.ip.contains(ip))
    if group:
        query = query.where(Asset.group_name == group)
    if is_online is not None:
        query = query.where(Asset.is_online == is_online)
    total_q = await db.execute(select(func.count()).select_from(Asset))
    total = total_q.scalar()
    result = await db.execute(query.order_by(Asset.last_seen.desc()).offset(skip).limit(limit))
    assets = result.scalars().all()
    return {"total": total, "items": assets}

@router.get("/changes")
async def all_changes(skip: int = 0, limit: int = 50, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(AssetChange).order_by(AssetChange.detected_at.desc()).offset(skip).limit(limit))
    changes = result.scalars().all()
    return {"items": changes}

@router.get("/{asset_id}")
async def get_asset(asset_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="资产不存在")
    return asset

@router.put("/{asset_id}")
async def update_asset(asset_id: int, data: AssetUpdate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="资产不存在")
    if data.tags is not None:
        asset.tags = data.tags
    if data.group_name is not None:
        asset.group_name = data.group_name
    await db.commit()
    return {"message": "资产已更新"}

@router.delete("/{asset_id}")
async def delete_asset(asset_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="资产不存在")
    await db.delete(asset)
    await db.commit()
    return {"message": "资产已删除"}

@router.get("/{asset_id}/changes")
async def asset_changes(asset_id: int, skip: int = 0, limit: int = 50, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(AssetChange).where(AssetChange.asset_id == asset_id).order_by(AssetChange.detected_at.desc()).offset(skip).limit(limit))
    return {"items": result.scalars().all()}

@router.get("/{asset_id}/snapshots")
async def asset_snapshots(asset_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(AssetSnapshot).where(AssetSnapshot.asset_id == asset_id).order_by(AssetSnapshot.created_at.desc()))
    return {"items": result.scalars().all()}

@router.post("/export")
async def export_assets(format: str = "json", db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(Asset))
    assets = result.scalars().all()
    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ip", "mac", "hostname", "os", "is_online", "group_name"])
        for a in assets:
            writer.writerow([a.ip, a.mac, a.hostname, a.os, a.is_online, a.group_name])
        return StreamingResponse(io.BytesIO(output.getvalue().encode()), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=assets.csv"})
    data = [{"ip": a.ip, "mac": a.mac, "hostname": a.hostname, "os": a.os, "ports": a.current_ports, "tags": a.tags, "group": a.group_name} for a in assets]
    return StreamingResponse(io.BytesIO(json.dumps(data, ensure_ascii=False).encode()), media_type="application/json", headers={"Content-Disposition": "attachment; filename=assets.json"})

@router.post("/import")
async def import_assets(file: UploadFile = File(...), db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    content = await file.read()
    if len(content) > MAX_IMPORT_SIZE:
        raise HTTPException(status_code=413, detail=f"文件大小超过限制 ({MAX_IMPORT_SIZE // 1024 // 1024}MB)")
    try:
        raw = json.loads(content)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="无效的 JSON 文件")
    items = raw if isinstance(raw, list) else [raw]
    count = 0
    skipped = 0
    for item in items:
        try:
            validated = AssetImportItem(**item)
        except Exception as e:
            logger.warning(f"Skipping invalid import item: {e}")
            skipped += 1
            continue
        existing = await db.execute(select(Asset).where(Asset.ip == validated.ip))
        if existing.scalar_one_or_none():
            skipped += 1
            continue
        asset = Asset(ip=validated.ip, mac=validated.mac, hostname=validated.hostname, os=validated.os, current_ports=validated.ports or [], tags=validated.tags or [], group_name=validated.group)
        db.add(asset)
        count += 1
    await db.commit()
    return {"message": f"已导入 {count} 个资产", "skipped": skipped}
