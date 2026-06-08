
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.database import get_db
from app.models.models import Asset, AssetChange, AssetSnapshot, User, KnownService
from app.schemas.asset import AssetResponse, AssetListResponse, AssetUpdate, AssetChangeResponse, AssetSnapshotResponse, AssetImportItem, KnownServiceCreate, KnownServiceResponse
from app.middleware.auth import get_current_user
import json, io, csv, ipaddress, logging

logger = logging.getLogger(__name__)
MAX_IMPORT_SIZE = 5 * 1024 * 1024

router = APIRouter(prefix="/assets", tags=["资产管理"])

@router.get("", response_model=AssetListResponse)
async def list_assets(
    ip: str | None = None,
    hostname: str | None = None,
    mac: str | None = None,
    os: str | None = None,
    group: str | None = None,
    fingerprint: str | None = None,
    is_online: bool | None = None,
    sort_by: str = "last_seen",
    sort_order: str = "desc",
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(Asset)
    if ip:
        query = query.where(Asset.ip.contains(ip))
    if hostname:
        query = query.where(Asset.hostname.contains(hostname))
    if mac:
        query = query.where(Asset.mac.contains(mac))
    if os:
        query = query.where(Asset.os.contains(os))
    if group:
        query = query.where(Asset.group_name == group)
    if fingerprint:
        query = query.where(Asset.fingerprint.contains(fingerprint))
    if is_online is not None:
        query = query.where(Asset.is_online == is_online)

    # 排序
    allowed_sort = {
        "ip": Asset.ip,
        "hostname": Asset.hostname,
        "mac": Asset.mac,
        "os": Asset.os,
        "group_name": Asset.group_name,
        "fingerprint": Asset.fingerprint,
        "first_seen": Asset.first_seen,
        "last_seen": Asset.last_seen,
    }
    sort_col = allowed_sort.get(sort_by, Asset.last_seen)

    if sort_by == "ip":
        # IP 数值排序：SQLite 字符串排序 10 < 2，需 Python 侧处理
        # 先查全量匹配结果（资产量级有限），排序后手动分页
        total_q = await db.execute(select(func.count()).select_from(query.subquery()))
        total = total_q.scalar()
        result = await db.execute(query)
        assets = result.scalars().all()

        from ipaddress import ip_address as _ip
        def _ip_key(a):
            try:
                return int(_ip(a.ip))
            except (ValueError, TypeError):
                return 0
        assets.sort(key=_ip_key, reverse=(sort_order == "desc"))
        assets = assets[skip: skip + limit]
    else:
        query = query.order_by(sort_col.desc() if sort_order == "desc" else sort_col.asc())
        total_q = await db.execute(select(func.count()).select_from(query.subquery()))
        total = total_q.scalar()
        result = await db.execute(query.offset(skip).limit(limit))
        assets = result.scalars().all()

    return {"total": total, "items": assets}

@router.get("/targets")
async def get_asset_targets(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Return all assets' IP list for scan target selection."""
    result = await db.execute(select(Asset.id, Asset.ip, Asset.hostname, Asset.is_online).order_by(Asset.ip))
    rows = result.all()
    return [{"id": r.id, "ip": r.ip, "hostname": r.hostname, "is_online": r.is_online} for r in rows]


@router.get("/changes")
async def all_changes(skip: int = 0, limit: int = 50, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(AssetChange).order_by(AssetChange.detected_at.desc()).offset(skip).limit(limit))
    changes = result.scalars().all()
    return {"items": changes}

@router.post("/batch-delete")
async def batch_delete_assets(ids: list[int], db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """批量删除资产"""
    if not ids:
        raise HTTPException(status_code=400, detail="ids 不能为空")
    result = await db.execute(select(Asset).where(Asset.id.in_(ids)))
    assets = result.scalars().all()
    found_ids = {a.id for a in assets}
    missing = set(ids) - found_ids
    if missing:
        raise HTTPException(status_code=404, detail=f"资产不存在: {missing}")
    for a in assets:
        await db.delete(a)
    await db.commit()
    return {"message": f"已删除 {len(assets)} 个资产"}

@router.get("/{asset_id}", response_model=AssetResponse)
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
        existing = None
        if validated.mac or (validated.hostname and validated.os):
            import hashlib
            if validated.mac:
                raw = f"mac:{validated.mac}"
            else:
                raw = f"host:{validated.hostname}|os:{validated.os}"
            fp = hashlib.sha256(raw.encode()).hexdigest()
            fp_result = await db.execute(select(Asset).where(Asset.fingerprint == fp))
            existing = fp_result.scalar_one_or_none()
        if not existing:
            ip_result = await db.execute(select(Asset).where(Asset.ip == validated.ip))
            existing = ip_result.scalar_one_or_none()
        if existing:
            skipped += 1
            continue
        fp_val = None
        if validated.mac or (validated.hostname and validated.os):
            import hashlib
            raw = f"mac:{validated.mac}" if validated.mac else f"host:{validated.hostname}|os:{validated.os}"
            fp_val = hashlib.sha256(raw.encode()).hexdigest()
        asset = Asset(ip=validated.ip, mac=validated.mac, hostname=validated.hostname, os=validated.os, fingerprint=fp_val, current_ports=validated.ports or [], tags=validated.tags or [], group_name=validated.group)
        db.add(asset)
        count += 1
    await db.commit()
    return {"message": f"已导入 {count} 个资产", "skipped": skipped}


@router.get("/services", response_model=list[KnownServiceResponse])
async def list_known_services(category: str | None = None, risk: str | None = None, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = select(KnownService).order_by(KnownService.port)
    if category:
        query = query.where(KnownService.category == category)
    if risk:
        query = query.where(KnownService.risk == risk)
    result = await db.execute(query)
    return result.scalars().all()


@router.post("/services", response_model=KnownServiceResponse)
async def create_known_service(data: KnownServiceCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    svc = KnownService(**data.model_dump())
    db.add(svc)
    await db.commit()
    await db.refresh(svc)
    return svc


@router.delete("/services/{service_id}")
async def delete_known_service(service_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(KnownService).where(KnownService.id == service_id))
    svc = result.scalar_one_or_none()
    if not svc:
        raise HTTPException(status_code=404, detail="服务定义不存在")
    await db.delete(svc)
    await db.commit()
    return {"message": "服务定义已删除"}


@router.post("/services/seed")
async def seed_services(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    from app.services.known_services import seed_known_services
    count = await seed_known_services(db)
    return {"message": f"已导入 {count} 个已知服务定义"}
