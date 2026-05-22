
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db
from app.models.models import Vulnerability, Asset, User
from app.schemas.vuln import VulnScanRequest
from app.middleware.auth import get_current_user
from app.services.nvd import search_cve
from datetime import datetime, timezone

router = APIRouter(prefix="/vulns", tags=["漏洞检测"])

@router.get("/")
async def list_vulns(severity: str | None = None, asset_id: int | None = None, cve_id: str | None = None, skip: int = 0, limit: int = 50, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = select(Vulnerability)
    if severity:
        query = query.where(Vulnerability.severity == severity)
    if asset_id:
        query = query.where(Vulnerability.asset_id == asset_id)
    if cve_id:
        query = query.where(Vulnerability.cve_id.contains(cve_id))
    result = await db.execute(query.order_by(Vulnerability.created_at.desc()).offset(skip).limit(limit))
    return {"items": result.scalars().all()}

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

@router.post("/scan")
async def scan_vulns(req: VulnScanRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(Asset).where(Asset.id == req.asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="资产不存在")

    found = []
    for port_info in (asset.current_ports or []):
        service = port_info.get("service", "")
        version = port_info.get("version", "")
        if not service:
            continue
        cves = await search_cve(service, version or None)
        for cve in cves:
            existing = await db.execute(select(Vulnerability).where(Vulnerability.asset_id == asset.id, Vulnerability.cve_id == cve["cve_id"]))
            if existing.scalar_one_or_none():
                continue
            vuln = Vulnerability(
                asset_id=asset.id, cve_id=cve["cve_id"], cve_description=cve.get("cve_description"),
                cvss_score=cve.get("cvss_score"), severity=cve.get("severity"),
                affected_service=service, affected_version=version,
                scan_task_id=req.scan_task_id, created_at=datetime.now(timezone.utc)
            )
            db.add(vuln)
            found.append(cve["cve_id"])

    await db.commit()
    return {"message": f"发现 {len(found)} 个漏洞", "cves": found}
