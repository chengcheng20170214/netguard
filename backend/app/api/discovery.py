
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db, async_session
from app.models.models import ScanTask, ScanResult, ScanType, ScanStatus, User
from app.schemas.discovery import ScanRequest, ScanTaskResponse
from app.middleware.auth import get_current_user

router = APIRouter(prefix="/scans", tags=["资产发现"])


async def _dispatch_scan(task: ScanTask, req: ScanRequest, db: AsyncSession):
    import asyncio
    dispatched = False
    try:
        from app.tasks.scan_tasks import run_scan_task
        await asyncio.wait_for(
            asyncio.to_thread(
                run_scan_task.delay,
                task.id, req.targets, req.scan_mode.value,
                [m.value for m in req.scan_methods], req.ports
            ),
            timeout=3.0
        )
        dispatched = True
    except Exception:
        pass

    if not dispatched:
        task.error_message = None
        await db.commit()
        await db.refresh(task)
        from app.services.scheduler import scheduler_service
        asyncio.create_task(scheduler_service._execute_scan(task.id))

    if req.scan_type == ScanType.periodic and req.interval_minutes:
        try:
            from app.services.scheduler import scheduler_service
            scheduler_service.add_periodic_scan(task.id, req.interval_minutes)
        except Exception:
            pass


@router.post("/", response_model=ScanTaskResponse)
async def create_scan(req: ScanRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Create a scan task (one-time or periodic)."""
    if req.scan_type == ScanType.periodic and (not req.interval_minutes or req.interval_minutes < 1):
        raise HTTPException(status_code=422, detail="周期扫描必须设置间隔时间（分钟）")

    next_run = None
    if req.scan_type == ScanType.periodic and req.interval_minutes:
        next_run = datetime.now(timezone.utc) + timedelta(minutes=req.interval_minutes)

    task = ScanTask(
        name=req.name, targets=req.targets, scan_type=req.scan_type,
        scan_mode=req.scan_mode,
        scan_methods=[m.value for m in req.scan_methods],
        ports=req.ports, interval_minutes=req.interval_minutes,
        created_by=current_user.id, next_run=next_run,
        is_active=True
    )
    db.add(task)
    await db.commit()
    await db.refresh(task)

    # One-time scans start immediately; periodic scans register with scheduler
    if req.scan_type == ScanType.one_time:
        await _dispatch_scan(task, req, db)
    else:
        await _dispatch_scan(task, req, db)

    return task


@router.get("/")
async def list_scans(
    scan_type: ScanType | None = None,
    skip: int = 0, limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List scan tasks, optionally filtered by scan_type."""
    query = select(ScanTask).order_by(ScanTask.created_at.desc()).offset(skip).limit(limit)
    if scan_type:
        query = query.where(ScanTask.scan_type == scan_type)
    result = await db.execute(query)
    tasks = result.scalars().all()
    return {"items": tasks}


@router.get("/{scan_id}")
async def get_scan(scan_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(ScanTask).where(ScanTask.id == scan_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="扫描任务不存在")
    results_res = await db.execute(select(ScanResult).where(ScanResult.scan_task_id == scan_id))
    results = results_res.scalars().all()
    return {**task.__dict__, "results": results}


@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(ScanTask).where(ScanTask.id == scan_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="扫描任务不存在")
    if task.celery_task_id:
        try:
            from app.tasks.celery_app import celery_app
            celery_app.control.revoke(task.celery_task_id, terminate=True)
        except Exception:
            pass
    task.status = ScanStatus.cancelled
    await db.commit()
    return {"message": "扫描任务已取消"}


@router.post("/{scan_id}/activate")
async def activate_periodic_scan(scan_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Activate a periodic scan schedule."""
    result = await db.execute(select(ScanTask).where(ScanTask.id == scan_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="扫描任务不存在")
    if task.scan_type != ScanType.periodic:
        raise HTTPException(status_code=400, detail="仅周期扫描可启用/停用")
    task.is_active = True
    task.next_run = datetime.now(timezone.utc) + timedelta(minutes=task.interval_minutes)
    await db.commit()
    try:
        from app.services.scheduler import scheduler_service
        scheduler_service.add_periodic_scan(task.id, task.interval_minutes)
    except Exception:
        pass
    return {"message": "周期扫描已启用"}


@router.post("/{scan_id}/deactivate")
async def deactivate_periodic_scan(scan_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Deactivate a periodic scan schedule."""
    result = await db.execute(select(ScanTask).where(ScanTask.id == scan_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="扫描任务不存在")
    if task.scan_type != ScanType.periodic:
        raise HTTPException(status_code=400, detail="仅周期扫描可启用/停用")
    task.is_active = False
    task.next_run = None
    await db.commit()
    try:
        from app.services.scheduler import scheduler_service
        scheduler_service.remove_periodic_scan(task.id)
    except Exception:
        pass
    return {"message": "周期扫描已停用"}


@router.websocket("/ws/scan/{task_id}")
async def scan_ws(websocket: WebSocket, task_id: int):
    await websocket.accept()
    try:
        while True:
            async with async_session() as db:
                result = await db.execute(select(ScanTask).where(ScanTask.id == task_id))
                task = result.scalar_one_or_none()
                if task:
                    await websocket.send_json({"status": task.status.value, "progress": task.progress})
                    if task.status.value in ("completed", "failed", "cancelled"):
                        break
            import asyncio
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass
