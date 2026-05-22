
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db, async_session
from app.models.models import ScanTask, ScanResult, User
from app.schemas.discovery import ScanRequest, ScanTaskResponse
from app.middleware.auth import get_current_user
from app.tasks.scan_tasks import run_scan_task

router = APIRouter(prefix="/scans", tags=["资产发现"])

@router.post("/", response_model=ScanTaskResponse)
async def create_scan(req: ScanRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    task = ScanTask(name=req.name, targets=req.targets, scan_mode=req.scan_mode, scan_methods=[m.value for m in req.scan_methods], ports=req.ports, created_by=current_user.id)
    db.add(task)
    await db.commit()
    await db.refresh(task)
    run_scan_task.delay(task.id, req.targets, req.scan_mode.value, [m.value for m in req.scan_methods], req.ports)
    return task

@router.get("/")
async def list_scans(skip: int = 0, limit: int = 50, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(ScanTask).order_by(ScanTask.created_at.desc()).offset(skip).limit(limit))
    tasks = result.scalars().all()
    return {"items": tasks}

@router.get("/{scan_id}")
async def get_scan(scan_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(ScanTask).where(ScanTask.id == scan_id))
    task = result.scalar_one_or_none()
    if not task:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="扫描任务不存在")
    results_res = await db.execute(select(ScanResult).where(ScanResult.scan_task_id == scan_id))
    results = results_res.scalars().all()
    return {**task.__dict__, "results": results}

@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(ScanTask).where(ScanTask.id == scan_id))
    task = result.scalar_one_or_none()
    if not task:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="扫描任务不存在")
    if task.celery_task_id:
        from app.tasks.celery_app import celery_app
        celery_app.control.revoke(task.celery_task_id, terminate=True)
    from app.models.models import ScanStatus
    task.status = ScanStatus.cancelled
    await db.commit()
    return {"message": "扫描任务已取消"}

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
