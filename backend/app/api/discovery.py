
from datetime import datetime, timezone, timedelta
import logging
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db, async_session
from app.models.models import ScanTask, ScanResult, ScanType, ScanStatus, User
from app.schemas.discovery import ScanRequest, ScanTaskResponse, ScanResultResponse, ScanUpdateRequest
from app.middleware.auth import get_current_user
from app.services.auth import decode_token

logger = logging.getLogger(__name__)

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
    except Exception as e:
        logger.error(f"Failed to dispatch scan via Celery: {e}")

    if not dispatched:
        task.error_message = None
        await db.commit()
        await db.refresh(task)
        from app.services.scan_executor import execute_scan
        task_handle = asyncio.create_task(execute_scan(task.id))
        task_handle.add_done_callback(lambda t: logger.error(f"Scan task {task.id} failed: {t.exception()}") if t.exception() else None)

    if req.scan_type == ScanType.periodic and req.interval_minutes:
        try:
            from app.services.scheduler import scheduler_service
            scheduler_service.add_periodic_scan(task.id, req.interval_minutes)
        except Exception as e:
            logger.error(f"Failed to register periodic scan: {e}")


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
        ports=req.ports, max_concurrent=req.max_concurrent, interval_minutes=req.interval_minutes,
        created_by=current_user.id, next_run=next_run,
        is_active=True
    )
    db.add(task)
    await db.commit()
    await db.refresh(task)

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
    task_data = ScanTaskResponse.model_validate(task).model_dump()
    task_data["results"] = [ScanResultResponse.model_validate(r).model_dump() for r in results]
    return task_data


@router.put("/{scan_id}", response_model=ScanTaskResponse)
async def update_scan(scan_id: int, req: ScanUpdateRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Update a scan task. Only tasks in pending/completed/cancelled/failed status can be edited."""
    result = await db.execute(select(ScanTask).where(ScanTask.id == scan_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="扫描任务不存在")
    if task.status == ScanStatus.running:
        raise HTTPException(status_code=400, detail="运行中的任务不可编辑")

    if req.name is not None:
        task.name = req.name
    if req.targets is not None:
        task.targets = req.targets
    if req.scan_mode is not None:
        task.scan_mode = req.scan_mode
    if req.scan_methods is not None:
        task.scan_methods = [m.value for m in req.scan_methods]
    if req.ports is not None:
        task.ports = req.ports
    if req.interval_minutes is not None:
        task.interval_minutes = req.interval_minutes
        # If periodic and active, update the scheduler
        if task.scan_type == ScanType.periodic and task.is_active:
            task.next_run = datetime.now(timezone.utc) + timedelta(minutes=req.interval_minutes)
            try:
                from app.services.scheduler import scheduler_service
                scheduler_service.remove_periodic_scan(task.id)
                scheduler_service.add_periodic_scan(task.id, req.interval_minutes)
            except Exception as e:
                logger.error(f"Failed to update scheduler for scan {task.id}: {e}")

    await db.commit()
    await db.refresh(task)
    return task


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
        except Exception as e:
            logger.warning(f"Failed to revoke celery task {task.celery_task_id}: {e}")
    if task.scan_type == ScanType.periodic:
        try:
            from app.services.scheduler import scheduler_service
            scheduler_service.remove_periodic_scan(task.id)
        except Exception as e:
            logger.warning(f"Failed to remove periodic scan {task.id} from scheduler: {e}")
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
    except Exception as e:
        logger.error(f"Failed to activate periodic scan {task.id}: {e}")
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
    if task.status == ScanStatus.running:
        task.status = ScanStatus.cancelled
    await db.commit()
    try:
        from app.services.scheduler import scheduler_service
        scheduler_service.remove_periodic_scan(task.id)
    except Exception as e:
        logger.error(f"Failed to deactivate periodic scan {task.id}: {e}")
    return {"message": "周期扫描已停用"}


@router.delete("/{scan_id}")
async def delete_scan(scan_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Delete a scan task and its results."""
    result = await db.execute(select(ScanTask).where(ScanTask.id == scan_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="扫描任务不存在")
    if task.status == ScanStatus.running:
        raise HTTPException(status_code=400, detail="运行中的任务不可删除，请先取消")

    if task.scan_type == ScanType.periodic and task.is_active:
        try:
            from app.services.scheduler import scheduler_service
            scheduler_service.remove_periodic_scan(task.id)
        except Exception as e:
            logger.warning(f"Failed to remove periodic scan {task.id} from scheduler: {e}")

    from sqlalchemy import delete as sa_delete
    await db.execute(sa_delete(ScanResult).where(ScanResult.scan_task_id == scan_id))
    from app.models.models import ScanChunk
    await db.execute(sa_delete(ScanChunk).where(ScanChunk.scan_task_id == scan_id))
    await db.delete(task)
    await db.commit()
    return {"message": "扫描任务已删除"}


@router.post("/{scan_id}/rescan", response_model=ScanTaskResponse)
async def rescan_scan(scan_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Re-run a scan task with the same configuration."""
    result = await db.execute(select(ScanTask).where(ScanTask.id == scan_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="扫描任务不存在")
    if task.status == ScanStatus.running:
        raise HTTPException(status_code=400, detail="任务正在运行中，请等待完成后再重新扫描")

    task.status = ScanStatus.pending
    task.progress = 0
    task.error_message = None
    task.scan_log = []
    task.result_summary = {}
    task.celery_task_id = None
    task.started_at = None
    task.completed_at = None
    task.last_run = datetime.now(timezone.utc)
    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(task, "scan_log")
    flag_modified(task, "result_summary")
    await db.commit()
    await db.refresh(task)

    from sqlalchemy import delete as sa_delete
    await db.execute(sa_delete(ScanResult).where(ScanResult.scan_task_id == scan_id))
    from app.models.models import ScanChunk
    await db.execute(sa_delete(ScanChunk).where(ScanChunk.scan_task_id == scan_id))
    await db.commit()
    await db.refresh(task)

    # Dispatch scan directly without reconstructing ScanRequest
    # (avoids ScanMethod enum validation errors for legacy data)
    import asyncio
    dispatched = False
    try:
        from app.tasks.scan_tasks import run_scan_task
        scan_mode_val = task.scan_mode.value if hasattr(task.scan_mode, 'value') else str(task.scan_mode)
        await asyncio.wait_for(
            asyncio.to_thread(
                run_scan_task.delay,
                task.id, task.targets, scan_mode_val,
                task.scan_methods or [], task.ports
            ),
            timeout=3.0
        )
        dispatched = True
    except Exception as e:
        logger.error(f"Failed to dispatch rescan via Celery: {e}")

    if not dispatched:
        from app.services.scan_executor import execute_scan
        task_handle = asyncio.create_task(execute_scan(task.id))
        task_handle.add_done_callback(lambda t: logger.error(f"Rescan task {task.id} failed: {t.exception()}") if t.exception() else None)

    if task.scan_type == ScanType.periodic and task.is_active and task.interval_minutes:
        try:
            from app.services.scheduler import scheduler_service
            scheduler_service.add_periodic_scan(task.id, task.interval_minutes)
        except Exception as e:
            logger.error(f"Failed to register periodic rescan: {e}")

    await db.refresh(task)
    return task


@router.websocket("/ws/scan/{task_id}")
async def scan_ws(websocket: WebSocket, task_id: int, token: str = Query(default="")):
    if not token:
        await websocket.close(code=4001, reason="Missing authentication token")
        return
    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        await websocket.close(code=4001, reason="Invalid or expired token")
        return
    await websocket.accept()
    try:
        while True:
            async with async_session() as db:
                result = await db.execute(select(ScanTask).where(ScanTask.id == task_id))
                task = result.scalar_one_or_none()
                if task:
                    await websocket.send_json({
                        "status": task.status.value,
                        "progress": task.progress,
                        "scan_log": task.scan_log or [],
                        "result_summary": task.result_summary or {},
                    })
                    if task.status.value in ("completed", "failed", "cancelled"):
                        break
            import asyncio
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass
