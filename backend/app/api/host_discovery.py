
from datetime import datetime, timezone, timedelta
import logging
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db, async_session
from app.models.models import ScanTask, ScanResult, ScanType, ScanStatus, ScanCategory, User
from app.schemas.discovery import ScanRequest, ScanTaskResponse, ScanResultResponse, ScanUpdateRequest
from app.middleware.auth import get_current_user
from app.services.auth import decode_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/host-scans", tags=["主机发现"])


async def _dispatch_scan(task: ScanTask, req: ScanRequest, db: AsyncSession):
    """仅负责调度一次性扫描执行，不处理周期扫描的scheduler注册"""
    import asyncio
    dispatched = False
    try:
        from app.tasks.scan_tasks import run_scan_task
        await asyncio.wait_for(
            asyncio.to_thread(
                run_scan_task.delay,
                task.id, req.targets, req.scan_mode.value, req.ports
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


@router.post("", response_model=ScanTaskResponse)
async def create_host_scan(req: ScanRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Create a host discovery scan task."""
    # Force host discovery category and validate methods
    req.scan_category = ScanCategory.host_discovery
    if req.scan_type == ScanType.periodic and (not req.interval_hours or req.interval_hours < 1):
        raise HTTPException(status_code=422, detail="周期扫描必须设置间隔时间（小时）")

    next_run = None
    if req.scan_type == ScanType.periodic and req.interval_hours:
        next_run = datetime.now(timezone.utc)  # scheduler 会立即执行首次扫描

    task = ScanTask(
        name=req.name, targets=req.targets, scan_category=ScanCategory.host_discovery,
        scan_type=req.scan_type, scan_mode=req.scan_mode,
        scan_methods=[],  # 主机发现固定两阶段(Ping+Top1000)，scan_methods 不参与调度
        target_all_assets=req.target_all_assets,  # 周期扫描动态获取所有资产
        ports=req.ports, max_concurrent=req.max_concurrent, interval_hours=req.interval_hours,
        created_by=current_user.id, next_run=next_run,
        is_active=True
    )
    db.add(task)
    await db.commit()
    await db.refresh(task)

    if req.scan_type == ScanType.periodic:
        # 周期扫描：注册到 scheduler，由 scheduler 立即执行首次扫描
        try:
            from app.services.scheduler import scheduler_service
            scheduler_service.add_periodic_scan(task.id, req.interval_hours)
        except Exception as e:
            logger.error(f"Failed to register periodic scan: {e}")
    else:
        # 一次性扫描：直接调度执行
        await _dispatch_scan(task, req, db)

    return task


@router.get("")
async def list_host_scans(
    scan_type: ScanType | None = None,
    skip: int = 0, limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List host discovery scan tasks."""
    query = select(ScanTask).where(ScanTask.scan_category == ScanCategory.host_discovery).order_by(ScanTask.created_at.desc()).offset(skip).limit(limit)
    if scan_type:
        query = query.where(ScanTask.scan_type == scan_type)
    result = await db.execute(query)
    tasks = result.scalars().all()
    return {"items": tasks}


@router.get("/{scan_id}")
async def get_host_scan(scan_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(select(ScanTask).where(ScanTask.id == scan_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="扫描任务不存在")
    results_res = await db.execute(select(ScanResult).where(ScanResult.scan_task_id == scan_id))
    results = results_res.scalars().all()
    return {**task.__dict__, "results": results}


@router.put("/{scan_id}")
async def update_host_scan(scan_id: int, req: ScanUpdateRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
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
    # scan_methods 不处理：主机发现固定两阶段，不接受外部修改
    if req.ports is not None:
        task.ports = req.ports
    if req.max_concurrent is not None:
        task.max_concurrent = req.max_concurrent
    if req.interval_hours is not None:
        task.interval_hours = req.interval_hours
        if task.scan_type == ScanType.periodic and task.is_active:
            task.next_run = datetime.now(timezone.utc)  # scheduler 重新注册后会立即执行
            try:
                from app.services.scheduler import scheduler_service
                scheduler_service.remove_periodic_scan(task.id)
                scheduler_service.add_periodic_scan(task.id, req.interval_hours)
            except Exception as e:
                logger.error(f"Failed to update scheduler for scan {task.id}: {e}")

    await db.commit()
    await db.refresh(task)
    return task


@router.post("/{scan_id}/cancel")
async def cancel_host_scan(scan_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
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
    # 通知 scan_executor 取消
    from app.services.scan_executor import request_cancel
    request_cancel(scan_id)
    task.status = ScanStatus.cancelled
    await db.commit()
    return {"message": "扫描任务已取消"}


@router.post("/{scan_id}/activate")
async def activate_host_scan(scan_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Activate a periodic host discovery scan."""
    result = await db.execute(select(ScanTask).where(ScanTask.id == scan_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="扫描任务不存在")
    if task.scan_type != ScanType.periodic:
        raise HTTPException(status_code=400, detail="仅周期扫描可启用/停用")
    task.is_active = True
    task.next_run = datetime.now(timezone.utc)  # scheduler 会立即执行
    await db.commit()
    try:
        from app.services.scheduler import scheduler_service
        scheduler_service.add_periodic_scan(task.id, task.interval_hours)
    except Exception as e:
        logger.error(f"Failed to activate periodic scan {task.id}: {e}")
    return {"message": "周期扫描已启用"}


@router.post("/{scan_id}/deactivate")
async def deactivate_host_scan(scan_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Deactivate a periodic host discovery scan."""
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
        from app.services.scan_executor import request_cancel
        request_cancel(scan_id)
    await db.commit()
    try:
        from app.services.scheduler import scheduler_service
        scheduler_service.remove_periodic_scan(task.id)
    except Exception as e:
        logger.error(f"Failed to deactivate periodic scan {task.id}: {e}")
    return {"message": "周期扫描已停用"}


@router.delete("/{scan_id}")
async def delete_host_scan(scan_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Delete a host discovery scan task and its results."""
    result = await db.execute(select(ScanTask).where(ScanTask.id == scan_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="扫描任务不存在")
    if task.status == ScanStatus.running:
        raise HTTPException(status_code=400, detail="运行中的任务不可删除，请先取消")

    # Remove periodic scheduler if active
    if task.scan_type == ScanType.periodic and task.is_active:
        try:
            from app.services.scheduler import scheduler_service
            scheduler_service.remove_periodic_scan(task.id)
        except Exception as e:
            logger.warning(f"Failed to remove periodic scan {task.id} from scheduler: {e}")

    # Delete scan results first
    from sqlalchemy import delete as sa_delete
    await db.execute(sa_delete(ScanResult).where(ScanResult.scan_task_id == scan_id))
    await db.delete(task)
    await db.commit()
    return {"message": "扫描任务已删除"}


@router.post("/{scan_id}/rescan", response_model=ScanTaskResponse)
async def rescan_host_scan(scan_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Re-run a host discovery scan task with the same configuration."""
    result = await db.execute(select(ScanTask).where(ScanTask.id == scan_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="扫描任务不存在")
    if task.status == ScanStatus.running:
        raise HTTPException(status_code=400, detail="任务正在运行中，请等待完成后再重新扫描")

    # Reset task state
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

    # Delete old scan results
    from sqlalchemy import delete as sa_delete
    await db.execute(sa_delete(ScanResult).where(ScanResult.scan_task_id == scan_id))
    # Delete old scan chunks
    from app.models.models import ScanChunk
    await db.execute(sa_delete(ScanChunk).where(ScanChunk.scan_task_id == scan_id))
    await db.commit()
    await db.refresh(task)

    if task.scan_type == ScanType.periodic and task.is_active and task.interval_hours:
        # 周期扫描：仅重新注册 scheduler，由 scheduler 立即执行首次扫描
        try:
            from app.services.scheduler import scheduler_service
            scheduler_service.add_periodic_scan(task.id, task.interval_hours)
        except Exception as e:
            logger.error(f"Failed to register periodic rescan: {e}")
    else:
        # 一次性扫描：直接调度执行
        import asyncio
        dispatched = False
        try:
            from app.tasks.scan_tasks import run_scan_task
            scan_mode_val = task.scan_mode.value if hasattr(task.scan_mode, 'value') else str(task.scan_mode)
            await asyncio.wait_for(
                asyncio.to_thread(
                    run_scan_task.delay,
                    task.id, task.targets, scan_mode_val, task.ports
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

    await db.refresh(task)
    return task


@router.websocket("/ws/scan/{task_id}")
async def scan_ws(websocket: WebSocket, task_id: int, token: str = Query(default="")):
    if not token:
        # Try header-based auth
        auth_header = websocket.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]

    if not token:
        await websocket.close(code=4001, reason="No auth token")
        return

    try:
        payload = decode_token(token)
        if not payload:
            await websocket.close(code=4001, reason="Invalid token")
            return
    except Exception:
        await websocket.close(code=4001, reason="Invalid token")
        return

    try:
        await websocket.accept()
    except Exception:
        return

    import asyncio
    try:
        while True:
            async with async_session() as db:
                result = await db.execute(select(ScanTask).where(ScanTask.id == task_id))
                task = result.scalar_one_or_none()
                if not task:
                    await websocket.send_json({"error": "Task not found"})
                    break
                data = {
                    "id": task.id,
                    "status": task.status.value if hasattr(task.status, 'value') else str(task.status),
                    "progress": task.progress,
                    "scan_log": task.scan_log[-5:] if task.scan_log else [],
                    "result_summary": task.result_summary,
                }
                await websocket.send_json(data)
                if task.status in (ScanStatus.completed, ScanStatus.failed, ScanStatus.cancelled):
                    break
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket error for task {task_id}: {e}")
