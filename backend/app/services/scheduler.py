
from datetime import datetime, timezone, timedelta
import asyncio
import logging

logger = logging.getLogger(__name__)


class SchedulerService:
    def __init__(self):
        self._periodic_tasks: dict[int, asyncio.Task] = {}
        self._running = False

    async def start(self):
        self._running = True
        from app.database import async_session
        from app.models.models import ScanTask, ScanType, ScanStatus
        from sqlalchemy import select

        async with async_session() as db:
            result = await db.execute(
                select(ScanTask).where(
                    ScanTask.scan_type == ScanType.periodic,
                    ScanTask.is_active == True
                )
            )
            tasks = result.scalars().all()
            for task in tasks:
                self.add_periodic_scan(task.id, task.interval_minutes)

        logger.info(f"Scheduler started with {len(self._periodic_tasks)} periodic scans")

    async def stop(self):
        self._running = False
        for task_id, atask in self._periodic_tasks.items():
            atask.cancel()
        self._periodic_tasks.clear()
        logger.info("Scheduler stopped")

    def add_periodic_scan(self, scan_task_id: int, interval_minutes: int):
        if scan_task_id in self._periodic_tasks:
            self._periodic_tasks[scan_task_id].cancel()
        atask = asyncio.create_task(self._run_periodic(scan_task_id, interval_minutes))
        self._periodic_tasks[scan_task_id] = atask

    def remove_periodic_scan(self, scan_task_id: int):
        if scan_task_id in self._periodic_tasks:
            self._periodic_tasks[scan_task_id].cancel()
            del self._periodic_tasks[scan_task_id]

    async def _run_periodic(self, scan_task_id: int, interval_minutes: int):
        from app.database import async_session
        from app.models.models import ScanTask, ScanType, ScanStatus
        from app.services.scan_executor import execute_scan
        from sqlalchemy import select

        while self._running:
            await asyncio.sleep(interval_minutes * 60)

            try:
                async with async_session() as db:
                    result = await db.execute(select(ScanTask).where(ScanTask.id == scan_task_id))
                    task = result.scalar_one_or_none()
                    if not task or not task.is_active or task.scan_type != ScanType.periodic:
                        break

                    next_run = datetime.now(timezone.utc) + timedelta(minutes=interval_minutes)
                    task.next_run = next_run
                    await db.commit()

                await execute_scan(scan_task_id)

                async with async_session() as db:
                    result = await db.execute(select(ScanTask).where(ScanTask.id == scan_task_id))
                    task = result.scalar_one_or_none()
                    if task:
                        task.last_run = datetime.now(timezone.utc)
                        task.next_run = datetime.now(timezone.utc) + timedelta(minutes=interval_minutes)
                        await db.commit()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Periodic scan {scan_task_id} error: {e}")
                try:
                    async with async_session() as db:
                        result = await db.execute(select(ScanTask).where(ScanTask.id == scan_task_id))
                        task = result.scalar_one_or_none()
                        if task and task.status == ScanStatus.running:
                            task.status = ScanStatus.failed
                            task.error_message = f"Periodic scan error: {e}"
                            await db.commit()
                except Exception:
                    pass

        self._periodic_tasks.pop(scan_task_id, None)


scheduler_service = SchedulerService()
