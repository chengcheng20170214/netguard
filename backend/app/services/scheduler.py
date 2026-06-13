"""
周期扫描调度器

关键设计:
- `await execute_scan(scan_task_id)` 阻塞等待扫描全部阶段完成后才返回
- 确保一轮完成再开始下一轮（不会出现多轮重叠）
- 扫描失败后等下一个周期再重试（不立即重试）
- 每轮开始前检查任务是否仍然活跃
- next_run 仅在扫描完成后设置（completed_at + interval），不在扫描前预设
"""
from datetime import datetime, timezone, timedelta
import asyncio
import logging

logger = logging.getLogger(__name__)


class SchedulerService:
    def __init__(self):
        self._periodic_tasks: dict[int, asyncio.Task] = {}
        self._running = False

    async def start(self):
        """启动调度器，恢复所有活跃的周期扫描"""
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
                # 修复：如果任务卡在 running 状态（服务重启导致），重置为 pending
                if task.status == ScanStatus.running:
                    logger.warning(f"Periodic scan {task.id} stuck in running state, resetting to pending")
                    task.status = ScanStatus.pending
                self.add_periodic_scan(task.id, task.interval_hours)
            await db.commit()

        logger.info(f"Scheduler started with {len(self._periodic_tasks)} periodic scans")

    async def stop(self):
        """停止调度器，取消所有周期任务"""
        self._running = False
        for task_id, atask in self._periodic_tasks.items():
            atask.cancel()
        self._periodic_tasks.clear()
        logger.info("Scheduler stopped")

    def add_periodic_scan(self, scan_task_id: int, interval_hours: int):
        """注册周期扫描任务"""
        if scan_task_id in self._periodic_tasks:
            self._periodic_tasks[scan_task_id].cancel()
        atask = asyncio.create_task(self._run_periodic(scan_task_id, interval_hours))
        self._periodic_tasks[scan_task_id] = atask
        logger.info(f"Registered periodic scan: task={scan_task_id}, interval={interval_hours}h")

    def remove_periodic_scan(self, scan_task_id: int):
        """移除周期扫描任务"""
        if scan_task_id in self._periodic_tasks:
            self._periodic_tasks[scan_task_id].cancel()
            del self._periodic_tasks[scan_task_id]
            logger.info(f"Removed periodic scan: task={scan_task_id}")

    async def _run_periodic(self, scan_task_id: int, interval_hours: int):
        """周期扫描循环: 执行 → 等待间隔 → 下一轮

        首次注册后立即执行第一次扫描，完成后等待间隔再执行下一轮。
        关键: await execute_scan() 会阻塞等待全部阶段完成才返回，
        因此不会出现多轮扫描重叠执行的问题。
        next_run 仅在扫描完成后设置，确保反映真实的下次执行时间。
        """
        from app.database import async_session
        from app.models.models import ScanTask, ScanType, ScanStatus
        from app.services.scan_executor import execute_scan
        from sqlalchemy import select

        while self._running:
            # 检查任务是否仍然活跃
            try:
                async with async_session() as db:
                    result = await db.execute(
                        select(ScanTask).where(ScanTask.id == scan_task_id)
                    )
                    task = result.scalar_one_or_none()
                    if not task or not task.is_active or task.scan_type != ScanType.periodic:
                        logger.info(f"Periodic scan {scan_task_id} no longer active, stopping")
                        break

                    # 如果上一轮还在运行（理论上不会，因为 await 会等待），跳过本轮
                    if task.status == ScanStatus.running:
                        logger.warning(f"Periodic scan {scan_task_id} still running, skipping this round")
                        await asyncio.sleep(60)
                        continue

            except Exception as e:
                logger.error(f"Periodic scan {scan_task_id} pre-check failed: {e}")
                await asyncio.sleep(30)
                continue

            # 如果 target_all_assets=True，执行前动态刷新资产列表
            try:
                async with async_session() as db:
                    result = await db.execute(
                        select(ScanTask).where(ScanTask.id == scan_task_id)
                    )
                    task = result.scalar_one_or_none()
                    if task and task.target_all_assets:
                        from app.models.models import Asset
                        asset_result = await db.execute(select(Asset))
                        assets = asset_result.scalars().all()
                        if assets:
                            new_targets = "\n".join(sorted(set(a.ip for a in assets)))
                            task.targets = new_targets
                            await db.commit()
                            logger.info(f"Periodic scan {scan_task_id}: refreshed targets from {len(assets)} assets")
                        else:
                            logger.warning(f"Periodic scan {scan_task_id}: target_all_assets=True but no assets found, skipping")
                            await asyncio.sleep(60)
                            continue
            except Exception as e:
                logger.error(f"Periodic scan {scan_task_id} target refresh failed: {e}")

            # 执行扫描（阻塞等待全部阶段完成）
            scan_error = False
            try:
                logger.info(f"Periodic scan {scan_task_id}: starting round")
                await execute_scan(scan_task_id)
                logger.info(f"Periodic scan {scan_task_id}: round completed")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Periodic scan {scan_task_id} execution error: {e}")
                scan_error = True

            # 更新 last_run 和 next_run（仅在扫描完成后设置，确保时间准确）
            try:
                async with async_session() as db:
                    result = await db.execute(
                        select(ScanTask).where(ScanTask.id == scan_task_id)
                    )
                    task = result.scalar_one_or_none()
                    if task:
                        now = datetime.now(timezone.utc)
                        task.last_run = now
                        task.next_run = now + timedelta(hours=interval_hours)

                        if scan_error and task.status == ScanStatus.running:
                            task.status = ScanStatus.failed
                            task.error_message = "Periodic scan execution error"

                        await db.commit()
            except Exception as e:
                logger.error(f"Periodic scan {scan_task_id} post-update failed: {e}")

            # 等待间隔（扫描完成后才 sleep，确保先执行再等待）
            try:
                await asyncio.sleep(interval_hours * 3600)
            except asyncio.CancelledError:
                break

            if not self._running:
                break

        # 清理
        self._periodic_tasks.pop(scan_task_id, None)
        logger.info(f"Periodic scan {scan_task_id} loop ended")


scheduler_service = SchedulerService()
