
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
        from sqlalchemy import select

        while self._running:
            try:
                async with async_session() as db:
                    result = await db.execute(select(ScanTask).where(ScanTask.id == scan_task_id))
                    task = result.scalar_one_or_none()
                    if not task or not task.is_active or task.scan_type != ScanType.periodic:
                        break

                    next_run = datetime.now(timezone.utc) + timedelta(minutes=interval_minutes)
                    task.next_run = next_run
                    await db.commit()

                await self._execute_scan(scan_task_id)

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

            await asyncio.sleep(interval_minutes * 60)

        self._periodic_tasks.pop(scan_task_id, None)

    async def _execute_scan(self, scan_task_id: int):
        from app.database import async_session
        from app.models.models import ScanTask, ScanResult, Asset, AssetSnapshot, ScanStatus
        from app.services.scanner import SCANNER_REGISTRY
        from app.services.change_tracker import create_snapshot, compare_snapshots
        from sqlalchemy import select

        async with async_session() as db:
            result = await db.execute(select(ScanTask).where(ScanTask.id == scan_task_id))
            scan_task = result.scalar_one_or_none()
            if not scan_task:
                return

            scan_task.status = ScanStatus.running
            scan_task.started_at = datetime.now(timezone.utc)
            scan_task.progress = 0
            await db.commit()

            all_results = {}
            scan_methods = scan_task.scan_methods or []
            total = len(scan_methods)

            for i, method in enumerate(scan_methods):
                try:
                    scanner_cls = SCANNER_REGISTRY.get(method)
                    if not scanner_cls:
                        continue
                    scanner = scanner_cls()
                    scan_results = await scanner.scan(
                        scan_task.targets, scan_task.ports,
                        scan_method=method, scan_mode=scan_task.scan_mode.value
                    )
                    for r in scan_results:
                        ip = r.get("ip")
                        if ip in all_results:
                            existing = all_results[ip]
                            if r.get("ports"):
                                existing_ports = {f"{p['port']}/{p.get('proto','tcp')}": p for p in (existing.get("ports") or [])}
                                for p in r["ports"]:
                                    key = f"{p['port']}/{p.get('proto','tcp')}"
                                    if key not in existing_ports:
                                        existing.setdefault("ports", []).append(p)
                                        existing_ports[key] = p
                            if r.get("os") and not existing.get("os"):
                                existing["os"] = r["os"]
                            if r.get("hostname") and not existing.get("hostname"):
                                existing["hostname"] = r["hostname"]
                            if r.get("mac") and not existing.get("mac"):
                                existing["mac"] = r["mac"]
                        else:
                            all_results[ip] = r
                except Exception as e:
                    scan_task.error_message = f"扫描方法 {method} 失败: {str(e)}"
                    await db.commit()
                    logger.warning(f"Scan method {method} failed for task {scan_task_id}: {e}")

                progress = int((i + 1) / total * 100) if total else 100
                scan_task.progress = progress
                await db.commit()

            for ip, data in all_results.items():
                scan_result = ScanResult(
                    scan_task_id=scan_task_id, ip=ip,
                    mac=data.get("mac"), hostname=data.get("hostname"),
                    os=data.get("os"), ports=data.get("ports", []),
                    created_at=datetime.now(timezone.utc)
                )
                db.add(scan_result)

                asset_result = await db.execute(select(Asset).where(Asset.ip == ip))
                asset = asset_result.scalar_one_or_none()

                if not asset:
                    asset = Asset(
                        ip=ip, mac=data.get("mac"), hostname=data.get("hostname"),
                        os=data.get("os"), current_ports=data.get("ports", []),
                        is_online=True, first_seen=datetime.now(timezone.utc),
                        last_seen=datetime.now(timezone.utc)
                    )
                    db.add(asset)
                    await db.commit()
                    await db.refresh(asset)
                    await create_snapshot(db, asset, scan_task_id)
                else:
                    prev_snapshot_result = await db.execute(
                        select(AssetSnapshot).where(AssetSnapshot.asset_id == asset.id)
                        .order_by(AssetSnapshot.created_at.desc()).limit(1)
                    )
                    prev_snapshot = prev_snapshot_result.scalar_one_or_none()
                    asset.mac = data.get("mac") or asset.mac
                    asset.hostname = data.get("hostname") or asset.hostname
                    asset.os = data.get("os") or asset.os
                    asset.current_ports = data.get("ports", asset.current_ports)
                    asset.is_online = True
                    asset.last_seen = datetime.now(timezone.utc)
                    await db.commit()
                    await db.refresh(asset)
                    new_snapshot = await create_snapshot(db, asset, scan_task_id)
                    if prev_snapshot:
                        await compare_snapshots(db, prev_snapshot, new_snapshot)

            scan_task.status = ScanStatus.completed
            scan_task.completed_at = datetime.now(timezone.utc)
            scan_task.progress = 100
            scan_task.result_summary = {
                "total_hosts": len(all_results),
                "total_ports": sum(len(d.get("ports", [])) for d in all_results.values())
            }
            await db.commit()


scheduler_service = SchedulerService()
