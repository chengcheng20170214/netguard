
import asyncio
from datetime import datetime, timezone
from .celery_app import celery_app
from app.database import async_session, engine
from app.models.models import ScanTask, ScanResult, Asset, AssetSnapshot, ScanStatus, ScanMode
from app.services.scanner import SCANNER_REGISTRY
from app.services.change_tracker import create_snapshot, compare_snapshots
from sqlalchemy import select


@celery_app.task(bind=True)
def run_scan_task(self, scan_task_id: int, targets: str, scan_mode: str, scan_methods: list, ports: str | None = None):
    asyncio.run(_run_scan(self, scan_task_id, targets, scan_mode, scan_methods, ports))


async def _run_scan(celery_task, scan_task_id: int, targets: str, scan_mode: str, scan_methods: list, ports: str | None):
    async with async_session() as db:
        result = await db.execute(select(ScanTask).where(ScanTask.id == scan_task_id))
        scan_task = result.scalar_one_or_none()
        if not scan_task:
            return

        scan_task.status = ScanStatus.running
        scan_task.started_at = datetime.now(timezone.utc)
        scan_task.celery_task_id = celery_task.request.id
        await db.commit()

        all_results = {}
        total = len(scan_methods)
        for i, method in enumerate(scan_methods):
            try:
                scanner_cls = SCANNER_REGISTRY.get(method)
                if not scanner_cls:
                    continue
                scanner = scanner_cls()
                scan_results = await scanner.scan(targets, ports, scan_method=method, scan_mode=scan_mode)
                for r in scan_results:
                    ip = r.get("ip")
                    if ip in all_results:
                        existing = all_results[ip]
                        if r.get("ports"):
                            existing_ports = {f"{p['port']}/{p.get('proto','tcp')}" : p for p in (existing.get("ports") or [])}
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
                pass

            progress = int((i + 1) / total * 100) if total else 100
            scan_task.progress = progress
            await db.commit()
            celery_task.update_state(state="PROGRESS", meta={"progress": progress})

        for ip, data in all_results.items():
            scan_result = ScanResult(
                scan_task_id=scan_task_id,
                ip=ip,
                mac=data.get("mac"),
                hostname=data.get("hostname"),
                os=data.get("os"),
                ports=data.get("ports", []),
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
                    select(AssetSnapshot).where(AssetSnapshot.asset_id == asset.id).order_by(AssetSnapshot.created_at.desc()).limit(1)
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
        scan_task.result_summary = {"total_hosts": len(all_results), "total_ports": sum(len(d.get("ports", [])) for d in all_results.values())}
        await db.commit()
