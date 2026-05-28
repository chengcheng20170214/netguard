
import asyncio
import hashlib
import logging
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import async_session
from app.models.models import ScanTask, ScanResult, Asset, AssetSnapshot, ScanStatus, ScanChunk, ScanChunkStatus
from app.services.scanner import SCANNER_REGISTRY
from app.services.change_tracker import create_snapshot, compare_snapshots
from app.config import settings

logger = logging.getLogger(__name__)


def generate_fingerprint(mac: str | None, hostname: str | None, os: str | None, ip: str) -> str:
    if mac:
        raw = f"mac:{mac}"
    elif hostname and os:
        raw = f"host:{hostname}|os:{os}"
    else:
        raw = f"ip:{ip}"
    return hashlib.sha256(raw.encode()).hexdigest()


async def _append_log(db: AsyncSession, scan_task: ScanTask, message: str):
    if scan_task.scan_log is None:
        scan_task.scan_log = []
    scan_task.scan_log.append({
        "ts": datetime.now(timezone.utc).isoformat(),
        "msg": message
    })
    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(scan_task, "scan_log")
    await db.commit()


def _build_chunk_ranges(chunk_size: int | None = None) -> list[tuple[int, int]]:
    size = chunk_size or settings.SCAN_CHUNK_SIZE
    ranges = []
    start = 1
    while start <= 65535:
        end = min(start + size - 1, 65535)
        ranges.append((start, end))
        start = end + 1
    return ranges


async def _ensure_chunks(db: AsyncSession, scan_task_id: int, scan_task: ScanTask):
    existing = await db.execute(
        select(ScanChunk).where(ScanChunk.scan_task_id == scan_task_id)
    )
    if existing.scalars().first():
        return

    chunk_ranges = _build_chunk_ranges()
    for port_start, port_end in chunk_ranges:
        chunk = ScanChunk(
            scan_task_id=scan_task_id,
            port_start=port_start,
            port_end=port_end,
            status=ScanChunkStatus.pending,
        )
        db.add(chunk)
    await db.commit()
    await _append_log(db, scan_task, f"已创建 {len(chunk_ranges)} 个扫描分块 (每块 {settings.SCAN_CHUNK_SIZE} 端口)")


async def _retry_failed_chunks(db: AsyncSession, scan_task_id: int, scan_task: ScanTask):
    max_retries = settings.SCAN_CHUNK_MAX_RETRIES
    result = await db.execute(
        select(ScanChunk).where(
            ScanChunk.scan_task_id == scan_task_id,
            ScanChunk.status == ScanChunkStatus.failed,
            ScanChunk.retry_count < max_retries,
        )
    )
    failed_chunks = result.scalars().all()
    if not failed_chunks:
        return 0

    for chunk in failed_chunks:
        chunk.status = ScanChunkStatus.pending
        chunk.retry_count += 1
        chunk.error_message = None
    await db.commit()

    await _append_log(db, scan_task, f"重试 {len(failed_chunks)} 个失败分块 (重试次数上限: {max_retries})")
    return len(failed_chunks)


HOST_DISCOVERY_PIPELINE = ["nmap_ping", "nmap_arp", "nmap_syn"]


async def run_host_discovery(targets: str, scan_mode: str, ports: str | None, scan_task_id: int, all_results: dict, db: AsyncSession, scan_task: ScanTask):
    """主机发现扫描：Ping/ARP/SYN 三阶段并行执行，结果合并去重。

    - Ping 和 ARP 快速发现存活性（~5-15秒）
    - SYN 端口扫描按端口块并发（最耗时，但数据最完整）
    - 三者并行启动，SYN 结束后整体完成
    """
    await _append_log(db, scan_task, f"开始主机发现扫描 (并行模式), 目标: {targets}, 模式: {scan_mode}")

    max_concurrent = scan_task.max_concurrent or 4
    phase_results: dict[str, list[dict]] = {}
    phase_errors: dict[str, str] = {}

    async def _run_phase(method: str, label: str):
        """执行单个扫描阶段。"""
        try:
            scanner_cls = SCANNER_REGISTRY.get(method)
            if not scanner_cls:
                await _append_log(db, scan_task, f"跳过未注册方法: {method}")
                return

            scanner = scanner_cls()

            async def _progress_cb(msg: str):
                await _append_log(db, scan_task, f"[{label}] {msg}")

            await _append_log(db, scan_task, f"[{label}] 开始")
            results = await scanner.scan(
                targets, ports,
                scan_method=method, scan_mode=scan_mode,
                progress_callback=_progress_cb,
                max_concurrent=max_concurrent,
            )
            phase_results[method] = results
            host_count = len(results)
            port_count = sum(len(r.get("ports", [])) for r in results)
            await _append_log(db, scan_task, f"[{label}] 完成: 发现 {host_count} 主机, {port_count} 开放端口")
        except Exception as e:
            phase_errors[method] = str(e)
            logger.warning(f"Host discovery method {method} failed for task {scan_task_id}: {e}")
            await _append_log(db, scan_task, f"[{label}] 失败: {e}")

    # 三阶段并行执行
    phase_labels = {"nmap_ping": "Ping探测", "nmap_arp": "ARP探测", "nmap_syn": "SYN端口扫描"}
    await asyncio.gather(*[
        _run_phase(method, phase_labels.get(method, method))
        for method in HOST_DISCOVERY_PIPELINE
    ])

    # 合并结果：SYN > ARP > Ping 优先级
    merge_order = ["nmap_ping", "nmap_arp", "nmap_syn"]  # 低→高优先级，后写入覆盖
    for method in merge_order:
        results = phase_results.get(method, [])
        _merge_results(all_results, results)

    # 持久化增量结果
    new_results_data = []
    for r in all_results.values():
        ip = r.get("ip")
        if ip:
            persisted = await persist_host_incremental(db, scan_task_id, ip, r)
            if persisted:
                new_results_data.append(persisted)

    errors = list(phase_errors.values())
    total_hosts = len(all_results)
    total_ports = sum(len(r.get("ports", [])) for r in all_results.values())
    await _append_log(db, scan_task, f"主机发现扫描完成: 共 {total_hosts} 主机, {total_ports} 开放端口")

    progress = 100
    yield progress, errors, new_results_data


async def run_chunked_full_scan(
    targets: str, scan_mode: str, scan_task_id: int,
    all_results: dict, db: AsyncSession, scan_task: ScanTask
):
    await _ensure_chunks(db, scan_task_id, scan_task)
    retried = await _retry_failed_chunks(db, scan_task_id, scan_task)

    chunk_result = await db.execute(
        select(ScanChunk).where(
            ScanChunk.scan_task_id == scan_task_id,
            ScanChunk.status.in_([ScanChunkStatus.pending, ScanChunkStatus.running]),
        ).order_by(ScanChunk.port_start)
    )
    pending_chunks = chunk_result.scalars().all()

    if not pending_chunks:
        completed_result = await db.execute(
            select(ScanChunk).where(
                ScanChunk.scan_task_id == scan_task_id,
                ScanChunk.status == ScanChunkStatus.completed,
            )
        )
        completed_count = len(completed_result.scalars().all())
        total_result = await db.execute(
            select(ScanChunk).where(ScanChunk.scan_task_id == scan_task_id)
        )
        total_count = len(total_result.scalars().all())
        if completed_count == total_count:
            yield 100, [], []
            return

    scanner_cls = SCANNER_REGISTRY.get("nmap_syn_full")
    if not scanner_cls:
        yield 0, ["nmap_syn_full scanner not registered"], []
        return
    scanner = scanner_cls()

    total_chunks_result = await db.execute(
        select(ScanChunk).where(ScanChunk.scan_task_id == scan_task_id)
    )
    total_chunks = len(total_chunks_result.scalars().all())
    errors = []

    for chunk in pending_chunks:
        chunk.status = ScanChunkStatus.running
        chunk.started_at = datetime.now(timezone.utc)
        await db.commit()

        port_spec = f"{chunk.port_start}-{chunk.port_end}"
        await _append_log(db, scan_task, f"分块扫描端口 {port_spec} ...")

        new_results_data = []
        try:
            scan_results = await scanner.scan(
                targets, port_spec,
                scan_method="nmap_syn_full", scan_mode=scan_mode,
            )
            chunk_open = []
            for r in scan_results:
                ip = r.get("ip")
                if not ip:
                    continue
                if r.get("ports"):
                    for p in r["ports"]:
                        if chunk.port_start <= p["port"] <= chunk.port_end:
                            chunk_open.append(p)

            _merge_results(all_results, scan_results)

            for r in scan_results:
                ip = r.get("ip")
                if ip:
                    persisted = await persist_host_incremental(db, scan_task_id, ip, r)
                    if persisted:
                        new_results_data.append(persisted)

            chunk.status = ScanChunkStatus.completed
            chunk.open_ports = chunk_open
            chunk.completed_at = datetime.now(timezone.utc)
            await db.commit()

            open_count = len(chunk_open)
            await _append_log(db, scan_task, f"端口 {port_spec} 完成, {open_count} 个开放端口")

        except Exception as e:
            logger.warning(f"Chunk {port_spec} failed for task {scan_task_id}: {e}")
            chunk.status = ScanChunkStatus.failed
            chunk.error_message = str(e)
            chunk.retry_count += 1
            await db.commit()
            errors.append(f"{port_spec}: {e}")
            await _append_log(db, scan_task, f"端口 {port_spec} 失败: {e}")

        completed_result = await db.execute(
            select(ScanChunk).where(
                ScanChunk.scan_task_id == scan_task_id,
                ScanChunk.status == ScanChunkStatus.completed,
            )
        )
        completed_count = len(completed_result.scalars().all())
        progress = int(completed_count / total_chunks * 100) if total_chunks else 100
        yield progress, errors, new_results_data


async def run_scan_methods(targets: str, scan_mode: str, scan_methods: list, ports: str | None, scan_task_id: int, all_results: dict, db: AsyncSession = None, scan_task: ScanTask = None):
    has_full_scan = "nmap_syn_full" in scan_methods
    other_methods = [m for m in scan_methods if m != "nmap_syn_full"]

    if has_full_scan:
        if db and scan_task:
            await _append_log(db, scan_task, "开始全端口分块扫描 (SYN Full)")
        async for progress, errors, new_results in run_chunked_full_scan(
            targets, scan_mode, scan_task_id, all_results, db, scan_task
        ):
            yield progress, errors, new_results

    if other_methods and db and scan_task:
        await _append_log(db, scan_task, f"开始执行其他扫描方法: {', '.join(other_methods)}")

    total = len(other_methods)
    errors = []
    for i, method in enumerate(other_methods):
        new_results_data = []
        try:
            scanner_cls = SCANNER_REGISTRY.get(method)
            if not scanner_cls:
                if db and scan_task:
                    await _append_log(db, scan_task, f"跳过未注册的扫描方法: {method}")
                continue
            scanner = scanner_cls()
            if db and scan_task:
                await _append_log(db, scan_task, f"开始执行扫描方法: {method}")
            scan_results = await scanner.scan(targets, ports, scan_method=method, scan_mode=scan_mode)
            _merge_results(all_results, scan_results)

            if db and scan_task_id:
                for r in scan_results:
                    ip = r.get("ip")
                    if ip:
                        persisted = await persist_host_incremental(db, scan_task_id, ip, r)
                        if persisted:
                            new_results_data.append(persisted)

            if db and scan_task:
                await _append_log(db, scan_task, f"扫描方法 {method} 完成, 发现 {len(scan_results)} 个结果")
        except Exception as e:
            logger.warning(f"Scan method {method} failed for task {scan_task_id}: {e}")
            errors.append(f"{method}: {e}")
            if db and scan_task:
                await _append_log(db, scan_task, f"扫描方法 {method} 失败: {e}")

        base_progress = 0
        if has_full_scan:
            base_progress = 100
        method_progress = int((i + 1) / total * 100) if total else 100
        if has_full_scan:
            progress = base_progress
        else:
            progress = method_progress
        yield progress, errors, new_results_data


def _merge_results(all_results: dict, scan_results: list[dict]):
    for r in scan_results:
        ip = r.get("ip")
        if not ip:
            continue
        if ip in all_results:
            existing = all_results[ip]
            if r.get("ports"):
                existing_ports = {f"{p['port']}/{p.get('proto', 'tcp')}": p for p in (existing.get("ports") or [])}
                for p in r["ports"]:
                    key = f"{p['port']}/{p.get('proto', 'tcp')}"
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


async def persist_host_incremental(db: AsyncSession, scan_task_id: int, ip: str, data: dict) -> dict | None:
    from app.models.models import AssetChange, ChangeType, ChangeSeverity

    mac = data.get("mac")
    hostname = data.get("hostname")
    os_name = data.get("os")
    fp = generate_fingerprint(mac, hostname, os_name, ip)

    asset = None
    fp_result = await db.execute(select(Asset).where(Asset.fingerprint == fp))
    asset = fp_result.scalar_one_or_none()

    if asset and asset.ip != ip:
        old_ip = asset.ip
        asset.ip = ip
        change = AssetChange(
            asset_id=asset.id, ip=ip, change_type=ChangeType.ip_changed,
            detail={"field": "ip", "old": old_ip, "new": ip},
            severity=ChangeSeverity.info, detected_at=datetime.now(timezone.utc)
        )
        db.add(change)
    elif not asset:
        ip_result = await db.execute(select(Asset).where(Asset.ip == ip))
        asset = ip_result.scalar_one_or_none()
        if asset and not asset.fingerprint:
            asset.fingerprint = fp

    scan_result = ScanResult(
        scan_task_id=scan_task_id, ip=ip, mac=mac,
        hostname=hostname, os=os_name,
        ports=data.get("ports", []), created_at=datetime.now(timezone.utc)
    )
    db.add(scan_result)

    if not asset:
        asset = Asset(
            ip=ip, mac=mac, hostname=hostname, os=os_name,
            fingerprint=fp, current_ports=data.get("ports", []),
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

        existing_port_keys = {f"{p['port']}/{p.get('proto', 'tcp')}" for p in (asset.current_ports or [])}
        merged_ports = list(asset.current_ports or [])
        for p in (data.get("ports") or []):
            key = f"{p['port']}/{p.get('proto', 'tcp')}"
            if key not in existing_port_keys:
                merged_ports.append(p)
                existing_port_keys.add(key)

        asset.mac = mac or asset.mac
        asset.hostname = hostname or asset.hostname
        asset.os = os_name or asset.os
        asset.current_ports = merged_ports
        asset.is_online = True
        asset.last_seen = datetime.now(timezone.utc)
        if not asset.fingerprint:
            asset.fingerprint = fp
        await db.commit()
        await db.refresh(asset)

        new_snapshot = await create_snapshot(db, asset, scan_task_id)
        if prev_snapshot:
            await compare_snapshots(db, prev_snapshot, new_snapshot)

    await db.refresh(scan_result)
    return {
        "id": scan_result.id,
        "scan_task_id": scan_task_id,
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "os": os_name,
        "ports": data.get("ports", []),
        "created_at": scan_result.created_at.isoformat() if scan_result.created_at else None,
    }


async def persist_results(db: AsyncSession, scan_task_id: int, all_results: dict):
    for ip, data in all_results.items():
        await persist_host_incremental(db, scan_task_id, ip, data)


async def execute_scan(scan_task_id: int, progress_callback=None, celery_task_id: str | None = None):
    async with async_session() as db:
        result = await db.execute(select(ScanTask).where(ScanTask.id == scan_task_id))
        scan_task = result.scalar_one_or_none()
        if not scan_task:
            return

        scan_task.status = ScanStatus.running
        scan_task.started_at = datetime.now(timezone.utc)
        scan_task.progress = 0
        scan_task.scan_log = [{"ts": datetime.now(timezone.utc).isoformat(), "msg": "任务开始执行"}]
        if celery_task_id:
            scan_task.celery_task_id = celery_task_id
        await db.commit()

        all_results = {}
        try:
            scan_methods = scan_task.scan_methods or []
            all_errors = []

            cat = scan_task.scan_category
            is_host_discovery = cat is not None and (cat.value if hasattr(cat, 'value') else str(cat)) == 'host_discovery'

            if is_host_discovery:
                async for progress, errors, new_results in run_host_discovery(
                    scan_task.targets, scan_task.scan_mode.value if hasattr(scan_task.scan_mode, 'value') else scan_task.scan_mode,
                    scan_task.ports, scan_task_id, all_results, db, scan_task
                ):
                    scan_task.progress = progress
                    all_errors = errors

                    scan_task.result_summary = {
                        "total_hosts": len(all_results),
                        "total_ports": sum(len(d.get("ports", [])) for d in all_results.values()),
                        "new_results": new_results,
                    }
                    from sqlalchemy.orm.attributes import flag_modified
                    flag_modified(scan_task, "result_summary")
                    await db.commit()
                    if progress_callback:
                        progress_callback(progress)
            else:
                await _append_log(db, scan_task, f"开始服务发现扫描, 目标: {scan_task.targets}, 模式: {scan_task.scan_mode.value if hasattr(scan_task.scan_mode, 'value') else scan_task.scan_mode}")
                async for progress, errors, new_results in run_scan_methods(
                    scan_task.targets, scan_task.scan_mode.value if hasattr(scan_task.scan_mode, 'value') else scan_task.scan_mode,
                    scan_methods, scan_task.ports, scan_task_id, all_results,
                    db=db, scan_task=scan_task
                ):
                    scan_task.progress = progress
                    all_errors = errors

                    scan_task.result_summary = {
                        "total_hosts": len(all_results),
                        "total_ports": sum(len(d.get("ports", [])) for d in all_results.values()),
                        "new_results": new_results,
                        "chunk_stats": await _get_chunk_stats(db, scan_task_id),
                    }
                    from sqlalchemy.orm.attributes import flag_modified
                    flag_modified(scan_task, "result_summary")
                    await db.commit()
                    if progress_callback:
                        progress_callback(progress)

            chunk_stats = await _get_chunk_stats(db, scan_task_id)

            await _append_log(db, scan_task, f"扫描完成, 共发现 {len(all_results)} 个主机")

            if chunk_stats["failed"] > 0:
                scan_task.status = ScanStatus.completed
                scan_task.error_message = f"{chunk_stats['failed']}/{chunk_stats['total']} 个分块失败 (可重跑任务自动重试)"
                await _append_log(db, scan_task, f"部分分块失败: {scan_task.error_message}")
            elif not all_results and all_errors:
                scan_task.status = ScanStatus.failed
                scan_task.error_message = "; ".join(all_errors)
                await _append_log(db, scan_task, f"任务失败: {scan_task.error_message}")
            else:
                scan_task.status = ScanStatus.completed
                await _append_log(db, scan_task, "任务成功完成")
        except Exception as e:
            logger.error(f"Scan task {scan_task_id} failed with exception: {e}")
            scan_task.status = ScanStatus.failed
            scan_task.error_message = str(e)
            await _append_log(db, scan_task, f"任务异常: {e}")

        scan_task.completed_at = datetime.now(timezone.utc)
        scan_task.progress = 100
        scan_task.result_summary = {
            "total_hosts": len(all_results),
            "total_ports": sum(len(d.get("ports", [])) for d in all_results.values()),
            "chunk_stats": await _get_chunk_stats(db, scan_task_id),
        }
        await db.commit()


async def _get_chunk_stats(db: AsyncSession, scan_task_id: int) -> dict:
    from sqlalchemy import func
    result = await db.execute(
        select(ScanChunk.status, func.count(ScanChunk.id))
        .where(ScanChunk.scan_task_id == scan_task_id)
        .group_by(ScanChunk.status)
    )
    counts = {row[0].value if hasattr(row[0], 'value') else str(row[0]): row[1] for row in result.all()}
    return {
        "total": sum(counts.values()),
        "completed": counts.get("completed", 0),
        "failed": counts.get("failed", 0),
        "pending": counts.get("pending", 0),
    }
