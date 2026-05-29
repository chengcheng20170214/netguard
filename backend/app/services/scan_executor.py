import asyncio
import hashlib
import ipaddress
import logging
import re
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


def _expand_targets_to_ips(targets: str) -> list[str]:
    """将扫描目标展开为具体IP地址列表。

    支持格式：单IP、CIDR网段、IP范围、域名。
    域名保留原样（由nmap解析）。
    """
    ips = []
    for part in targets.replace("\n", " ").split():
        part = part.strip()
        if not part:
            continue
        # CIDR网段
        try:
            network = ipaddress.ip_network(part, strict=False)
            if network.prefixlen < 32:
                for host in network.hosts():
                    ips.append(str(host))
            else:
                ips.append(str(network.network_address))
            continue
        except ValueError:
            pass
        # IP范围 (如 192.168.1.1-254)
        range_match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$', part)
        if range_match:
            prefix = range_match.group(1)
            start = int(range_match.group(2))
            end = int(range_match.group(3))
            for i in range(start, end + 1):
                ips.append(f"{prefix}.{i}")
            continue
        # 单IP
        try:
            ipaddress.ip_address(part)
            ips.append(part)
            continue
        except ValueError:
            pass
        # 域名：保留原样，由nmap解析
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$', part) and '..' not in part:
            ips.append(part)
            continue
        logger.warning(f"Cannot expand target: {part}, keeping as-is")
        ips.append(part)
    return ips


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

# 进度分配：阶段1(0-10%) + 阶段2(10-20%) + 阶段3(20-100%)
PROGRESS_PING_END = 10
PROGRESS_ARP_END = 20


async def run_host_discovery(targets: str, scan_mode: str, ports: str | None, scan_task_id: int, all_results: dict, db: AsyncSession, scan_task: ScanTask):
    """主机发现扫描：三阶段串行（Ping→ARP→TCP端口扫描），阶段3内部按端口块并行。

    - 阶段1 Ping (~5-15秒) → 阶段2 ARP (~5秒) → 阶段3 TCP端口扫描 (最耗时)
    - 阶段3: 全端口拆为5000/块(14块)，Semaphore(并发数)并行
    - 所有nmap操作使用 -sT (TCP Connect)，不需要root权限
    - 每阶段失败不影响后续阶段，端口块失败自动重试2次
    """
    await _append_log(db, scan_task, f"开始主机发现扫描, 目标: {targets}, 并发: {scan_task.max_concurrent or 4}")
    max_concurrent = scan_task.max_concurrent or 4
    phase_errors: dict[str, str] = {}
    total_phase_progress = 0

    # ===== 阶段1: Ping探测 =====
    try:
        scanner_cls = SCANNER_REGISTRY.get("nmap_ping")
        if scanner_cls:
            scanner = scanner_cls()
            async def _ping_progress(msg: str):
                await _append_log(db, scan_task, f"[Ping探测] {msg}")

            await _append_log(db, scan_task, "[Ping探测] 开始")
            ping_results = await scanner.scan(
                targets, ports,
                scan_method="nmap_ping", scan_mode=scan_mode,
                progress_callback=_ping_progress,
                max_concurrent=max_concurrent,
            )
            _merge_results(all_results, ping_results)
            ping_hosts = len(ping_results)
            await _append_log(db, scan_task, f"[Ping探测] 完成: 发现 {ping_hosts} 个存活主机")
            for r in ping_results:
                ip = r.get("ip")
                if ip:
                    await persist_host_incremental(db, scan_task_id, ip, r)
        else:
            await _append_log(db, scan_task, "[Ping探测] 扫描器未注册, 跳过")
    except Exception as e:
        phase_errors["nmap_ping"] = str(e)
        logger.warning(f"Ping discovery failed for task {scan_task_id}: {e}")
        await _append_log(db, scan_task, f"[Ping探测] 失败: {e}, 继续后续阶段")

    total_phase_progress = PROGRESS_PING_END
    scan_task.progress = total_phase_progress
    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(scan_task, "scan_log")
    scan_task.result_summary = {
        "total_hosts": len(all_results),
        "total_ports": sum(len(d.get("ports", [])) for d in all_results.values()),
    }
    flag_modified(scan_task, "result_summary")
    await db.commit()
    yield total_phase_progress, list(phase_errors.values()), []

    # ===== 阶段2: ARP探测 =====
    try:
        scanner_cls = SCANNER_REGISTRY.get("nmap_arp")
        if scanner_cls:
            scanner = scanner_cls()
            async def _arp_progress(msg: str):
                await _append_log(db, scan_task, f"[ARP探测] {msg}")

            await _append_log(db, scan_task, "[ARP探测] 开始")
            arp_results = await scanner.scan(
                targets, ports,
                scan_method="nmap_arp", scan_mode=scan_mode,
                progress_callback=_arp_progress,
                max_concurrent=max_concurrent,
            )
            prev_count = len(all_results)
            _merge_results(all_results, arp_results)
            new_arp = len(all_results) - prev_count
            arp_hosts = len(arp_results)
            await _append_log(db, scan_task, f"[ARP探测] 完成: 发现 {arp_hosts} 个存活主机, 新增 {new_arp}")
            for r in arp_results:
                ip = r.get("ip")
                if ip:
                    await persist_host_incremental(db, scan_task_id, ip, r)
        else:
            await _append_log(db, scan_task, "[ARP探测] 扫描器未注册, 跳过")
    except Exception as e:
        phase_errors["nmap_arp"] = str(e)
        logger.warning(f"ARP discovery failed for task {scan_task_id}: {e}")
        await _append_log(db, scan_task, f"[ARP探测] 失败: {e}, 继续后续阶段")

    total_phase_progress = PROGRESS_ARP_END
    scan_task.progress = total_phase_progress
    flag_modified(scan_task, "scan_log")
    scan_task.result_summary = {
        "total_hosts": len(all_results),
        "total_ports": sum(len(d.get("ports", [])) for d in all_results.values()),
    }
    flag_modified(scan_task, "result_summary")
    await db.commit()
    yield total_phase_progress, list(phase_errors.values()), []

    # ===== 阶段3: TCP端口扫描 (按端口块并发) =====
    tcp_results = []
    try:
        scanner_cls = SCANNER_REGISTRY.get("nmap_syn")
        if scanner_cls:
            scanner = scanner_cls()

            async def _tcp_progress(msg: str):
                await _append_log(db, scan_task, f"[TCP端口扫描] {msg}")

            await _append_log(db, scan_task, "[TCP端口扫描] 开始 (14个端口块并发)")
            tcp_results = await scanner.scan(
                targets, ports,
                scan_method="nmap_syn", scan_mode=scan_mode,
                progress_callback=_tcp_progress,
                max_concurrent=max_concurrent,
            )
            _merge_results(all_results, tcp_results)
            tcp_port_count = sum(len(r.get("ports", [])) for r in tcp_results)
            await _append_log(db, scan_task, f"[TCP端口扫描] 完成: 发现 {tcp_port_count} 个开放端口")
        else:
            await _append_log(db, scan_task, "[TCP端口扫描] 扫描器未注册")
    except Exception as e:
        phase_errors["nmap_syn"] = str(e)
        logger.warning(f"TCP port scan failed for task {scan_task_id}: {e}")
        await _append_log(db, scan_task, f"[TCP端口扫描] 失败: {e}")

    # 持久化最终结果
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

    if "nmap_syn" in phase_errors and total_ports == 0 and total_hosts > 0:
        await _append_log(db, scan_task, f"TCP端口扫描失败, 但Ping/ARP发现 {total_hosts} 个存活主机, 任务标记完成")
    elif "nmap_syn" in phase_errors and total_hosts == 0:
        await _append_log(db, scan_task, "所有扫描阶段均失败")
    else:
        await _append_log(db, scan_task, f"主机发现扫描完成: 共 {total_hosts} 主机, {total_ports} 开放端口")

    progress = 100
    yield progress, errors, new_results_data


async def run_host_discovery_ip_sequential(targets: str, scan_mode: str, ports: str | None, scan_task_id: int, all_results: dict, db: AsyncSession, scan_task: ScanTask):
    """主机发现扫描（逐IP分端口策略）：三阶段串行，阶段3多IP并发扫描。

    - 阶段1 Ping → 阶段2 ARP → 阶段3 逐IP分端口扫描
    - 阶段3: 从targets展开所有IP，多个IP并发扫描
    - max_concurrent 控制**同时运行的 nmap 进程数**（全局共享）
    - 每个 IP 内部的端口块扫描和跨 IP 的扫描共享同一 Semaphore
    - 进度按IP数量划分: 阶段3进度 = 20 + (已完成IP数 / 总IP数) × 80
    """
    max_concurrent = scan_task.max_concurrent or 4
    await _append_log(db, scan_task, f"开始主机发现扫描(逐IP策略), 目标: {targets}, 并发: {max_concurrent}")
    phase_errors: dict[str, str] = {}

    # ===== 阶段1: Ping探测 =====
    try:
        scanner_cls = SCANNER_REGISTRY.get("nmap_ping")
        if scanner_cls:
            scanner = scanner_cls()
            async def _ping_progress(msg: str):
                await _append_log(db, scan_task, f"[Ping探测] {msg}")

            await _append_log(db, scan_task, "[Ping探测] 开始")
            ping_results = await scanner.scan(
                targets, ports,
                scan_method="nmap_ping", scan_mode=scan_mode,
                progress_callback=_ping_progress,
                max_concurrent=max_concurrent,
            )
            _merge_results(all_results, ping_results)
            await _append_log(db, scan_task, f"[Ping探测] 完成: 发现 {len(ping_results)} 个存活主机")
            for r in ping_results:
                ip = r.get("ip")
                if ip:
                    await persist_host_incremental(db, scan_task_id, ip, r)
        else:
            await _append_log(db, scan_task, "[Ping探测] 扫描器未注册, 跳过")
    except Exception as e:
        phase_errors["nmap_ping"] = str(e)
        logger.warning(f"Ping discovery failed for task {scan_task_id}: {e}")
        await _append_log(db, scan_task, f"[Ping探测] 失败: {e}, 继续后续阶段")

    scan_task.progress = PROGRESS_PING_END
    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(scan_task, "scan_log")
    scan_task.result_summary = {
        "total_hosts": len(all_results),
        "total_ports": sum(len(d.get("ports", [])) for d in all_results.values()),
    }
    flag_modified(scan_task, "result_summary")
    await db.commit()
    yield PROGRESS_PING_END, list(phase_errors.values()), []

    # ===== 阶段2: ARP探测 =====
    try:
        scanner_cls = SCANNER_REGISTRY.get("nmap_arp")
        if scanner_cls:
            scanner = scanner_cls()
            async def _arp_progress(msg: str):
                await _append_log(db, scan_task, f"[ARP探测] {msg}")

            await _append_log(db, scan_task, "[ARP探测] 开始")
            arp_results = await scanner.scan(
                targets, ports,
                scan_method="nmap_arp", scan_mode=scan_mode,
                progress_callback=_arp_progress,
                max_concurrent=max_concurrent,
            )
            prev_count = len(all_results)
            _merge_results(all_results, arp_results)
            new_arp = len(all_results) - prev_count
            await _append_log(db, scan_task, f"[ARP探测] 完成: 发现 {len(arp_results)} 个存活主机, 新增 {new_arp}")
            for r in arp_results:
                ip = r.get("ip")
                if ip:
                    await persist_host_incremental(db, scan_task_id, ip, r)
        else:
            await _append_log(db, scan_task, "[ARP探测] 扫描器未注册, 跳过")
    except Exception as e:
        phase_errors["nmap_arp"] = str(e)
        logger.warning(f"ARP discovery failed for task {scan_task_id}: {e}")
        await _append_log(db, scan_task, f"[ARP探测] 失败: {e}, 继续后续阶段")

    scan_task.progress = PROGRESS_ARP_END
    flag_modified(scan_task, "scan_log")
    scan_task.result_summary = {
        "total_hosts": len(all_results),
        "total_ports": sum(len(d.get("ports", [])) for d in all_results.values()),
    }
    flag_modified(scan_task, "result_summary")
    await db.commit()
    yield PROGRESS_ARP_END, list(phase_errors.values()), []

    # ===== 阶段3: 逐IP分端口扫描（多IP并发，共享全局 Semaphore） =====
    ip_list = _expand_targets_to_ips(targets)
    total_ips = len(ip_list)
    await _append_log(db, scan_task, f"[逐IP分端口扫描] 展开 {total_ips} 个IP地址, 并发数 {max_concurrent}")

    scanner_cls = SCANNER_REGISTRY.get("nmap_syn")
    if not scanner_cls:
        await _append_log(db, scan_task, "[逐IP分端口扫描] 扫描器未注册")
        progress = 100
        yield progress, list(phase_errors.values()), []
        return

    scanner = scanner_cls()
    completed_ips = 0
    # 全局 Semaphore: 控制同时运行的 nmap 进程总数
    # 每个 IP 的 scanner.scan() 内部也会创建端口块并发任务，它们共享此信号量
    global_semaphore = asyncio.Semaphore(max_concurrent)

    async def _scan_single_ip(ip_idx: int, ip_target: str):
        """扫描单个IP的所有端口块，受全局 Semaphore 约束。"""
        nonlocal completed_ips
        await _append_log(db, scan_task, f"[逐IP分端口扫描] 开始扫描 IP {ip_idx + 1}/{total_ips}: {ip_target}")

        ip_results = []
        try:
            async def _ip_tcp_progress(msg: str):
                await _append_log(db, scan_task, f"[TCP端口扫描][{ip_target}] {msg}")

            # 将全局 Semaphore 传入 scanner，让端口块级并发也共享同一配额
            ip_results = await scanner.scan(
                ip_target, ports,
                scan_method="nmap_syn", scan_mode=scan_mode,
                progress_callback=_ip_tcp_progress,
                max_concurrent=max_concurrent,
                _global_semaphore=global_semaphore,
            )
            _merge_results(all_results, ip_results)
            ip_port_count = sum(len(r.get("ports", [])) for r in ip_results)
            await _append_log(db, scan_task, f"[逐IP分端口扫描] IP {ip_target} 完成: 发现 {ip_port_count} 个开放端口")
        except Exception as e:
            phase_errors[f"nmap_syn_{ip_target}"] = str(e)
            logger.warning(f"TCP port scan failed for IP {ip_target} in task {scan_task_id}: {e}")
            await _append_log(db, scan_task, f"[逐IP分端口扫描] IP {ip_target} 失败: {e}")

        # 持久化该IP结果
        for r in ip_results:
            r_ip = r.get("ip")
            if r_ip:
                await persist_host_incremental(db, scan_task_id, r_ip, r)

        completed_ips += 1

        # 计算进度: 阶段3进度 = 20 + (已完成IP数 / 总IP数) × 80
        progress = int(PROGRESS_ARP_END + (completed_ips / total_ips) * 80) if total_ips > 0 else 100
        scan_task.progress = progress
        flag_modified(scan_task, "scan_log")
        scan_task.result_summary = {
            "total_hosts": len(all_results),
            "total_ports": sum(len(d.get("ports", [])) for d in all_results.values()),
        }
        flag_modified(scan_task, "result_summary")
        await db.commit()

    # 并发启动所有IP扫描任务
    ip_tasks = [
        asyncio.create_task(_scan_single_ip(ip_idx, ip_target))
        for ip_idx, ip_target in enumerate(ip_list)
    ]
    await asyncio.gather(*ip_tasks)

    # 最终持久化
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

    if total_hosts > 0:
        await _append_log(db, scan_task, f"逐IP扫描完成: 共 {total_hosts} 主机, {total_ports} 开放端口")
    else:
        await _append_log(db, scan_task, "所有扫描阶段均失败")

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
            scan_mode_val = scan_task.scan_mode.value if hasattr(scan_task.scan_mode, 'value') else scan_task.scan_mode

            if is_host_discovery:
                # 根据 scan_mode 选择扫描策略
                if scan_mode_val == "ip_sequential":
                    scan_gen = run_host_discovery_ip_sequential(
                        scan_task.targets, scan_mode_val,
                        scan_task.ports, scan_task_id, all_results, db, scan_task
                    )
                else:
                    scan_gen = run_host_discovery(
                        scan_task.targets, scan_mode_val,
                        scan_task.ports, scan_task_id, all_results, db, scan_task
                    )

                async for progress, errors, new_results in scan_gen:
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
                await _append_log(db, scan_task, f"开始服务发现扫描, 目标: {scan_task.targets}, 模式: {scan_mode_val}")
                async for progress, errors, new_results in run_scan_methods(
                    scan_task.targets, scan_mode_val,
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
        'total': sum(counts.values()),
        'completed': counts.get('completed', 0),
        'failed': counts.get('failed', 0),
        'pending': counts.get('pending', 0),
    }