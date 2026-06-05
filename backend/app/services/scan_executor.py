"""
扫描执行引擎 — 支持新旧两种模式:

旧模式 (scan_methods): 兼容主机发现和旧式服务发现，无断点恢复
新模式 (scan_profile): 渐进式服务发现，阶段式探测 + 断点恢复 + 结果直写DB

核心设计理念:
  阶段1(端口发现) → 阶段2+3(服务识别+脚本扫描，始终合并) → 阶段4(OS识别)
  每个阶段只对上一阶段发现的开放端口做定向探测，避免重复扫描
  任何阶段、任何时刻中断，重启后都能从断点续跑，不丢失已完成结果
"""
import asyncio
import hashlib
import ipaddress
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.database import async_session
from app.models.models import (
    ScanTask, ScanResult, Asset, AssetSnapshot, ScanStatus,
    ScanChunk, ScanChunkStatus, ScanProfile, ScanCheckpoint,
)
from app.services.scanner import SCANNER_REGISTRY
from app.services.scanner.nmap_scanner import NmapScanner
from app.services.change_tracker import create_snapshot, compare_snapshots
from app.config import settings

logger = logging.getLogger(__name__)

# 全局 DB 写入锁：防止并发 asyncio 任务同时 commit 同一个 session
_db_lock = asyncio.Lock()

# 端口分块大小（旧引擎全端口扫描用）
PORT_CHUNK_SIZE = 5000


# ========================================================================
# 取消信号管理
# ========================================================================
_cancel_events: dict[int, asyncio.Event] = {}


def request_cancel(scan_task_id: int):
    """请求取消扫描任务"""
    if scan_task_id in _cancel_events:
        _cancel_events[scan_task_id].set()


async def _check_cancelled(scan_task_id: int):
    """检查是否被请求取消，如果已取消则抛出 CancelledError"""
    if scan_task_id in _cancel_events and _cancel_events[scan_task_id].is_set():
        raise asyncio.CancelledError(f"任务 {scan_task_id} 被用户取消")


# ========================================================================
# 通用工具函数（新旧引擎共用）
# ========================================================================

def generate_fingerprint(mac: str | None, hostname: str | None, os: str | None, ip: str) -> str:
    """基于 mac/hostname+os/ip 生成 SHA256 指纹，用于资产去重"""
    if mac:
        raw = f"mac:{mac}"
    elif hostname and os:
        raw = f"host:{hostname}|os:{os}"
    else:
        raw = f"ip:{ip}"
    return hashlib.sha256(raw.encode()).hexdigest()


async def _append_log(db: AsyncSession, scan_task: ScanTask, message: str):
    """安全追加日志：通过全局锁防止并发 commit 导致 SQLAlchemy 错误"""
    async with _db_lock:
        if scan_task.scan_log is None:
            scan_task.scan_log = []
        scan_task.scan_log.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "msg": message
        })
        flag_modified(scan_task, "scan_log")
        await db.commit()


async def _append_log_to_task(scan_task_id: int, message: str):
    """通过 task_id 追加日志（独立获取 session 和 task 对象，避免 session 冲突）"""
    async with async_session() as db:
        result = await db.execute(select(ScanTask).where(ScanTask.id == scan_task_id))
        task = result.scalar_one_or_none()
        if task:
            await _append_log(db, task, message)


async def _update_progress(db: AsyncSession, scan_task: ScanTask, progress: int, all_results: dict):
    """更新扫描进度和摘要，通过全局锁安全写入（旧引擎用）"""
    async with _db_lock:
        scan_task.progress = progress
        flag_modified(scan_task, "scan_log")
        scan_task.result_summary = {
            "total_hosts": len(all_results),
            "total_ports": sum(len(d.get("ports", [])) for d in all_results.values()),
        }
        flag_modified(scan_task, "result_summary")
        await db.commit()


def _build_port_ranges(chunk_size: int = PORT_CHUNK_SIZE) -> list[tuple[int, int]]:
    """将 1-65535 拆分为端口块列表"""
    ranges = []
    start = 1
    while start <= 65535:
        end = min(start + chunk_size - 1, 65535)
        ranges.append((start, end))
        start = end + 1
    return ranges


def _expand_targets_to_ips(targets: str) -> list[str]:
    """将扫描目标展开为具体IP地址列表

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


def _split_ips_into_groups(ip_list: list[str], group_size: int) -> list[list[str]]:
    """将IP列表按指定大小分组"""
    return [ip_list[i:i + group_size] for i in range(0, len(ip_list), group_size)]


# ========================================================================
# 断点恢复 — checkpoint 读写（独立表 scan_checkpoints）
# ========================================================================

async def _save_checkpoint(
    db: AsyncSession,
    scan_task_id: int,
    phase: int,
    key: str,
    value: Any,
):
    """保存断点数据到 scan_checkpoints 表（按key粒度 UPSERT）"""
    async with _db_lock:
        existing = await db.execute(
            select(ScanCheckpoint).where(
                ScanCheckpoint.task_id == scan_task_id,
                ScanCheckpoint.phase == phase,
                ScanCheckpoint.key == key,
            )
        )
        record = existing.scalar_one_or_none()

        if record:
            record.value = value
            record.updated_at = datetime.now(timezone.utc)
        else:
            record = ScanCheckpoint(
                task_id=scan_task_id,
                phase=phase,
                key=key,
                value=value,
            )
            db.add(record)

        await db.commit()


async def _load_checkpoint(
    db: AsyncSession,
    scan_task_id: int,
    phase: int,
    key: str,
) -> Any | None:
    """读取单条断点数据"""
    result = await db.execute(
        select(ScanCheckpoint.value).where(
            ScanCheckpoint.task_id == scan_task_id,
            ScanCheckpoint.phase == phase,
            ScanCheckpoint.key == key,
        )
    )
    return result.scalar_one_or_none()


async def _load_all_checkpoints(
    db: AsyncSession,
    scan_task_id: int,
) -> dict[int, dict[str, Any]]:
    """加载任务所有断点数据（用于恢复时一次性读取）

    Returns:
        { phase: { key: value, ... }, ... }
        例: { 1: {"open_ports": {...}, "completed_ips": [...]}, 2: {"completed_ips": [...]} }
    """
    result = await db.execute(
        select(ScanCheckpoint).where(
            ScanCheckpoint.task_id == scan_task_id,
        )
    )
    checkpoints: dict[int, dict[str, Any]] = {}
    for record in result.scalars().all():
        if record.phase not in checkpoints:
            checkpoints[record.phase] = {}
        checkpoints[record.phase][record.key] = record.value
    return checkpoints


async def _update_phase_status(
    db: AsyncSession,
    scan_task_id: int,
    phase: int,
    status: str,
    **kwargs,
):
    """更新阶段状态（写入 scan_checkpoints 表 + 同步 ScanTask.current_phase）"""
    # 读取当前 status 值
    existing_value = await _load_checkpoint(db, scan_task_id, phase, "status")
    if existing_value is None:
        existing_value = {}

    existing_value["status"] = status
    for k, v in kwargs.items():
        existing_value[k] = v

    await _save_checkpoint(db, scan_task_id, phase, "status", existing_value)

    # 同步 ScanTask.current_phase（轻量更新，存阶段名称而非数字）
    _phase_names = {1: "port_scan", 2: "service_scan", 3: "script_scan", 4: "os_detect"}
    async with _db_lock:
        scan_task = await db.get(ScanTask, scan_task_id)
        if scan_task:
            scan_task.current_phase = _phase_names.get(phase, str(phase))
            await db.commit()


# ========================================================================
# 新引擎: Nmap 参数构建
# ========================================================================

def build_phase_args(
    phase: str,
    port_spec: str | None,
    timing: dict,
) -> list[str]:
    """根据阶段和策略构建 nmap 参数列表

    Args:
        phase: 阶段名 "port_scan" / "service_detect" / "script_scan" / "os_detect"
        port_spec: 端口规格，如 "22,80,443" 或 "1-65535"
        timing: timing 配置字典

    Returns:
        nmap 参数列表 (list[str])，可直接传给 scan_with_args
    """
    args = ["-sT", "-T4", "-Pn", "-n"]

    # 时序参数
    args.extend(["--max-retries", str(timing.get("max_retries", 3))])
    args.extend(["--min-rate", str(timing.get("min_rate", 300))])

    host_timeout = timing.get("host_timeout", 0)
    if host_timeout > 0:
        args.extend(["--host-timeout", f"{host_timeout}s"])

    args.extend(["--max-rtt-timeout", f"{timing.get('max_rtt_timeout_ms', 500)}ms"])
    args.extend(["--initial-rtt-timeout", f"{timing.get('initial_rtt_timeout_ms', 200)}ms"])
    args.extend(["--max-scan-delay", f"{timing.get('max_scan_delay_ms', 10)}ms"])

    if phase == "port_scan":
        if port_spec:
            args.extend(["-p", port_spec])
        args.extend(["-v", "--reason"])

    elif phase == "service_detect":
        args.append("-sV")
        if port_spec:
            args.extend(["-p", port_spec])

    elif phase == "script_scan":
        # --script=... 由调用方拼入
        if port_spec:
            args.extend(["-p", port_spec])

    elif phase == "os_detect":
        args.append("-O")
        args.append("--osscan-limit")
        if port_spec:
            args.extend(["-p", port_spec])

    return args


def _timing_args_str(timing: dict) -> str:
    """将 timing 参数拼为 nmap 参数字符串（用于阶段2+3合并等复杂场景）"""
    parts = []
    parts.append(f"--max-retries {timing.get('max_retries', 3)}")
    parts.append(f"--min-rate {timing.get('min_rate', 300)}")
    host_timeout = timing.get("host_timeout", 0)
    if host_timeout > 0:
        parts.append(f"--host-timeout {host_timeout}s")
    parts.append(f"--max-rtt-timeout {timing.get('max_rtt_timeout_ms', 500)}ms")
    parts.append(f"--initial-rtt-timeout {timing.get('initial_rtt_timeout_ms', 200)}ms")
    parts.append(f"--max-scan-delay {timing.get('max_scan_delay_ms', 10)}ms")
    return " ".join(parts)


# ========================================================================
# 新引擎: nmap 进程保护
# ========================================================================

async def _run_nmap_with_timeout(
    targets: str,
    args: str | list[str],
    timeout_sec: int = 0,
    scan_task_id: int = 0,
    db: AsyncSession | None = None,
    scan_task: ScanTask | None = None,
) -> list[dict]:
    """带超时的 nmap 执行，防止进程卡死

    Args:
        targets: 扫描目标
        args: nmap 参数（字符串或列表）
        timeout_sec: 超时秒数，0=不限（但建议始终设置）
        scan_task_id: 任务ID（用于日志和进程清理）
        db: 数据库 session（用于写日志）
        scan_task: ScanTask 对象（用于写日志）

    Returns:
        扫描结果列表

    Raises:
        asyncio.TimeoutError: 超时
        asyncio.CancelledError: 被取消
    """
    scanner = NmapScanner()

    try:
        if timeout_sec > 0:
            results = await asyncio.wait_for(
                scanner.scan_with_args(targets, args, timeout_sec=0),
                timeout=timeout_sec,
            )
        else:
            results = await scanner.scan_with_args(targets, args, timeout_sec=0)

        return results

    except asyncio.TimeoutError:
        logger.warning(f"nmap 扫描超时 ({timeout_sec}s): {targets}")
        if db and scan_task:
            await _append_log(db, scan_task,
                f"扫描超时 ({timeout_sec}s): {targets}，强制终止")

        # 清理残留 nmap 进程
        await _kill_orphan_nmap_processes(scan_task_id)
        raise

    except asyncio.CancelledError:
        # 任务被取消，清理进程
        await _kill_orphan_nmap_processes(scan_task_id)
        raise


async def _kill_orphan_nmap_processes(scan_task_id: int = 0):
    """清理残留的 nmap 进程（运行超过2小时的）"""
    try:
        import psutil

        for proc in psutil.process_iter(["pid", "name", "create_time"]):
            try:
                if proc.info["name"] == "nmap":
                    create_time = proc.info.get("create_time", 0)
                    if create_time and (time.time() - create_time > 7200):
                        proc.kill()
                        logger.info(f"清理残留 nmap 进程: PID={proc.info['pid']}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except ImportError:
        logger.debug("psutil 未安装，跳过孤儿 nmap 进程清理")


# ========================================================================
# 新引擎: 结果汇总查询（替代内存 all_results）
# ========================================================================

async def _get_scan_summary(db: AsyncSession, scan_task_id: int) -> dict:
    """从DB查询扫描结果摘要（替代内存 all_results）"""
    host_count = await db.execute(
        select(func.count(func.distinct(ScanResult.ip)))
        .where(ScanResult.scan_task_id == scan_task_id)
    )
    port_count = await db.execute(
        select(func.count(ScanResult.id))
        .where(ScanResult.scan_task_id == scan_task_id)
    )
    return {
        "total_hosts": host_count.scalar() or 0,
        "total_ports": port_count.scalar() or 0,
    }


async def _update_scan_task_progress(
    db: AsyncSession, scan_task: ScanTask, progress: int, summary: dict | None = None
):
    """新引擎: 更新 ScanTask 进度和摘要"""
    async with _db_lock:
        scan_task.progress = progress
        if summary:
            scan_task.result_summary = summary
            flag_modified(scan_task, "result_summary")
        flag_modified(scan_task, "scan_log")
        await db.commit()


async def _check_disk_space(min_gb: float = 1.0) -> bool:
    """检查磁盘可用空间"""
    import shutil
    usage = shutil.disk_usage(".")
    available_gb = usage.free / (1024 ** 3)
    if available_gb < min_gb:
        logger.error(f"磁盘空间不足: {available_gb:.1f}GB < {min_gb}GB")
        return False
    return True


# ========================================================================
# 新引擎: 阶段1 — 端口发现（带断点）
# ========================================================================

async def _phase1_port_scan_with_checkpoint(
    targets: str,
    profile: ScanProfile,
    scan_task_id: int,
    scan_task: ScanTask,
    checkpoints: dict,
):
    """阶段1: 端口发现，带IP组粒度断点

    支持3种模式:
    - top1000: --top-ports N 快速扫描
    - full: 全端口分块扫描（复用 ScanChunk 机制）
    - custom: 自定义端口列表

    Returns:
        open_ports_map: { ip: [port1, port2, ...], ... }
    """
    port_config = profile.port_scan or {}
    scan_mode = port_config.get("scan_mode", "standard")
    max_concurrent = port_config.get("max_concurrent", 4)
    timing = profile.timing or {}
    nmap_timeout = timing.get("nmap_timeout_sec", 3600)
    mode = port_config.get("mode", "top1000")

    # 从断点恢复: 读取已完成的IP和已发现的开放端口
    async with async_session() as db:
        completed_ips = set(await _load_checkpoint(db, scan_task_id, 1, "completed_ips") or [])
        open_ports_map: dict[str, list[int]] = await _load_checkpoint(
            db, scan_task_id, 1, "open_ports"
        ) or {}

    # 展开目标
    ip_list = _expand_targets_to_ips(targets)
    remaining_ips = [ip for ip in ip_list if ip not in completed_ips]

    if not remaining_ips:
        await _append_log_to_task(scan_task_id, "阶段1 端口发现已全部完成（断点恢复），跳过")
        return open_ports_map

    await _append_log_to_task(scan_task_id,
        f"阶段1 端口发现开始, 模式={mode}, 目标={len(ip_list)}IP, "
        f"已完成={len(completed_ips)}, 待扫描={len(remaining_ips)}")

    # ------------------------------------------------------------------
    # top1000 模式
    # ------------------------------------------------------------------
    if mode == "top1000":
        top_ports = port_config.get("top_ports", 1000)
        open_ports_map = await _phase1_top1000(
            remaining_ips, top_ports, scan_mode, max_concurrent, timing,
            nmap_timeout, scan_task_id, scan_task, completed_ips, open_ports_map,
        )

    # ------------------------------------------------------------------
    # full 全端口分块模式
    # ------------------------------------------------------------------
    elif mode == "full":
        open_ports_map = await _phase1_full_scan(
            targets, remaining_ips, scan_mode, max_concurrent, timing,
            nmap_timeout, scan_task_id, scan_task, completed_ips, open_ports_map,
        )

    # ------------------------------------------------------------------
    # custom 自定义端口模式
    # ------------------------------------------------------------------
    elif mode == "custom":
        custom_ports = port_config.get("custom_ports", "22,80,443")
        open_ports_map = await _phase1_custom(
            remaining_ips, custom_ports, scan_mode, max_concurrent, timing,
            nmap_timeout, scan_task_id, scan_task, completed_ips, open_ports_map,
        )

    else:
        await _append_log_to_task(scan_task_id, f"阶段1 未知端口扫描模式: {mode}，回退到 top1000")
        open_ports_map = await _phase1_top1000(
            remaining_ips, 1000, scan_mode, max_concurrent, timing,
            nmap_timeout, scan_task_id, scan_task, completed_ips, open_ports_map,
        )

    # 阶段1完成: 保存最终 checkpoint
    async with async_session() as db:
        await _save_checkpoint(db, scan_task_id, 1, "open_ports", open_ports_map)
        await _save_checkpoint(db, scan_task_id, 1, "completed_ips", list(completed_ips))

    return open_ports_map


async def _phase1_top1000(
    remaining_ips: list[str],
    top_ports: int,
    scan_mode: str,
    max_concurrent: int,
    timing: dict,
    nmap_timeout: int,
    scan_task_id: int,
    scan_task: ScanTask,
    completed_ips: set,
    open_ports_map: dict[str, list[int]],
) -> dict[str, list[int]]:
    """阶段1 top1000 端口扫描"""
    if scan_mode == "ip_sequential":
        # 逐IP串行，Semaphore 控制并发
        semaphore = asyncio.Semaphore(max_concurrent)
        total = len(remaining_ips)

        async def _scan_one_ip(ip: str, idx: int):
            async with semaphore:
                await _check_cancelled(scan_task_id)
                try:
                    args = build_phase_args("port_scan", None, timing)
                    args.extend(["--top-ports", str(top_ports)])
                    results = await _run_nmap_with_timeout(
                        ip, args, timeout_sec=nmap_timeout,
                        scan_task_id=scan_task_id,
                    )

                    # 处理结果
                    for r in results:
                        r_ip = r.get("ip")
                        if r_ip and r.get("ports"):
                            # nmap_scanner 只返回开放端口，无需再过滤 state
                            ip_ports = [p["port"] for p in r["ports"]]
                            if ip_ports:
                                open_ports_map[r_ip] = ip_ports
                            # 直写DB
                            async with async_session() as db:
                                await persist_host_incremental(db, scan_task_id, r_ip, r)

                    completed_ips.add(ip)  # 无论有无开放端口都标记完成

                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logger.warning(f"Phase1 top1000 failed for {ip}: {e}")
                    completed_ips.add(ip)  # 失败也标记完成，不阻塞后续
                    await _append_log_to_task(scan_task_id, f"IP {ip} 端口扫描失败: {e}（跳过）")

            # 定期更新 checkpoint
            if idx % max(1, total // 20) == 0 or idx == total - 1:
                async with async_session() as db:
                    await _save_checkpoint(db, scan_task_id, 1, "completed_ips", list(completed_ips))
                    await _save_checkpoint(db, scan_task_id, 1, "open_ports", open_ports_map)

                # 更新进度
                async with async_session() as db:
                    summary = await _get_scan_summary(db, scan_task_id)
                    summary["phase_info"] = f"阶段1: {idx+1}/{total} IP"
                    db_obj = await db.get(ScanTask, scan_task_id)
                    if db_obj:
                        await _update_scan_task_progress(db, db_obj, 30, summary)

        tasks = [_scan_one_ip(ip, i) for i, ip in enumerate(remaining_ips)]
        await asyncio.gather(*tasks)

    else:
        # standard: 按组并发
        ip_groups = _split_ips_into_groups(remaining_ips, max_concurrent)
        total_groups = len(ip_groups)

        for group_idx, ip_group in enumerate(ip_groups):
            await _check_cancelled(scan_task_id)
            try:
                group_targets = " ".join(ip_group)
                args = build_phase_args("port_scan", None, timing)
                args.extend(["--top-ports", str(top_ports)])
                results = await _run_nmap_with_timeout(
                    group_targets, args, timeout_sec=nmap_timeout,
                    scan_task_id=scan_task_id,
                )

                for r in results:
                    r_ip = r.get("ip")
                    if r_ip and r.get("ports"):
                        # nmap_scanner 只返回开放端口，无需再过滤 state
                        ip_ports = [p["port"] for p in r["ports"]]
                        if ip_ports:
                            open_ports_map[r_ip] = ip_ports
                        async with async_session() as db:
                            await persist_host_incremental(db, scan_task_id, r_ip, r)

                for ip in ip_group:
                    completed_ips.add(ip)

                await _append_log_to_task(scan_task_id,
                    f"阶段1 Top{top_ports}: 组 {group_idx+1}/{total_groups} 完成")

            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning(f"Phase1 top1000 group {group_idx+1} failed: {e}")
                for ip in ip_group:
                    completed_ips.add(ip)
                await _append_log_to_task(scan_task_id,
                    f"组 {group_idx+1}/{total_groups} 扫描失败: {e}（跳过）")

            # 每组完成后更新 checkpoint 和进度
            async with async_session() as db:
                await _save_checkpoint(db, scan_task_id, 1, "completed_ips", list(completed_ips))
                await _save_checkpoint(db, scan_task_id, 1, "open_ports", open_ports_map)
                summary = await _get_scan_summary(db, scan_task_id)
                summary["phase_info"] = f"阶段1: 组 {group_idx+1}/{total_groups}"
                db_obj = await db.get(ScanTask, scan_task_id)
                if db_obj:
                    await _update_scan_task_progress(db, db_obj, 30, summary)

    return open_ports_map


async def _phase1_full_scan(
    targets: str,
    remaining_ips: list[str],
    scan_mode: str,
    max_concurrent: int,
    timing: dict,
    nmap_timeout: int,
    scan_task_id: int,
    scan_task: ScanTask,
    completed_ips: set,
    open_ports_map: dict[str, list[int]],
) -> dict[str, list[int]]:
    """阶段1 全端口分块扫描（复用 ScanChunk 机制 + 新增断点）"""
    # 确保分块记录存在
    async with async_session() as db:
        db_task = await db.get(ScanTask, scan_task_id)
        if db_task:
            await _ensure_chunks(db, scan_task_id, db_task)
            # 重试失败分块
            await _retry_failed_chunks(db, scan_task_id, db_task)

    # 使用旧引擎的 run_chunked_full_scan 完成分块扫描
    # 然后从 ScanResult 汇总 open_ports_map
    scanner_cls = SCANNER_REGISTRY.get("nmap_syn_full")
    if not scanner_cls:
        await _append_log_to_task(scan_task_id, "nmap_syn_full scanner 未注册，无法进行全端口扫描")
        return open_ports_map

    async with async_session() as db:
        # 获取待处理分块
        chunk_result = await db.execute(
            select(ScanChunk).where(
                ScanChunk.scan_task_id == scan_task_id,
                ScanChunk.status.in_([ScanChunkStatus.pending, ScanChunkStatus.running]),
            ).order_by(ScanChunk.port_start)
        )
        pending_chunks = chunk_result.scalars().all()

        if not pending_chunks:
            # 所有分块完成，从 ScanResult 汇总 open_ports
            open_ports_map = await _collect_open_ports_from_results(db, scan_task_id)
            return open_ports_map

        # 获取总分块数
        total_result = await db.execute(
            select(ScanChunk).where(ScanChunk.scan_task_id == scan_task_id)
        )
        total_chunks = len(total_result.scalars().all())
        completed_chunks = total_chunks - len(pending_chunks)

    # 执行分块扫描
    scanner = scanner_cls()
    for chunk in pending_chunks:
        await _check_cancelled(scan_task_id)

        async with async_session() as db:
            chunk = await db.get(ScanChunk, chunk.id)
            if not chunk:
                continue
            chunk.status = ScanChunkStatus.running
            chunk.started_at = datetime.now(timezone.utc)
            await db.commit()

            port_spec = f"{chunk.port_start}-{chunk.port_end}"
            await _append_log_to_task(scan_task_id, f"全端口分块扫描: 端口 {port_spec} ...")

            try:
                scan_results = await scanner.scan(
                    targets, port_spec,
                    scan_method="nmap_syn_full", scan_mode=scan_mode,
                )

                # 处理结果
                for r in scan_results:
                    r_ip = r.get("ip")
                    if r_ip:
                        await persist_host_incremental(db, scan_task_id, r_ip, r)
                        # 汇总开放端口
                        if r.get("ports"):
                            # nmap_scanner 只返回开放端口，无需再过滤 state
                            ip_open = [p["port"] for p in r["ports"]
                                       if chunk.port_start <= p["port"] <= chunk.port_end]
                            if ip_open:
                                if r_ip not in open_ports_map:
                                    open_ports_map[r_ip] = []
                                open_ports_map[r_ip].extend(ip_open)

                chunk.status = ScanChunkStatus.completed
                chunk.completed_at = datetime.now(timezone.utc)
                await db.commit()

                completed_chunks += 1

            except asyncio.CancelledError:
                chunk.status = ScanChunkStatus.failed
                chunk.error_message = "任务被取消"
                await db.commit()
                raise

            except Exception as e:
                logger.warning(f"Chunk {port_spec} failed: {e}")
                chunk.status = ScanChunkStatus.failed
                chunk.error_message = str(e)
                chunk.retry_count += 1
                await db.commit()

            # 更新 checkpoint
            await _save_checkpoint(db, scan_task_id, 1, "open_ports", open_ports_map)
            # 更新进度
            chunk_progress = int(completed_chunks / total_chunks * 30)
            summary = await _get_scan_summary(db, scan_task_id)
            summary["phase_info"] = f"阶段1 全端口: 分块 {completed_chunks}/{total_chunks}"
            db_obj = await db.get(ScanTask, scan_task_id)
            if db_obj:
                await _update_scan_task_progress(db, db_obj, chunk_progress, summary)

    # 全部分块完成后，最终汇总
    async with async_session() as db:
        open_ports_map = await _collect_open_ports_from_results(db, scan_task_id)
        # 去重
        for ip in open_ports_map:
            open_ports_map[ip] = sorted(set(open_ports_map[ip]))

    return open_ports_map


async def _phase1_custom(
    remaining_ips: list[str],
    custom_ports: str,
    scan_mode: str,
    max_concurrent: int,
    timing: dict,
    nmap_timeout: int,
    scan_task_id: int,
    scan_task: ScanTask,
    completed_ips: set,
    open_ports_map: dict[str, list[int]],
) -> dict[str, list[int]]:
    """阶段1 自定义端口扫描"""
    if scan_mode == "ip_sequential":
        semaphore = asyncio.Semaphore(max_concurrent)
        total = len(remaining_ips)

        async def _scan_one(ip: str, idx: int):
            async with semaphore:
                await _check_cancelled(scan_task_id)
                try:
                    args = build_phase_args("port_scan", custom_ports, timing)
                    results = await _run_nmap_with_timeout(
                        ip, args, timeout_sec=nmap_timeout,
                        scan_task_id=scan_task_id,
                    )
                    for r in results:
                        r_ip = r.get("ip")
                        if r_ip and r.get("ports"):
                            # nmap_scanner 只返回开放端口，无需再过滤 state
                            ip_ports = [p["port"] for p in r["ports"]]
                            if ip_ports:
                                open_ports_map[r_ip] = ip_ports
                            async with async_session() as db:
                                await persist_host_incremental(db, scan_task_id, r_ip, r)
                    completed_ips.add(ip)
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logger.warning(f"Phase1 custom failed for {ip}: {e}")
                    completed_ips.add(ip)

            if idx % max(1, total // 20) == 0 or idx == total - 1:
                async with async_session() as db:
                    await _save_checkpoint(db, scan_task_id, 1, "completed_ips", list(completed_ips))
                    await _save_checkpoint(db, scan_task_id, 1, "open_ports", open_ports_map)

        tasks = [_scan_one(ip, i) for i, ip in enumerate(remaining_ips)]
        await asyncio.gather(*tasks)

    else:
        ip_groups = _split_ips_into_groups(remaining_ips, max_concurrent)
        total_groups = len(ip_groups)

        for group_idx, ip_group in enumerate(ip_groups):
            await _check_cancelled(scan_task_id)
            try:
                group_targets = " ".join(ip_group)
                args = build_phase_args("port_scan", custom_ports, timing)
                results = await _run_nmap_with_timeout(
                    group_targets, args, timeout_sec=nmap_timeout,
                    scan_task_id=scan_task_id,
                )
                for r in results:
                    r_ip = r.get("ip")
                    if r_ip and r.get("ports"):
                        # nmap_scanner 只返回开放端口，无需再过滤 state
                        ip_ports = [p["port"] for p in r["ports"]]
                        if ip_ports:
                            open_ports_map[r_ip] = ip_ports
                        async with async_session() as db:
                            await persist_host_incremental(db, scan_task_id, r_ip, r)
                for ip in ip_group:
                    completed_ips.add(ip)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning(f"Phase1 custom group {group_idx+1} failed: {e}")
                for ip in ip_group:
                    completed_ips.add(ip)

            async with async_session() as db:
                await _save_checkpoint(db, scan_task_id, 1, "completed_ips", list(completed_ips))
                await _save_checkpoint(db, scan_task_id, 1, "open_ports", open_ports_map)

    return open_ports_map


async def _collect_open_ports_from_results(
    db: AsyncSession, scan_task_id: int
) -> dict[str, list[int]]:
    """从 ScanResult 表汇总已发现的开放端口"""
    result = await db.execute(
        select(ScanResult.ip, ScanResult.ports)
        .where(ScanResult.scan_task_id == scan_task_id)
    )
    open_ports_map: dict[str, list[int]] = {}
    for ip, ports in result.all():
        if ip and ports:
            # nmap_scanner 只返回开放端口，无需再过滤 state
            open_ports = [p["port"] for p in ports]
            if open_ports:
                if ip not in open_ports_map:
                    open_ports_map[ip] = []
                open_ports_map[ip].extend(open_ports)
    # 去重排序
    for ip in open_ports_map:
        open_ports_map[ip] = sorted(set(open_ports_map[ip]))
    return open_ports_map


# ========================================================================
# 新引擎: 阶段2+3 — 服务识别+脚本扫描（始终合并执行，带断点）
# ========================================================================

async def _phase23_service_and_script_with_checkpoint(
    open_ports_map: dict[str, list[int]],
    profile: ScanProfile,
    scan_task_id: int,
    scan_task: ScanTask,
    checkpoints: dict,
):
    """阶段2+3: 服务识别 + 脚本扫描（始终合并执行），带IP粒度断点

    架构决策①: 始终合并阶段2+3，即使有 script_args 也可通过 --script-args= 传入
    """
    svc_config = profile.service_detect or {}
    script_config = profile.script_scan or {}
    timing = profile.timing or {}
    nmap_timeout = timing.get("nmap_timeout_sec", 7200)
    script_timeout_sec = timing.get("script_timeout_sec", 60)
    port_config = profile.port_scan or {}
    max_concurrent = port_config.get("max_concurrent", 4)

    svc_enabled = svc_config.get("enabled", False)
    script_enabled = script_config.get("enabled", False)

    if not svc_enabled and not script_enabled:
        await _append_log_to_task(scan_task_id, "阶段2/3 服务识别和脚本扫描均未启用，跳过")
        return

    # 从断点恢复: 读取已完成的IP
    async with async_session() as db:
        completed_ips = set(await _load_checkpoint(db, scan_task_id, 2, "completed_ips") or [])

    remaining = {ip: ports for ip, ports in open_ports_map.items() if ip not in completed_ips}

    if not remaining:
        await _append_log_to_task(scan_task_id, "阶段2+3 服务识别+脚本扫描已全部完成（断点恢复），跳过")
        return

    await _append_log_to_task(scan_task_id,
        f"阶段2+3 开始: 服务识别={svc_enabled}, 脚本扫描={script_enabled}, "
        f"待扫描IP={len(remaining)}")

    # ------------------------------------------------------------------
    # 逐IP扫描（合并 -sV + --script）
    # ------------------------------------------------------------------
    ip_list = list(remaining.keys())
    total = len(ip_list)

    for idx, ip in enumerate(ip_list):
        await _check_cancelled(scan_task_id)

        ports = remaining[ip]
        port_spec = ",".join(str(p) for p in ports)

        # 构建 nmap 参数
        args = ["-sT", "-Pn", "-n"]

        # 服务识别
        if svc_enabled:
            args.append("-sV")
            svc_intensity = svc_config.get("intensity", 7)
            args.extend(["--version-intensity", str(svc_intensity)])

        # 脚本扫描（合并到同一次 nmap 调用）
        if script_enabled:
            script_categories = script_config.get("categories", ["default"])
            if script_categories:
                args.extend(["--script", ",".join(script_categories)])
            script_args = script_config.get("script_args", "")
            if script_args:
                args.extend(["--script-args", script_args])
            if script_timeout_sec > 0:
                args.extend(["--script-timeout", f"{script_timeout_sec}s"])

        # 端口规格
        args.extend(["-p", port_spec])

        # timing 参数
        args.extend(["-T4"])
        args.extend(["--max-retries", str(timing.get("max_retries", 3))])
        args.extend(["--min-rate", str(timing.get("min_rate", 300))])
        host_timeout = timing.get("host_timeout", 0)
        if host_timeout > 0:
            args.extend(["--host-timeout", f"{host_timeout}s"])
        args.extend(["--max-rtt-timeout", f"{timing.get('max_rtt_timeout_ms', 500)}ms"])
        args.extend(["--initial-rtt-timeout", f"{timing.get('initial_rtt_timeout_ms', 200)}ms"])
        args.extend(["--max-scan-delay", f"{timing.get('max_scan_delay_ms', 10)}ms"])

        try:
            results = await _run_nmap_with_timeout(
                ip, args, timeout_sec=nmap_timeout,
                scan_task_id=scan_task_id,
            )

            for r in results:
                r_ip = r.get("ip")
                if r_ip:
                    async with async_session() as db:
                        await persist_host_incremental(db, scan_task_id, r_ip, r)

            completed_ips.add(ip)

        except asyncio.CancelledError:
            # 保存当前进度再退出
            async with async_session() as db:
                await _save_checkpoint(db, scan_task_id, 2, "completed_ips", list(completed_ips))
            raise

        except Exception as e:
            logger.warning(f"Phase2+3 failed for {ip}: {e}")
            completed_ips.add(ip)  # 失败也标记完成
            await _append_log_to_task(scan_task_id, f"IP {ip} 服务识别+脚本扫描失败: {e}（跳过）")

        # 定期更新 checkpoint（每1个IP或每5%）
        if idx % max(1, total // 20) == 0 or idx == total - 1:
            async with async_session() as db:
                await _save_checkpoint(db, scan_task_id, 2, "completed_ips", list(completed_ips))
                # 更新进度 (30-70%)
                progress = 30 + int((idx + 1) / total * 40)
                summary = await _get_scan_summary(db, scan_task_id)
                summary["phase_info"] = f"阶段2+3: {idx+1}/{total} IP"
                db_obj = await db.get(ScanTask, scan_task_id)
                if db_obj:
                    await _update_scan_task_progress(db, db_obj, progress, summary)

    # 阶段2+3完成
    async with async_session() as db:
        await _save_checkpoint(db, scan_task_id, 2, "completed_ips", list(completed_ips))

    await _append_log_to_task(scan_task_id,
        f"阶段2+3 完成: 扫描了 {len(completed_ips)} 个IP")


# ========================================================================
# 新引擎: 阶段4 — OS识别（带断点）
# ========================================================================

async def _phase4_os_detect_with_checkpoint(
    open_ports_map: dict[str, list[int]],
    profile: ScanProfile,
    scan_task_id: int,
    scan_task: ScanTask,
    checkpoints: dict,
):
    """阶段4: OS识别，带IP粒度断点

    注意: OS识别(-O)需要root权限，否则nmap会跳过
    """
    os_config = profile.os_detect or {}
    timing = profile.timing or {}
    nmap_timeout = timing.get("nmap_timeout_sec", 7200)

    if not os_config.get("enabled", False):
        await _append_log_to_task(scan_task_id, "阶段4 OS识别未启用，跳过")
        return

    # 从断点恢复
    async with async_session() as db:
        completed_ips = set(await _load_checkpoint(db, scan_task_id, 4, "completed_ips") or [])

    remaining = {ip: ports for ip, ports in open_ports_map.items() if ip not in completed_ips}

    if not remaining:
        await _append_log_to_task(scan_task_id, "阶段4 OS识别已全部完成（断点恢复），跳过")
        return

    await _append_log_to_task(scan_task_id,
        f"阶段4 OS识别开始: 待扫描IP={len(remaining)}")

    ip_list = list(remaining.keys())
    total = len(ip_list)

    for idx, ip in enumerate(ip_list):
        await _check_cancelled(scan_task_id)

        # OS识别只需几个开放端口即可（nmap用TCP指纹判断）
        ports = remaining[ip]
        # 最多取5个端口用于OS识别
        sample_ports = ports[:5]
        port_spec = ",".join(str(p) for p in sample_ports)

        args = build_phase_args("os_detect", port_spec, timing)

        try:
            results = await _run_nmap_with_timeout(
                ip, args, timeout_sec=nmap_timeout,
                scan_task_id=scan_task_id,
            )

            for r in results:
                r_ip = r.get("ip")
                if r_ip:
                    async with async_session() as db:
                        await persist_host_incremental(db, scan_task_id, r_ip, r)

            completed_ips.add(ip)

        except asyncio.CancelledError:
            async with async_session() as db:
                await _save_checkpoint(db, scan_task_id, 4, "completed_ips", list(completed_ips))
            raise

        except Exception as e:
            logger.warning(f"Phase4 OS detect failed for {ip}: {e}")
            completed_ips.add(ip)
            await _append_log_to_task(scan_task_id, f"IP {ip} OS识别失败: {e}（跳过）")

        # 定期更新 checkpoint
        if idx % max(1, total // 20) == 0 or idx == total - 1:
            async with async_session() as db:
                await _save_checkpoint(db, scan_task_id, 4, "completed_ips", list(completed_ips))
                progress = 70 + int((idx + 1) / total * 25)
                summary = await _get_scan_summary(db, scan_task_id)
                summary["phase_info"] = f"阶段4: {idx+1}/{total} IP"
                db_obj = await db.get(ScanTask, scan_task_id)
                if db_obj:
                    await _update_scan_task_progress(db, db_obj, progress, summary)

    # 阶段4完成
    async with async_session() as db:
        await _save_checkpoint(db, scan_task_id, 4, "completed_ips", list(completed_ips))

    await _append_log_to_task(scan_task_id,
        f"阶段4 完成: 扫描了 {len(completed_ips)} 个IP")


# ========================================================================
# 新引擎: 主流程 run_service_discovery
# ========================================================================

async def run_service_discovery(
    scan_task_id: int,
):
    """新引擎主流程: 渐进式服务发现（按阶段推进，带断点恢复）

    阶段1(端口发现) → 阶段2+3(服务识别+脚本扫描) → 阶段4(OS识别)
    任何阶段中断，重启后都能从断点续跑
    """
    start_time = time.time()

    # 注册取消信号
    cancel_event = asyncio.Event()
    _cancel_events[scan_task_id] = cancel_event

    try:
        async with async_session() as db:
            # 加载任务和配置
            scan_task = await db.get(ScanTask, scan_task_id)
            if not scan_task:
                logger.error(f"任务 {scan_task_id} 不存在")
                return

            # 加载 ScanProfile
            profile_id = scan_task.scan_profile_id
            if not profile_id:
                logger.error(f"任务 {scan_task_id} 无 scan_profile_id，不应进入新引擎")
                return

            profile = await db.get(ScanProfile, profile_id)
            if not profile:
                logger.error(f"ScanProfile {profile_id} 不存在")
                await _fail_scan_task(db, scan_task, f"扫描配置 {profile_id} 不存在")
                return

            # 加载所有断点
            checkpoints = await _load_all_checkpoints(db, scan_task_id)

            # 设置任务状态为 running
            scan_task.status = ScanStatus.running
            scan_task.started_at = scan_task.started_at or datetime.now(timezone.utc)
            scan_task.current_phase = "port_scan"
            await db.commit()

            targets = scan_task.targets
            await _append_log(db, scan_task,
                f"新引擎启动: profile={profile.name}, targets={targets}")

        # 磁盘空间检查
        if not await _check_disk_space(min_gb=1.0):
            async with async_session() as db:
                scan_task = await db.get(ScanTask, scan_task_id)
                if scan_task:
                    await _fail_scan_task(db, scan_task, "磁盘空间不足，扫描终止")
            return

        # ------------------------------------------------------------------
        # 阶段1: 端口发现
        # ------------------------------------------------------------------
        phase1_status = checkpoints.get(1, {}).get("status", {}).get("status", "pending")

        if phase1_status == "completed":
            await _append_log_to_task(scan_task_id, "阶段1 已完成（断点恢复），跳过")
            # 从DB加载已有开放端口
            async with async_session() as db:
                open_ports_map = await _collect_open_ports_from_results(db, scan_task_id)
        else:
            async with async_session() as db:
                await _update_phase_status(db, scan_task_id, 1, "running")

            open_ports_map = await _phase1_port_scan_with_checkpoint(
                targets, profile, scan_task_id, scan_task, checkpoints,
            )

            async with async_session() as db:
                await _update_phase_status(db, scan_task_id, 1, "completed")

            await _append_log_to_task(scan_task_id,
                f"阶段1 端口发现完成: 发现 {len(open_ports_map)} 个有开放端口的主机")

        if not open_ports_map:
            await _append_log_to_task(scan_task_id, "未发现任何开放端口，扫描结束")
            async with async_session() as db:
                scan_task = await db.get(ScanTask, scan_task_id)
                if scan_task:
                    await _complete_scan_task(db, scan_task)
            return

        # ------------------------------------------------------------------
        # 阶段2+3: 服务识别 + 脚本扫描（始终合并）
        # ------------------------------------------------------------------
        svc_config = profile.service_detect or {}
        script_config = profile.script_scan or {}
        svc_or_script_enabled = svc_config.get("enabled", False) or script_config.get("enabled", False)

        if svc_or_script_enabled:
            phase23_status = checkpoints.get(2, {}).get("status", {}).get("status", "pending")

            if phase23_status == "completed":
                await _append_log_to_task(scan_task_id, "阶段2+3 已完成（断点恢复），跳过")
            else:
                async with async_session() as db:
                    await _update_phase_status(db, scan_task_id, 2, "running")

                await _phase23_service_and_script_with_checkpoint(
                    open_ports_map, profile, scan_task_id, scan_task, checkpoints,
                )

                async with async_session() as db:
                    await _update_phase_status(db, scan_task_id, 2, "completed")

        # ------------------------------------------------------------------
        # 阶段4: OS识别
        # ------------------------------------------------------------------
        os_config = profile.os_detect or {}

        if os_config.get("enabled", False):
            phase4_status = checkpoints.get(4, {}).get("status", {}).get("status", "pending")

            if phase4_status == "completed":
                await _append_log_to_task(scan_task_id, "阶段4 已完成（断点恢复），跳过")
            else:
                async with async_session() as db:
                    await _update_phase_status(db, scan_task_id, 4, "running")

                await _phase4_os_detect_with_checkpoint(
                    open_ports_map, profile, scan_task_id, scan_task, checkpoints,
                )

                async with async_session() as db:
                    await _update_phase_status(db, scan_task_id, 4, "completed")

        # ------------------------------------------------------------------
        # 全部阶段完成
        # ------------------------------------------------------------------
        duration = time.time() - start_time
        async with async_session() as db:
            scan_task = await db.get(ScanTask, scan_task_id)
            if scan_task:
                scan_task.last_duration_sec = int(duration)
                scan_task.current_phase = "completed"
                await _complete_scan_task(db, scan_task)

        await _append_log_to_task(scan_task_id,
            f"扫描全部完成，耗时 {duration:.1f}s")

    except asyncio.CancelledError:
        logger.info(f"任务 {scan_task_id} 被取消")
        async with async_session() as db:
            scan_task = await db.get(ScanTask, scan_task_id)
            if scan_task:
                scan_task.status = ScanStatus.cancelled
                # 保留 current_phase 为被取消时的阶段名，便于用户了解进度
                scan_task.completed_at = datetime.now(timezone.utc)
                flag_modified(scan_task, "scan_log")
                await db.commit()
        await _append_log_to_task(scan_task_id, "任务被用户取消")

    except Exception as e:
        logger.error(f"任务 {scan_task_id} 执行失败: {e}", exc_info=True)
        async with async_session() as db:
            scan_task = await db.get(ScanTask, scan_task_id)
            if scan_task:
                await _fail_scan_task(db, scan_task, f"执行失败: {e}")

    finally:
        # 清理取消信号
        _cancel_events.pop(scan_task_id, None)


async def _fail_scan_task(db: AsyncSession, scan_task: ScanTask, message: str):
    """将任务标记为失败"""
    scan_task.status = ScanStatus.failed
    scan_task.completed_at = datetime.now(timezone.utc)
    if scan_task.scan_log is None:
        scan_task.scan_log = []
    scan_task.scan_log.append({
        "ts": datetime.now(timezone.utc).isoformat(),
        "msg": message,
        "level": "error",
    })
    flag_modified(scan_task, "scan_log")
    await db.commit()


async def _complete_scan_task(db: AsyncSession, scan_task: ScanTask):
    """将任务标记为完成"""
    scan_task.status = ScanStatus.completed
    scan_task.completed_at = datetime.now(timezone.utc)
    scan_task.progress = 100
    # 从DB统计最终摘要
    summary = await _get_scan_summary(db, scan_task.id)
    scan_task.result_summary = summary
    flag_modified(scan_task, "result_summary")
    flag_modified(scan_task, "scan_log")
    await db.commit()


# ========================================================================
# 主入口 execute_scan — 新旧引擎分流
# ========================================================================

async def execute_scan(scan_task_id: int):
    """扫描执行主入口 — 根据 scan_profile_id 分流到旧/新引擎

    - 有 scan_profile_id → 新引擎 (run_service_discovery)
    - 无 scan_profile_id → 旧引擎 (_execute_scan_legacy)
    """
    async with async_session() as db:
        scan_task = await db.get(ScanTask, scan_task_id)
        if not scan_task:
            logger.error(f"任务 {scan_task_id} 不存在")
            return

        has_profile = scan_task.scan_profile_id is not None

    if has_profile:
        logger.info(f"任务 {scan_task_id}: 使用新引擎 (profile={scan_task.scan_profile_id})")
        await run_service_discovery(scan_task_id)
    else:
        logger.info(f"任务 {scan_task_id}: 使用旧引擎 (scan_methods)")
        await _execute_scan_legacy(scan_task_id)


# ========================================================================
# 旧引擎: 兼容主机发现和旧式服务发现
# ========================================================================

async def _execute_scan_legacy(scan_task_id: int):
    """旧引擎: 兼容 scan_methods 模式的扫描执行（无断点恢复）

    保留此函数用于:
    - host_discovery.py 主机发现
    - 旧式服务发现（无 ScanProfile）
    """
    async with async_session() as db:
        scan_task = await db.get(ScanTask, scan_task_id)
        if not scan_task:
            logger.error(f"任务 {scan_task_id} 不存在")
            return

        if scan_task.status == ScanStatus.completed:
            logger.info(f"任务 {scan_task_id} 已完成，跳过")
            return

        scan_task.status = ScanStatus.running
        scan_task.started_at = scan_task.started_at or datetime.now(timezone.utc)
        await db.commit()

        targets = scan_task.targets
        scan_methods = scan_task.scan_methods or []
        scan_mode = scan_task.scan_mode or "standard"

        all_results: dict[str, dict] = {}
        await _append_log(db, scan_task, f"开始扫描: {targets}, 方式: {scan_methods}, 模式: {scan_mode}")

    try:
        for method in scan_methods:
            async with async_session() as db:
                scan_task = await db.get(ScanTask, scan_task_id)
                if not scan_task or scan_task.status != ScanStatus.running:
                    break

            scanner_cls = SCANNER_REGISTRY.get(method)
            if not scanner_cls:
                logger.warning(f"Unknown scan method: {method}")
                continue

            scanner = scanner_cls()

            # 全端口扫描走分块逻辑
            if method == "nmap_syn_full":
                async with async_session() as db:
                    scan_task = await db.get(ScanTask, scan_task_id)
                    if scan_task:
                        await _ensure_chunks(db, scan_task_id, scan_task)
                        await _retry_failed_chunks(db, scan_task_id, scan_task)
                        await _run_chunked_full_scan(db, scan_task, scanner, all_results, scan_mode)
                continue

            # 普通扫描
            try:
                results = await scanner.scan(
                    targets, scan_method=method, scan_mode=scan_mode
                )
                _merge_results(all_results, results)

                async with async_session() as db:
                    scan_task = await db.get(ScanTask, scan_task_id)
                    if scan_task:
                        await _append_log(db, scan_task, f"扫描方式 {method} 完成: 发现 {len(results)} 个主机")
                        await _update_progress(db, scan_task, 0, all_results)

            except Exception as e:
                logger.error(f"扫描方式 {method} 失败: {e}")
                async with async_session() as db:
                    scan_task = await db.get(ScanTask, scan_task_id)
                    if scan_task:
                        await _append_log(db, scan_task, f"扫描方式 {method} 失败: {e}")

        # 保存结果
        async with async_session() as db:
            scan_task = await db.get(ScanTask, scan_task_id)
            if scan_task and scan_task.status == ScanStatus.running:
                await persist_results(db, scan_task, all_results)
                scan_task.status = ScanStatus.completed
                scan_task.completed_at = datetime.now(timezone.utc)
                scan_task.progress = 100
                scan_task.result_summary = {
                    "total_hosts": len(all_results),
                    "total_ports": sum(len(d.get("ports", [])) for d in all_results.values()),
                }
                flag_modified(scan_task, "result_summary")
                flag_modified(scan_task, "scan_log")
                await db.commit()

    except Exception as e:
        logger.error(f"扫描任务 {scan_task_id} 失败: {e}", exc_info=True)
        async with async_session() as db:
            scan_task = await db.get(ScanTask, scan_task_id)
            if scan_task:
                await _fail_scan_task(db, scan_task, str(e))


# ========================================================================
# 旧引擎: 分块扫描（全端口）
# ========================================================================

async def _ensure_chunks(db: AsyncSession, scan_task_id: int, scan_task: ScanTask):
    """确保全端口扫描的分块记录存在"""
    existing = await db.execute(
        select(ScanChunk).where(ScanChunk.scan_task_id == scan_task_id)
    )
    if existing.scalars().first():
        return

    port_ranges = _build_port_ranges()
    for start, end in port_ranges:
        chunk = ScanChunk(
            scan_task_id=scan_task_id,
            port_start=start,
            port_end=end,
            status=ScanChunkStatus.pending,
            retry_count=0,
        )
        db.add(chunk)
    await db.commit()
    await _append_log(db, scan_task, f"已创建 {len(port_ranges)} 个端口分块")


async def _retry_failed_chunks(db: AsyncSession, scan_task_id: int, scan_task: ScanTask):
    """重试失败的分块（最多3次）"""
    failed = await db.execute(
        select(ScanChunk).where(
            ScanChunk.scan_task_id == scan_task_id,
            ScanChunk.status == ScanChunkStatus.failed,
            ScanChunk.retry_count < 3,
        )
    )
    for chunk in failed.scalars().all():
        chunk.status = ScanChunkStatus.pending
        await _append_log(
            db, scan_task,
            f"重试分块 {chunk.port_start}-{chunk.port_end} (第{chunk.retry_count}次)"
        )
    await db.commit()


async def _run_chunked_full_scan(
    db: AsyncSession, scan_task: ScanTask, scanner, all_results: dict, scan_mode: str
):
    """执行全端口分块扫描"""
    scan_task_id = scan_task.id
    targets = scan_task.targets

    chunk_result = await db.execute(
        select(ScanChunk).where(
            ScanChunk.scan_task_id == scan_task_id,
            ScanChunk.status.in_([ScanChunkStatus.pending, ScanChunkStatus.running]),
        ).order_by(ScanChunk.port_start)
    )
    pending_chunks = chunk_result.scalars().all()

    if not pending_chunks:
        return

    total_result = await db.execute(
        select(ScanChunk).where(ScanChunk.scan_task_id == scan_task_id)
    )
    total_chunks = len(total_result.scalars().all())
    completed_chunks = total_chunks - len(pending_chunks)

    for chunk in pending_chunks:
        async with async_session() as db2:
            chunk = await db2.get(ScanChunk, chunk.id)
            if not chunk:
                continue
            chunk.status = ScanChunkStatus.running
            chunk.started_at = datetime.now(timezone.utc)
            await db2.commit()

        port_spec = f"{chunk.port_start}-{chunk.port_end}"

        try:
            results = await scanner.scan(
                targets, port_spec,
                scan_method="nmap_syn_full", scan_mode=scan_mode,
            )
            _merge_results(all_results, results)

            async with async_session() as db2:
                chunk = await db2.get(ScanChunk, chunk.id)
                if chunk:
                    chunk.status = ScanChunkStatus.completed
                    chunk.completed_at = datetime.now(timezone.utc)
                    await db2.commit()

                scan_task_obj = await db2.get(ScanTask, scan_task_id)
                if scan_task_obj:
                    await _append_log(db2, scan_task_obj, f"分块 {port_spec} 完成")
                    completed_chunks += 1
                    progress = int(completed_chunks / total_chunks * 100)
                    await _update_progress(db2, scan_task_obj, progress, all_results)

        except Exception as e:
            logger.error(f"分块 {port_spec} 扫描失败: {e}")
            async with async_session() as db2:
                chunk = await db2.get(ScanChunk, chunk.id)
                if chunk:
                    chunk.status = ScanChunkStatus.failed
                    chunk.error_message = str(e)
                    chunk.retry_count += 1
                    await db2.commit()


# ========================================================================
# 旧引擎: 结果合并与持久化
# ========================================================================

def _merge_results(all_results: dict, new_results: list):
    """合并扫描结果到 all_results 字典"""
    for result in new_results:
        ip = result.get("ip")
        if not ip:
            continue

        if ip not in all_results:
            all_results[ip] = result
        else:
            existing = all_results[ip]
            # 合并端口
            existing_ports = {p.get("port"): p for p in existing.get("ports", [])}
            for port_info in result.get("ports", []):
                port_num = port_info.get("port")
                if port_num not in existing_ports:
                    existing.setdefault("ports", []).append(port_info)
                    existing_ports[port_num] = port_info
                else:
                    # 更新已有端口的额外信息（如service）
                    existing_ports[port_num].update(
                        {k: v for k, v in port_info.items() if v}
                    )

            # 合并其他信息
            for key in ["hostname", "mac", "os", "os_match"]:
                if result.get(key) and not existing.get(key):
                    existing[key] = result[key]


async def persist_results(db: AsyncSession, scan_task: ScanTask, all_results: dict):
    """旧引擎: 批量持久化扫描结果到数据库"""
    for ip, data in all_results.items():
        await persist_host_incremental(db, scan_task.id, ip, data)


# ========================================================================
# 新旧引擎共用: 结果直写DB（增量持久化，带 fingerprint 去重和变更记录）
# ========================================================================

async def persist_host_incremental(
    db: AsyncSession,
    scan_task_id: int,
    ip: str,
    result: dict,
):
    """增量持久化单主机扫描结果到数据库

    架构决策②: 结果直写DB，去掉内存 all_results
    - 每次nmap返回结果后立即写入DB
    - 通过 fingerprint 比对实现资产去重
    - 记录资产变更到 AssetChange 表

    此函数被新引擎和旧引擎共用。
    """
    ports_data = result.get("ports", [])
    hostname = result.get("hostname")
    mac = result.get("mac")
    os_info = result.get("os")
    os_match = result.get("os_match")

    # 生成指纹
    fingerprint = generate_fingerprint(mac, hostname, os_info, ip)

    # 查找现有资产（通过 fingerprint 或 IP 去重）
    async with _db_lock:
        existing_asset = await db.execute(
            select(Asset).where(Asset.fingerprint == fingerprint)
        )
        asset = existing_asset.scalar_one_or_none()

        if not asset:
            # 尝试通过 IP 查找
            existing_by_ip = await db.execute(
                select(Asset).where(Asset.ip == ip)
            )
            asset = existing_by_ip.scalar_one_or_none()

        is_new = asset is None

        if is_new:
            asset = Asset(
                ip=ip,
                hostname=hostname,
                mac=mac,
                os=os_info,
                os_match=os_match,
                fingerprint=fingerprint,
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
                status="active",
            )
            db.add(asset)
            await db.flush()
        else:
            # 更新已有资产信息
            changed = False
            if hostname and hostname != asset.hostname:
                asset.hostname = hostname
                changed = True
            if mac and mac != asset.mac:
                asset.mac = mac
                changed = True
            if os_info and os_info != asset.os:
                asset.os = os_info
                changed = True
            if os_match and os_match != asset.os_match:
                asset.os_match = os_match
                changed = True
            if fingerprint != asset.fingerprint:
                asset.fingerprint = fingerprint
                changed = True
            asset.last_seen = datetime.now(timezone.utc)

        # 写入/合并 ScanResult（同 task + ip 只保留一条，后续阶段结果覆盖/合并）
        existing_sr_result = await db.execute(
            select(ScanResult).where(
                ScanResult.scan_task_id == scan_task_id,
                ScanResult.ip == ip,
            )
        )
        existing_sr = existing_sr_result.scalar_one_or_none()

        if existing_sr:
            # 合并: 更新主机级字段（非空值覆盖）
            if hostname:
                existing_sr.hostname = hostname
            if mac:
                existing_sr.mac = mac
            if os_info:
                existing_sr.os = os_info
            if os_match:
                existing_sr.os_match = os_match
            # 合并端口: 逐端口合并，新结果中非空字段覆盖旧值
            if ports_data:
                old_ports: list[dict] = existing_sr.ports or []
                old_map = {
                    (p.get("port"), p.get("proto")): p for p in old_ports
                }
                for new_p in ports_data:
                    key = (new_p.get("port"), new_p.get("proto"))
                    if key in old_map:
                        # 覆盖非空字段（空列表视为空，不覆盖）
                        old_p = old_map[key]
                        for k, v in new_p.items():
                            if v not in (None, "") and v != []:
                                old_p[k] = v
                    else:
                        old_map[key] = dict(new_p)
                existing_sr.ports = list(old_map.values())
                # SQLAlchemy JSON 列原地修改后需手动标记 dirty，否则 commit 不会写入
                from sqlalchemy.orm.attributes import flag_modified
                flag_modified(existing_sr, "ports")
        else:
            scan_result = ScanResult(
                scan_task_id=scan_task_id,
                ip=ip,
                hostname=hostname,
                mac=mac,
                os=os_info,
                os_match=os_match,
                ports=ports_data,
            )
            db.add(scan_result)

        await db.commit()


# ========================================================================
# 旧引擎: 主机发现阶段函数（供 host_discovery.py 使用）
# ========================================================================

async def _phase1_ping(
    targets: str,
    scan_task_id: int,
    scan_mode: str = "standard",
) -> list[dict]:
    """主机发现: ping 扫描（-sn）"""
    scanner = NmapScanner()
    try:
        results = await scanner.scan_with_args(
            targets, ["-sn", "-PE", "-PP", "-PM"],
            timeout_sec=300,
        )
        return results
    except Exception as e:
        logger.warning(f"Ping scan failed: {e}")
        return []


async def _phase1_top_ports(
    targets: str,
    top_ports: int = 1000,
    scan_task_id: int = 0,
    scan_mode: str = "standard",
) -> list[dict]:
    """主机发现: top 端口快速扫描"""
    scanner = NmapScanner()
    try:
        args = ["-sT", "--top-ports", str(top_ports), "-Pn", "-n", "-T4"]
        results = await scanner.scan_with_args(
            targets, args, timeout_sec=3600,
        )
        return results
    except Exception as e:
        logger.warning(f"Top ports scan failed: {e}")
        return []


# ========================================================================
# 启动恢复: _recover_interrupted_tasks
# ========================================================================

async def _recover_interrupted_tasks():
    """启动时恢复中断的扫描任务

    策略:
    - 状态为 running 但已无活跃进程的任务 → 自动恢复
    - 新引擎任务: 有 scan_profile_id 且有 checkpoint → 断点续跑
    - 旧引擎任务: 重新开始
    """
    async with async_session() as db:
        result = await db.execute(
            select(ScanTask).where(ScanTask.status == ScanStatus.running)
        )
        running_tasks = result.scalars().all()

        for task in running_tasks:
            logger.info(f"恢复中断任务: id={task.id}, targets={task.targets}")

            if task.scan_profile_id:
                # 新引擎任务: 断点续跑
                logger.info(f"任务 {task.id}: 新引擎断点恢复")
                asyncio.create_task(run_service_discovery(task.id))
            else:
                # 旧引擎任务: 重新开始
                logger.info(f"任务 {task.id}: 旧引擎重新执行")
                task.status = ScanStatus.pending
                flag_modified(task, "scan_log")
                await db.commit()
                asyncio.create_task(execute_scan(task.id))


def get_recovery_func():
    """返回启动恢复函数（供 main.py 调用）"""
    return _recover_interrupted_tasks