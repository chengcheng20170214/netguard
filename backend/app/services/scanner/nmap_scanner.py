import asyncio
import ipaddress
import logging
import os
import queue
import re
import shlex
import subprocess
import tempfile
import threading
import time

import nmap
from .base import BaseScanner
from app.config import settings

logger = logging.getLogger(__name__)


def validate_targets(targets: str) -> str:
    parts = [t.strip() for t in targets.split() if t.strip()]
    validated = []
    for part in parts:
        try:
            ipaddress.ip_network(part, strict=False)
            validated.append(part)
            continue
        except ValueError:
            pass
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}-\d{1,3}$', part):
            validated.append(part)
            continue
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$', part) and '..' not in part:
            validated.append(part)
            continue
        raise ValueError(f"Invalid target: {part}")
    return " ".join(validated)


def _split_targets(targets: str) -> list[str]:
    """将目标拆分为独立网段/主机列表。"""
    return [t.strip() for t in targets.split() if t.strip()]


METHOD_ARGS = {
    # 注意: nmap_syn 名称暗示 SYN 扫描(-sS)，但实际使用 TCP Connect(-sT)，
    # 因为 SYN 扫描需要 root 权限。保留名称仅为向后兼容已有数据库记录。
    "nmap_syn": ["-sT"],          # TCP Connect, 不需要root (命名历史遗留)
    "nmap_connect": ["-sT"],      # 同 nmap_syn，兼容旧数据
    "nmap_service": ["-sV"],      # 服务版本识别
    "nmap_script": ["-sC"],       # 脚本扫描
    "nmap_ping": ["-sn"],         # Ping 主机发现
    "nmap_syn_full": ["-sT"],     # TCP Connect 全端口
}

_PROGRESS_PATTERNS = re.compile(
    r"(Discovered open port|Completed|Scanning|Timing:|Nmap scan report|Note: Host seems down|Connect scan|hosts up|ports/host)"
)

# 端口分块大小：每块 5000 端口，65535/5000 ≈ 14 块
PORT_CHUNK_SIZE = 5000


def _build_port_chunks(chunk_size: int = PORT_CHUNK_SIZE) -> list[tuple[int, int]]:
    """将 1-65535 拆分为端口块列表。"""
    chunks = []
    start = 1
    while start <= 65535:
        end = min(start + chunk_size - 1, 65535)
        chunks.append((start, end))
        start = end + 1
    return chunks


def _build_tcp_scan_args(
    ports: str | None = None,
    host_timeout: int | None = None,
    top_ports: int | None = None,
    max_retries: int | None = None,
    min_rate: int | None = None,
) -> str:
    """构建TCP端口扫描参数（-sT，不需要root）。

    Args:
        ports: 端口范围，如 "1-5000"。None 表示全端口。
        host_timeout: 单主机超时秒数。0=不超时，None 使用配置默认值。
        top_ports: 使用 nmap 原生 --top-ports 参数扫描最常见的 N 个端口。
            基于 nmap-services 频率数据，优先级高于 ports 参数。
        max_retries: 无响应端口重传次数。None 使用配置默认值。
        min_rate: 最低发包速率/秒。None 使用配置默认值。
    """
    parts = ["-sT", "-T4"]

    if top_ports:
        parts.extend(["--top-ports", str(top_ports)])
        host_timeout_val = host_timeout if host_timeout is not None else settings.SCAN_TOP_HOST_TIMEOUT_SEC
        retries = max_retries if max_retries is not None else settings.SCAN_TOP_MAX_RETRIES
        rate = min_rate if min_rate is not None else settings.SCAN_TOP_MIN_RATE
    elif ports:
        parts.extend(["-p", ports])
        host_timeout_val = host_timeout if host_timeout is not None else settings.SCAN_FULL_HOST_TIMEOUT_SEC
        retries = max_retries if max_retries is not None else settings.SCAN_FULL_MAX_RETRIES
        rate = min_rate if min_rate is not None else settings.SCAN_FULL_MIN_RATE
    else:
        parts.extend(["-p", "1-65535"])
        host_timeout_val = host_timeout if host_timeout is not None else settings.SCAN_FULL_HOST_TIMEOUT_SEC
        retries = max_retries if max_retries is not None else settings.SCAN_FULL_MAX_RETRIES
        rate = min_rate if min_rate is not None else settings.SCAN_FULL_MIN_RATE

    parts.extend(["-Pn", "-n"])

    parts.extend(["--max-retries", str(retries)])
    parts.extend(["--min-rate", str(rate)])
    if host_timeout_val > 0:
        parts.extend(["--host-timeout", f"{host_timeout_val}s"])
    parts.extend(["--max-rtt-timeout", f"{settings.SCAN_MAX_RTT_TIMEOUT_MS}ms"])
    parts.extend(["--initial-rtt-timeout", f"{settings.SCAN_INITIAL_RTT_TIMEOUT_MS}ms"])
    parts.extend(["--max-scan-delay", f"{settings.SCAN_MAX_SCAN_DELAY_MS}ms"])

    parts.extend(["-v", "--reason"])

    return " ".join(parts)


def _build_ping_args() -> str:
    """构建Ping探测参数：-sn 只做主机发现，不扫端口。"""
    return "-sn -T4 --max-rtt-timeout 500ms --initial-rtt-timeout 200ms"


def _merge_results(all_results: dict, new_results: list[dict]):
    """合并扫描结果，同 IP 的端口去重，缺失字段从新结果补充。"""
    for r in new_results:
        ip = r.get("ip")
        if not ip:
            continue
        if ip in all_results:
            existing = all_results[ip]
            if r.get("ports"):
                ep = {f"{p['port']}/{p.get('proto', 'tcp')}": p for p in (existing.get("ports") or [])}
                for p in r["ports"]:
                    key = f"{p['port']}/{p.get('proto', 'tcp')}"
                    if key not in ep:
                        existing.setdefault("ports", []).append(p)
                        ep[key] = p
            if r.get("os") and not existing.get("os"):
                existing["os"] = r["os"]
            if r.get("hostname") and not existing.get("hostname"):
                existing["hostname"] = r["hostname"]
            if r.get("mac") and not existing.get("mac"):
                existing["mac"] = r["mac"]
        else:
            all_results[ip] = r


class NmapScanner(BaseScanner):

    async def scan_with_args(
        self, targets: str, args: str | list[str],
        timeout_sec: int = 0,
    ) -> list[dict]:
        """使用自定义参数执行 nmap 扫描。

        新引擎核心接口：各阶段通过此方法执行自定义 nmap 命令。

        Args:
            targets: 扫描目标，如 "192.168.1.1" 或 "192.168.1.1 192.168.1.2"
            args: nmap 参数，字符串或列表形式。
                  例: "-sT -sV --version-intensity 7 -p 22,80,443 -Pn -n"
                  或: ["-sT", "-sV", "--version-intensity", "7", "-p", "22,80,443", "-Pn", "-n"]
            timeout_sec: 超时秒数，0 表示不限制。

        Returns:
            扫描结果列表，每项含 ip/mac/hostname/os/ports 等字段。
            超时或执行失败返回空列表。
        """
        if isinstance(args, str):
            cmd_args = shlex.split(args)
        else:
            cmd_args = list(args)

        nmap_path = settings.NMAP_PATH
        cmd = [nmap_path] + cmd_args + _split_targets(targets)

        # 确保 -oX 输出 XML 用于解析
        xml_fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="netguard_phase_")
        os.close(xml_fd)
        cmd_with_xml = cmd + ["-oX", xml_path]

        try:
            # 同步执行（在线程池中，不阻塞事件循环）
            result = await asyncio.to_thread(
                self._run_nmap_sync,
                cmd_with_xml, xml_path, "phase_scan",
                queue.Queue(), 1, 0,  # noop_queue, attempt=1, max_retries=0
            )

            if result is None:
                logger.warning(f"scan_with_args 返回 None: targets={targets}, args={args}")
                return []

            chunk_results, _, _ = result
            return chunk_results

        except Exception as e:
            logger.error(f"scan_with_args 异常: targets={targets}, error={e}")
            return []
        finally:
            if os.path.exists(xml_path):
                os.unlink(xml_path)

    async def scan(self, targets: str, ports: str | None = None, **kwargs) -> list[dict]:
        targets = validate_targets(targets)
        scan_method = kwargs.get("scan_method", "nmap_syn")
        scan_mode = kwargs.get("scan_mode", "standard")
        progress_callback = kwargs.get("progress_callback")
        max_concurrent = kwargs.get("max_concurrent", settings.SCAN_MAX_CONCURRENT)
        # 外部全局信号量：用于逐IP策略中跨IP共享 nmap 进程并发配额
        _global_semaphore = kwargs.get("_global_semaphore")

        # Ping：简单快速扫描，用线程池
        if scan_method == "nmap_ping":
            args = _build_ping_args()
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._run_nmap, targets, args)

        # TCP端口扫描（主机发现阶段2 / 服务发现）
        if scan_method == "nmap_syn_full":
            # 服务发现：全端口分块扫描
            return await self._scan_full_port_chunked(targets, ports, max_concurrent=max_concurrent, **kwargs)

        # 主机发现阶段3：TCP端口扫描，按端口块并发
        if progress_callback:
            host_timeout = kwargs.get("host_timeout")
            top_ports = kwargs.get("top_ports")
            return await self._scan_port_chunked(targets, progress_callback, max_concurrent, _global_semaphore, host_timeout=host_timeout, top_ports=top_ports)

        # 无进度回调的回退
        args = _build_tcp_scan_args(ports)
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_nmap, targets, args)



    # ----------------------------------------------------------------
    # 阶段3：按端口块并发 + 实时进度（队列模式，兼容 Celery prefork）
    # ----------------------------------------------------------------

    async def _scan_port_chunked(
        self, targets: str, progress_callback, max_concurrent: int = 4,
        _global_semaphore: asyncio.Semaphore | None = None,
        host_timeout: int | None = None,
        top_ports: int | None = None,
    ) -> list[dict]:
        """全端口TCP扫描：按端口块并发，失败自动重试。

        核心设计:
        - 同步线程通过 queue.Queue 发送进度消息（线程安全，无需事件循环）
        - 异步消费者在主事件循环中读取队列并调用 progress_callback（DB 安全）
        - 彻底解决 Celery prefork 下 asyncio.to_thread 的事件循环问题

        Args:
            host_timeout: 单主机超时秒数。0=不超时，None=使用配置默认值。
                当只扫描已确认存活的主机时，设为0避免误杀。
            top_ports: 使用 nmap 原生 --top-ports N 参数，基于频率扫描最常见的 N 个端口。
                设置后忽略端口分块，对每个目标做单次 --top-ports 扫描。

        Args:
            _global_semaphore: 外部全局信号量，用于逐IP策略中多个IP共享
                nmap 进程并发配额。如果提供，则不再创建内部信号量，
                直接使用全局信号量控制端口块级并发。
        """
        target_list = _split_targets(targets)

        # top_ports 快捷路径：使用 nmap 原生 --top-ports，不分端口块
        if top_ports:
            await progress_callback(
                f"Top{top_ports}端口扫描: {len(target_list)} 个目标, --top-ports {top_ports}"
            )
            args = _build_tcp_scan_args(top_ports=top_ports, host_timeout=host_timeout)
            nmap_path = settings.NMAP_PATH
            cmd = [nmap_path] + shlex.split(args) + target_list

            max_retries = settings.SCAN_CHUNK_MAX_RETRIES
            for attempt in range(1, max_retries + 2):
                xml_fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="netguard_top_")
                os.close(xml_fd)
                cmd_with_xml = cmd + ["-oX", xml_path]
                try:
                    noop_queue: queue.Queue = queue.Queue()
                    result = await asyncio.to_thread(
                        self._run_nmap_sync,
                        cmd_with_xml, xml_path, f"top{top_ports}",
                        noop_queue, attempt, max_retries,
                    )
                    if result is not None:
                        all_results = {}
                        chunk_results, host_count, port_count = result
                        _merge_results(all_results, chunk_results)
                        total_hosts = len(all_results)
                        total_ports = sum(len(r.get("ports", [])) for r in all_results.values())
                        await progress_callback(
                            f"Top{top_ports}端口扫描完成: {total_hosts} 个存活主机, {total_ports} 个开放端口"
                        )
                        return list(all_results.values())
                    if attempt > max_retries:
                        await progress_callback(f"Top{top_ports}端口扫描失败，重试次数用尽")
                        return []
                    await progress_callback(f"Top{top_ports}端口扫描失败，第{attempt}次重试...")
                except Exception as e:
                    if attempt > max_retries:
                        await progress_callback(f"Top{top_ports}端口扫描异常: {e}")
                        return []
                finally:
                    if os.path.exists(xml_path):
                        os.unlink(xml_path)
            return []

        port_chunks = _build_port_chunks()
        total = len(port_chunks)

        # 估算目标主机数
        est_hosts = 0
        for t in target_list:
            try:
                est_hosts += ipaddress.ip_network(t, strict=False).num_addresses - 2
            except ValueError:
                est_hosts += 1
        est_hosts = max(est_hosts, 1)

        max_retries = settings.SCAN_CHUNK_MAX_RETRIES
        msg_queue: queue.Queue = queue.Queue()

        await progress_callback(
            f"TCP端口扫描: {len(target_list)} 个网段 × {total} 个端口块 "
            f"(每块 {PORT_CHUNK_SIZE} 端口), 并发数 {max_concurrent}, 估计 {est_hosts} 目标主机"
        )

        all_results: dict = {}
        completed = 0
        failed_chunks: list[str] = []
        global_host_count = 0
        global_port_count = 0
        active_workers = 0
        active_lock = threading.Lock()

        async def _scan_port_chunk(port_start: int, port_end: int):
            nonlocal completed, global_host_count, global_port_count, active_workers
            with active_lock:
                active_workers += 1
            port_spec = f"{port_start}-{port_end}"
            args = _build_tcp_scan_args(port_spec, host_timeout=host_timeout)
            nmap_path = settings.NMAP_PATH
            cmd = [nmap_path] + shlex.split(args) + target_list

            for attempt in range(1, max_retries + 2):
                xml_fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="netguard_p_")
                os.close(xml_fd)
                cmd_with_xml = cmd + ["-oX", xml_path]

                try:
                    # 同步执行 nmap，通过 msg_queue 传递进度
                    result = await asyncio.to_thread(
                        self._run_nmap_sync,
                        cmd_with_xml, xml_path, port_spec,
                        msg_queue, attempt, max_retries,
                    )

                    if result is None:
                        if attempt > max_retries:
                            failed_chunks.append(port_spec)
                            completed += 1
                            msg_queue.put(("fail", port_spec, completed, total, 0, 0))
                            break
                        else:
                            msg_queue.put(("retry", port_spec, attempt, 0, 0, 0))
                            continue

                    chunk_results, host_count, port_count = result
                    _merge_results(all_results, chunk_results)
                    global_host_count = max(global_host_count, host_count)
                    global_port_count += port_count
                    completed += 1
                    msg_queue.put(("done", port_spec, completed, total, port_count, global_port_count))
                    break

                except Exception as e:
                    if attempt <= max_retries:
                        msg_queue.put(("error", port_spec, attempt, 0, 0, 0))
                        continue
                    else:
                        completed += 1
                        failed_chunks.append(port_spec)
                        msg_queue.put(("fail", port_spec, completed, total, 0, 0))
                finally:
                    if os.path.exists(xml_path):
                        os.unlink(xml_path)

            with active_lock:
                active_workers -= 1
            msg_queue.put(None)  # worker 结束信号

        # 启动所有扫描任务（不 await，让它们在后台跑）
        # 如果提供了全局信号量（逐IP策略），使用全局信号量控制跨IP并发；
        # 否则创建内部信号量控制单次扫描的端口块并发
        semaphore = _global_semaphore or asyncio.Semaphore(max_concurrent)

        async def _bounded_scan(ps, pe):
            async with semaphore:
                await _scan_port_chunk(ps, pe)

        tasks = [asyncio.create_task(_bounded_scan(ps, pe)) for ps, pe in port_chunks]

        # 异步消费者：从队列读取消息，调用 progress_callback
        total_workers = len(port_chunks)
        finished_workers = 0
        last_drain = time.time()

        while finished_workers < total_workers:
            # 非阻塞消费队列
            drained = False
            while not msg_queue.empty():
                try:
                    msg = msg_queue.get_nowait()
                except queue.Empty:
                    break

                if msg is None:
                    finished_workers += 1
                    continue

                msg_type = msg[0]
                if msg_type == "progress":
                    # ("progress", label, line)
                    label, line = msg[1], msg[2]
                    await progress_callback(f"[端口 {label}] {line}")
                elif msg_type == "done":
                    _, port_spec, done_cnt, tot, pc, gpc = msg
                    await progress_callback(
                        f"[端口 {port_spec}] 完成 ({done_cnt}/{tot}): "
                        f"{pc} 个开放端口 (累计 {global_port_count} 端口)"
                    )
                elif msg_type == "retry":
                    _, port_spec, att, _, _, _ = msg
                    await progress_callback(f"[端口 {port_spec}] 失败, 第{att}次重试...")
                elif msg_type == "error":
                    _, port_spec, att, _, _, _ = msg
                    await progress_callback(f"[端口 {port_spec}] 执行失败, 第{att}次重试...")
                elif msg_type == "fail":
                    _, port_spec, done_cnt, tot, _, _ = msg
                    await progress_callback(f"[端口 {port_spec}] 扫描失败, 跳过 ({done_cnt}/{tot})")
                drained = True

            # 2秒心跳
            if time.time() - last_drain >= 2 and not drained:
                if completed > 0 and completed < total:
                    await progress_callback(
                        f"TCP端口扫描进行中... ({completed}/{total} 端口块完成, "
                        f"{global_host_count} 主机, {global_port_count} 开放端口)"
                    )
                last_drain = time.time()

            await asyncio.sleep(0.3)

        # 等待所有 task 完成
        await asyncio.gather(*tasks)

        total_hosts = len(all_results)
        total_open_ports = sum(len(r.get("ports", [])) for r in all_results.values())

        summary = f"TCP端口扫描完成, 共发现 {total_hosts} 个存活主机, {total_open_ports} 个开放端口"
        if failed_chunks:
            summary += f", {len(failed_chunks)} 个端口块失败: {', '.join(failed_chunks)}"
        await progress_callback(summary)

        return list(all_results.values())

    # 解析 "Discovered open port 25/tcp on 129.28.10.53" 格式
    # nmap -v 可能输出: "Discovered open port 25/tcp on 129.28.10.53" 或
    # "Discovered open port 25/tcp on 129.28.10.53 (12234)" (带反向DNS或进程信息)
    _OPEN_PORT_RE = re.compile(r"^Discovered open port (\d+)/(tcp|udp) on (\S+?)(?:\s|$)")

    def _run_nmap_sync(
        self, cmd: list[str], xml_path: str, label: str,
        msg_queue: queue.Queue, attempt: int, max_retries: int
    ) -> tuple[list[dict], int, int] | None:
        """同步执行 nmap，通过 queue.Queue 发送进度消息。

        线程安全：不使用任何 asyncio API，不依赖事件循环。

        当 nmap 因 --host-timeout 跳过主机时，XML 中不会包含已发现的端口，
        但 stdout 实时输出了 "Discovered open port" 行。本方法会从 stdout
        捕获这些端口信息，与 XML 解析结果合并，确保端口数据不丢失。
        """
        timeout_sec = settings.SCAN_HOST_DISCOVERY_TIMEOUT * 60
        host_count = 0
        port_count = 0
        last_progress_time = 0.0

        # 从 stdout 实时捕获的端口发现: {ip: [{"port": int, "proto": str}, ...]}
        stdout_ports: dict[str, list[dict]] = {}

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                bufsize=1,
            )

            start_time = time.time()
            if proc.stdout:
                for raw_line in proc.stdout:
                    if time.time() - start_time > timeout_sec:
                        proc.kill()
                        proc.wait()
                        return None

                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue

                    # 统计
                    if line.startswith("Nmap scan report for "):
                        host_count += 1
                    if line.startswith("Discovered open port"):
                        port_count += 1
                        # 从 stdout 捕获端口发现信息（备份，防止 XML 因超时丢失）
                        m = self._OPEN_PORT_RE.match(line)
                        if m:
                            p_port, p_proto, p_ip = int(m.group(1)), m.group(2), m.group(3)
                            stdout_ports.setdefault(p_ip, []).append({
                                "port": p_port, "proto": p_proto,
                                "service": "", "version": "",
                            })

                    # 进度行 → 放入队列（1秒节流）
                    if _PROGRESS_PATTERNS.search(line):
                        now = time.time()
                        if now - last_progress_time >= 1.0:
                            last_progress_time = now
                            msg_queue.put(("progress", label, line))

            proc.wait(timeout=30)

            if proc.returncode != 0:
                return None

            results = self._parse_xml_results(xml_path)

            # 将 stdout 捕获的端口合并到 XML 解析结果中
            # 当 --host-timeout 导致 XML 中缺少端口时，stdout 的端口发现是唯一的来源
            if stdout_ports:
                result_by_ip = {r["ip"]: r for r in results}
                merged_count = 0
                for ip, ports in stdout_ports.items():
                    if ip in result_by_ip:
                        existing = result_by_ip[ip]
                        existing_port_keys = {
                            f"{p['port']}/{p.get('proto', 'tcp')}"
                            for p in (existing.get("ports") or [])
                        }
                        for p in ports:
                            key = f"{p['port']}/{p.get('proto', 'tcp')}"
                            if key not in existing_port_keys:
                                existing.setdefault("ports", []).append(p)
                                existing_port_keys.add(key)
                                merged_count += 1
                    else:
                        # XML 中完全没有这个主机（超时被跳过），从 stdout 创建
                        results.append({
                            "ip": ip, "mac": None, "hostname": None,
                            "os": None, "ports": ports,
                        })
                        merged_count += len(ports)
                if merged_count > 0:
                    logger.info(
                        f"{label}: merged {merged_count} ports from stdout "
                        f"into XML results (host-timeout recovery)"
                    )

            return results, host_count, port_count

        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return None
        except Exception as e:
            logger.error(f"nmap scan error for {label}: {e}")
            return None

    # ----------------------------------------------------------------
    # 服务发现：全端口分块扫描（支持 chunk 回调）
    # ----------------------------------------------------------------

    async def _scan_full_port_chunked(self, targets: str, ports: str | None, max_concurrent: int = 4, **kwargs) -> list[dict]:
        """服务发现全端口分块扫描，按端口块并发，支持 on_chunk_done 回调。"""
        target_list = _split_targets(targets)

        semaphore = asyncio.Semaphore(max_concurrent)
        chunk_size = kwargs.get("chunk_size", settings.SCAN_CHUNK_SIZE)
        on_chunk_done = kwargs.get("on_chunk_done")
        progress_callback = kwargs.get("progress_callback")
        max_retries = settings.SCAN_CHUNK_MAX_RETRIES

        chunk_ranges = _build_port_chunks(chunk_size)

        if progress_callback:
            await progress_callback(
                f"全端口扫描: {len(target_list)} 网段 × {len(chunk_ranges)} 端口块 (每块 {chunk_size}), 并发数 {max_concurrent}"
            )

        all_results: dict = {}
        total_tasks = len(target_list) * len(chunk_ranges)
        completed_tasks = 0

        async def _scan_chunk(segment: str, port_start: int, port_end: int, chunk_idx: int):
            nonlocal completed_tasks
            async with semaphore:
                port_spec = f"{port_start}-{port_end}"
                args = _build_tcp_scan_args(port_spec)
                nmap_path = settings.NMAP_PATH
                cmd = [nmap_path] + shlex.split(args) + [segment]

                for attempt in range(1, max_retries + 2):
                    xml_fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="netguard_chunk_")
                    os.close(xml_fd)
                    cmd_with_xml = cmd + ["-oX", xml_path]

                    try:
                        # 服务发现不需要实时日志，传空队列
                        noop_queue: queue.Queue = queue.Queue()
                        result = await asyncio.to_thread(
                            self._run_nmap_sync,
                            cmd_with_xml, xml_path, f"{segment}:{port_spec}",
                            noop_queue, attempt, max_retries,
                        )

                        if result is None:
                            if attempt <= max_retries:
                                continue
                            else:
                                break

                        chunk_results, _, port_count = result
                        _merge_results(all_results, chunk_results)
                        completed_tasks += 1

                        if progress_callback and completed_tasks % 5 == 0:
                            await progress_callback(
                                f"全端口扫描进度: {completed_tasks}/{total_tasks} 块完成"
                            )

                        if on_chunk_done:
                            on_chunk_done(chunk_idx, port_start, port_end, success=True)
                        break  # 成功跳出重试

                    except Exception:
                        if attempt > max_retries:
                            completed_tasks += 1
                            if on_chunk_done:
                                on_chunk_done(chunk_idx, port_start, port_end, success=False)
                    finally:
                        if os.path.exists(xml_path):
                            os.unlink(xml_path)

        tasks = []
        for segment in target_list:
            for i, (port_start, port_end) in enumerate(chunk_ranges):
                tasks.append(_scan_chunk(segment, port_start, port_end, i))

        await asyncio.gather(*tasks)

        if progress_callback:
            total_hosts = len(all_results)
            total_ports = sum(len(r.get("ports", [])) for r in all_results.values())
            await progress_callback(
                f"全端口扫描完成: {total_hosts} 主机, {total_ports} 开放端口"
            )

        return list(all_results.values())

    # ----------------------------------------------------------------
    # XML 解析
    # ----------------------------------------------------------------

    def _parse_xml_results(self, xml_path: str) -> list[dict]:
        """用 python-nmap 解析 XML 文件，返回标准结果列表。"""
        if not os.path.exists(xml_path):
            return []
        nm = nmap.PortScanner()
        try:
            with open(xml_path, "r", errors="replace") as f:
                nm.analyse_nmap_xml_scan(f.read())
        except Exception:
            return []

        results = []
        for host in nm.all_hosts():
            host_data = nm[host]
            if host_data.state() == "down":
                continue

            ip = host
            mac = host_data.get("addresses", {}).get("mac")
            hostname = None
            hostnames = host_data.get("hostnames", [])
            if hostnames and isinstance(hostnames, list):
                hostname = hostnames[0].get("name") if hostnames[0] else None

            os_name = None
            osmatch = host_data.get("osmatch", [])
            if osmatch and isinstance(osmatch, list):
                os_name = osmatch[0].get("name") if osmatch[0] else None

            ports_list = []
            for proto in host_data.all_protocols():
                for port, port_data in host_data[proto].items():
                    if port_data.get("state") == "open":
                        ports_list.append({
                            "port": int(port),
                            "proto": proto,
                            "service": port_data.get("name", ""),
                            "version": port_data.get("version", ""),
                        })

            results.append({
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "os": os_name,
                "ports": ports_list,
            })

        return results

    # ----------------------------------------------------------------
    # 参数构建 & 同步 nmap 执行
    # ----------------------------------------------------------------

    def _build_args(self, scan_method: str, scan_mode: str, ports: str | None,
                     top_ports: int | None = None, host_timeout: int | None = None) -> str:
        """构建nmap参数（所有扫描方式都不需要root权限）。"""
        if scan_method == "nmap_ping":
            return _build_ping_args()

        return _build_tcp_scan_args(ports, host_timeout=host_timeout, top_ports=top_ports)

    def _run_nmap(self, targets: str, args: str) -> list[dict]:
        """同步执行nmap，解析结果。"""
        nm = nmap.PortScanner(nmap_search_path=[settings.NMAP_PATH])
        try:
            nm.scan(hosts=targets, arguments=args)
        except nmap.PortScannerError as e:
            raise RuntimeError(f"nmap scan failed: {e}")
        except Exception as e:
            raise RuntimeError(f"nmap execution error: {e}")

        results = []
        for host in nm.all_hosts():
            host_data = nm[host]
            if host_data.state() == "down":
                continue

            ip = host
            mac = host_data.get("addresses", {}).get("mac")
            hostname = host_data.get("hostnames", [{}])[0].get("name") if host_data.get("hostnames") else None
            os_name = host_data.get("osmatch", [{}])[0].get("name") if host_data.get("osmatch") else None

            ports_list = []
            for proto in host_data.all_protocols():
                for port, port_data in host_data[proto].items():
                    if port_data.get("state") == "open":
                        ports_list.append({
                            "port": int(port),
                            "proto": proto,
                            "service": port_data.get("name", ""),
                            "version": port_data.get("version", ""),
                        })

            results.append({
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "os": os_name,
                "ports": ports_list,
            })

        return results
