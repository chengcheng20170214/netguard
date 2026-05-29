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
    "nmap_syn": ["-sT"],          # 统一使用 -sT (TCP Connect), 不需要root
    "nmap_connect": ["-sT"],
    "nmap_udp": ["-sT"],          # 不用 -sU (需root), 退化为TCP探测
    "nmap_service": ["-sV"],
    "nmap_os": ["-sV"],           # 不用 -O (需root), 用 -sV 间接获取
    "nmap_script": ["-sC"],
    "nmap_ping": ["-sn"],
    "nmap_arp": ["-sn", "-PR"],
    "nmap_syn_full": ["-sT"],     # 统一使用 -sT
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


def _build_tcp_scan_args(ports: str | None = None) -> str:
    """构建TCP端口扫描参数（-sT，不需要root），含超时优化。"""
    parts = ["-sT", "-T4"]

    # 端口范围
    if ports:
        parts.extend(["-p", ports])
    else:
        parts.extend(["-p", "1-65535"])

    # 跳过主机发现（阶段1/2已完成）和DNS
    parts.extend(["-Pn", "-n"])

    # 超时优化：减少无响应主机端口等待
    parts.extend(["--max-retries", str(settings.SCAN_MAX_RETRIES)])
    parts.extend(["--min-rate", str(settings.SCAN_MIN_RATE)])
    parts.extend(["--host-timeout", f"{settings.SCAN_HOST_TIMEOUT_MIN}m"])
    parts.extend(["--max-rtt-timeout", f"{settings.SCAN_MAX_RTT_TIMEOUT_MS}ms"])
    parts.extend(["--initial-rtt-timeout", f"{settings.SCAN_INITIAL_RTT_TIMEOUT_MS}ms"])
    parts.extend(["--max-scan-delay", f"{settings.SCAN_MAX_SCAN_DELAY_MS}ms"])

    # 进度输出
    parts.extend(["-v", "--reason"])

    return " ".join(parts)


def _build_ping_args() -> str:
    """构建Ping探测参数。"""
    return "-sn -T4"


def _build_arp_args() -> str:
    """构建ARP探测参数。"""
    return "-sn -PR -T4"


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
    async def scan(self, targets: str, ports: str | None = None, **kwargs) -> list[dict]:
        targets = validate_targets(targets)
        scan_method = kwargs.get("scan_method", "nmap_syn")
        scan_mode = kwargs.get("scan_mode", "standard")
        progress_callback = kwargs.get("progress_callback")
        max_concurrent = kwargs.get("max_concurrent", settings.SCAN_MAX_CONCURRENT)

        # Ping/ARP：简单快速扫描，用线程池
        if scan_method in ("nmap_ping", "nmap_arp"):
            if scan_method == "nmap_ping":
                args = _build_ping_args()
            else:
                args = _build_arp_args()
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._run_nmap, targets, args)

        # TCP端口扫描（主机发现阶段3 / 服务发现）
        if scan_method == "nmap_syn_full":
            # 服务发现：全端口分块扫描
            return await self._scan_full_port_chunked(targets, ports, max_concurrent=max_concurrent, **kwargs)

        # 主机发现阶段3：TCP端口扫描，按端口块并发
        if progress_callback:
            return await self._scan_port_chunked(targets, progress_callback, max_concurrent)

        # 无进度回调的回退
        args = _build_tcp_scan_args(ports)
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_nmap, targets, args)

    # ----------------------------------------------------------------
    # 并发上限计算
    # ----------------------------------------------------------------

    @staticmethod
    def _calc_max_concurrent(
        user_concurrent: int, target_hosts: int, chunk_ports: int = PORT_CHUNK_SIZE
    ) -> int:
        """根据系统资源动态计算安全并发上限。

        nmap -sT 实际 fd 消耗:
        - nmap 内部用 poll/select 调度并发连接，同时活跃连接数 ≈ min_rate × avg_rtt
        - 局域网 RTT <1ms + min_rate=300 → 峰值约 300 个并发 socket
        - 每个目标主机还有 1 个 fd 用于调度，加上 nmap 内部 fd
        - 实测: 扫描 500 主机 × 5000 端口块，nmap 峰值 fd 约 500-800

        因此按保守估算: 每进程 fd = min(800, target_hosts + 300)
        """
        import multiprocessing

        cpu_count = multiprocessing.cpu_count()
        try:
            fd_limit = os.sysconf("SC_OPEN_MAX")
        except (ValueError, OSError):
            fd_limit = 1024

        # 读取临时端口范围
        local_ports = 28000
        try:
            with open("/proc/sys/net/ipv4/ip_local_port_range") as f:
                lo, hi = f.read().split()
                local_ports = int(hi) - int(lo)
        except Exception:
            pass

        # 实际估算: nmap 同时活跃连接 ≈ min_rate * RTT，约 300 个 socket
        # 加上每个目标主机的调度开销 + nmap 内部 fd
        est_fds_per_proc = min(800, target_hosts + 300)

        safe_by_fd = max(1, (fd_limit - 256) // est_fds_per_proc)
        safe_by_cpu = max(1, cpu_count)
        # 临时端口: 每个并发连接占用 1 个源端口，nmap 复用已关闭的端口
        # 保守: 每进程峰值 300 连接，复用源端口
        safe_by_port = max(1, local_ports // 300)

        effective = min(user_concurrent, safe_by_fd, safe_by_cpu, safe_by_port, 16)
        effective = max(1, effective)

        return effective

    # ----------------------------------------------------------------
    # 阶段3：按端口块并发 + 实时进度（队列模式，兼容 Celery prefork）
    # ----------------------------------------------------------------

    async def _scan_port_chunked(
        self, targets: str, progress_callback, max_concurrent: int = 4
    ) -> list[dict]:
        """全端口TCP扫描：按端口块并发，失败自动重试。

        核心设计:
        - 同步线程通过 queue.Queue 发送进度消息（线程安全，无需事件循环）
        - 异步消费者在主事件循环中读取队列并调用 progress_callback（DB 安全）
        - 彻底解决 Celery prefork 下 asyncio.to_thread 的事件循环问题
        """
        target_list = _split_targets(targets)
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

        # 动态计算安全并发上限
        safe_concurrent = self._calc_max_concurrent(max_concurrent, est_hosts)
        if safe_concurrent < max_concurrent:
            await progress_callback(
                f"并发上限调整: 用户设定 {max_concurrent} → 安全值 {safe_concurrent} "
                f"(原因: {est_hosts} 目标主机, fd/CPU/端口约束)"
            )
        max_concurrent = safe_concurrent

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
            args = _build_tcp_scan_args(port_spec)
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
        semaphore = asyncio.Semaphore(max_concurrent)

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

    def _run_nmap_sync(
        self, cmd: list[str], xml_path: str, label: str,
        msg_queue: queue.Queue, attempt: int, max_retries: int
    ) -> tuple[list[dict], int, int] | None:
        """同步执行 nmap，通过 queue.Queue 发送进度消息。

        线程安全：不使用任何 asyncio API，不依赖事件循环。
        """
        timeout_sec = settings.SCAN_HOST_DISCOVERY_TIMEOUT * 60
        host_count = 0
        port_count = 0
        last_progress_time = 0.0

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

        # 估算目标主机数 + 智能并发上限
        est_hosts = 0
        for t in target_list:
            try:
                est_hosts += ipaddress.ip_network(t, strict=False).num_addresses - 2
            except ValueError:
                est_hosts += 1
        est_hosts = max(est_hosts, 1)
        max_concurrent = self._calc_max_concurrent(max_concurrent, est_hosts)

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

    def _build_args(self, scan_method: str, scan_mode: str, ports: str | None) -> str:
        """构建nmap参数（所有扫描方式都不需要root权限）。"""
        if scan_method == "nmap_ping":
            return _build_ping_args()
        if scan_method == "nmap_arp":
            return _build_arp_args()

        # TCP端口扫描（-sT，不需要root）
        return _build_tcp_scan_args(ports)

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
