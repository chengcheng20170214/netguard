import asyncio
import ipaddress
import logging
import os
import re
import shlex
import tempfile
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
    # 阶段3：TCP端口扫描，按端口块并发 + 重试
    # ----------------------------------------------------------------

    async def _scan_port_chunked(
        self, targets: str, progress_callback, max_concurrent: int = 4
    ) -> list[dict]:
        """全端口TCP扫描：按端口块(5000/块)并发，失败自动重试。"""
        max_concurrent = min(max(1, max_concurrent), 8)
        semaphore = asyncio.Semaphore(max_concurrent)
        target_list = _split_targets(targets)

        port_chunks = _build_port_chunks()
        total = len(port_chunks)
        max_retries = settings.SCAN_CHUNK_MAX_RETRIES

        await progress_callback(
            f"TCP端口扫描: 拆分为 {total} 个端口块 (每块 {PORT_CHUNK_SIZE} 端口), 并发数 {max_concurrent}, 目标网段 {len(target_list)}"
        )

        all_results: dict = {}
        completed = 0
        failed_chunks: list[str] = []
        global_host_count = 0
        global_port_count = 0

        async def _scan_port_chunk(port_start: int, port_end: int):
            nonlocal completed, global_host_count, global_port_count
            async with semaphore:
                port_spec = f"{port_start}-{port_end}"
                args = _build_tcp_scan_args(port_spec)
                nmap_path = settings.NMAP_PATH
                cmd = [nmap_path] + shlex.split(args) + target_list

                # 带重试的执行
                for attempt in range(1, max_retries + 2):
                    xml_fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="netguard_p_")
                    os.close(xml_fd)
                    cmd_with_xml = cmd + ["-oX", xml_path]

                    try:
                        timeout_sec = settings.SCAN_HOST_DISCOVERY_TIMEOUT * 60
                        proc = await asyncio.create_subprocess_exec(
                            *cmd_with_xml,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )

                        last_progress_time = 0.0
                        last_output_time = time.time()
                        chunk_port_count = 0
                        success = False

                        try:
                            if proc.stdout:
                                while True:
                                    try:
                                        line = await asyncio.wait_for(proc.stdout.readline(), timeout=10)
                                    except asyncio.TimeoutError:
                                        # 10秒无输出 → 心跳
                                        now = time.time()
                                        since_output = int(now - last_output_time)
                                        await progress_callback(
                                            f"[端口 {port_spec}] 扫描进行中... 已等待{since_output}秒 (全局: {global_host_count} 主机, {global_port_count} 开放端口)"
                                        )
                                        last_progress_time = now
                                        continue
                                    if not line:
                                        break
                                    line_str = line.decode("utf-8", errors="replace").strip()
                                    if not line_str:
                                        continue

                                    # 任何输出都更新最后输出时间
                                    last_output_time = time.time()

                                    # 统计主机和端口
                                    if line_str.startswith("Nmap scan report for ") or line_str.startswith("Nmap scan report for\t"):
                                        global_host_count += 1
                                    if line_str.startswith("Discovered open port"):
                                        chunk_port_count += 1
                                        global_port_count += 1

                                    # 匹配进度行 → 1秒节流输出
                                    if _PROGRESS_PATTERNS.search(line_str):
                                        now = time.time()
                                        if now - last_progress_time >= 1:
                                            await progress_callback(
                                                f"[端口 {port_spec}] {line_str} (全局: {global_host_count} 主机, {global_port_count} 开放端口)"
                                            )
                                            last_progress_time = now

                            await asyncio.wait_for(proc.wait(), timeout=timeout_sec)
                            success = True
                        except asyncio.TimeoutError:
                            proc.kill()
                            await proc.wait()
                            if attempt <= max_retries:
                                await progress_callback(f"[端口 {port_spec}] 超时, 第{attempt}次重试...")
                                continue
                            else:
                                await progress_callback(f"[端口 {port_spec}] 超时, 已达最大重试次数, 跳过")
                                failed_chunks.append(port_spec)

                        if success:
                            results = self._parse_xml_results(xml_path)
                            _merge_results(all_results, results)
                            completed += 1
                            await progress_callback(
                                f"[端口 {port_spec}] 完成 ({completed}/{total}), 本块 {chunk_port_count} 个开放端口"
                            )
                            break  # 成功则跳出重试循环

                    except Exception as e:
                        if attempt <= max_retries:
                            await progress_callback(f"[端口 {port_spec}] 执行失败: {e}, 第{attempt}次重试...")
                            continue
                        else:
                            completed += 1
                            await progress_callback(f"[端口 {port_spec}] 执行失败, 已达最大重试次数, 跳过: {e}")
                            failed_chunks.append(port_spec)
                    finally:
                        if os.path.exists(xml_path):
                            os.unlink(xml_path)

        tasks = [_scan_port_chunk(ps, pe) for ps, pe in port_chunks]
        await asyncio.gather(*tasks)

        total_hosts = len(all_results)
        total_open_ports = sum(len(r.get("ports", [])) for r in all_results.values())

        summary = f"TCP端口扫描完成, 共发现 {total_hosts} 个存活主机, {total_open_ports} 个开放端口"
        if failed_chunks:
            summary += f", {len(failed_chunks)} 个端口块失败已跳过: {', '.join(failed_chunks)}"
        await progress_callback(summary)

        return list(all_results.values())

    # ----------------------------------------------------------------
    # 服务发现：全端口分块扫描（支持 chunk 回调）
    # ----------------------------------------------------------------

    async def _scan_full_port_chunked(self, targets: str, ports: str | None, max_concurrent: int = 4, **kwargs) -> list[dict]:
        """服务发现全端口分块扫描，按端口块并发，支持 on_chunk_done 回调。"""
        target_list = _split_targets(targets)
        max_concurrent = min(max(1, max_concurrent), 8)
        semaphore = asyncio.Semaphore(max_concurrent)
        chunk_size = kwargs.get("chunk_size", settings.SCAN_CHUNK_SIZE)
        on_chunk_done = kwargs.get("on_chunk_done")
        progress_callback = kwargs.get("progress_callback")
        max_retries = settings.SCAN_CHUNK_MAX_RETRIES

        chunk_ranges = _build_port_chunks(chunk_size)

        if progress_callback:
            await progress_callback(
                f"全端口扫描: {len(target_list)} 网段 × {len(chunk_ranges)} 端口块 (每块 {chunk_size}), 最大并发 {max_concurrent}"
            )

        all_results: dict = {}
        total_tasks = len(target_list) * len(chunk_ranges)
        completed_tasks = 0

        async def _scan_chunk(segment: str, port_start: int, port_end: int, chunk_idx: int):
            nonlocal completed_tasks
            async with semaphore:
                port_spec = f"{port_start}-{port_end}"
                args = _build_tcp_scan_args(port_spec)

                for attempt in range(1, max_retries + 2):
                    xml_fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="netguard_chunk_")
                    os.close(xml_fd)

                    try:
                        nmap_path = settings.NMAP_PATH
                        cmd = [nmap_path] + shlex.split(args) + [segment, "-oX", xml_path]
                        proc = await asyncio.create_subprocess_exec(
                            *cmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        timeout_sec = settings.SCAN_HOST_DISCOVERY_TIMEOUT * 60
                        try:
                            await asyncio.wait_for(proc.wait(), timeout=timeout_sec)
                        except asyncio.TimeoutError:
                            proc.kill()
                            await proc.wait()
                            if attempt <= max_retries:
                                continue
                            else:
                                break

                        chunk_results = self._parse_xml_results(xml_path)
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
