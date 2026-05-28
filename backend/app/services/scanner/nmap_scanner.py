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


STEALTH_PROFILES = {
    "stealth_light": {"timing": "-T2", "scan_delay": "400ms", "max_rate": "50", "extra": []},
    "stealth_medium": {"timing": "-T1", "scan_delay": "3s", "max_rate": "10", "extra": ["-f", "--randomize-hosts"]},
    "stealth_deep": {"timing": "-T0", "scan_delay": "10s", "max_rate": "5", "extra": ["-f", "-D", "RND,RND,ME", "-Pn", "-g", "53", "--data-length", "25", "--randomize-hosts"]},
}

METHOD_ARGS = {
    "nmap_syn": ["-sS"],
    "nmap_connect": ["-sT"],
    "nmap_udp": ["-sU"],
    "nmap_service": ["-sV"],
    "nmap_os": ["-O"],
    "nmap_script": ["-sC"],
    "nmap_ping": ["-sn"],
    "nmap_arp": ["-sn", "-PR"],
    "nmap_syn_full": ["-sS"],
}

_PROGRESS_PATTERNS = re.compile(
    r"(Discovered open port|Completed|Scanning|Timing:|Nmap scan report|Note: Host seems down)"
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


def _build_full_port_args(scan_mode: str) -> str:
    reliability_flags = [
        "-Pn", "-n",
        f"--max-retries", str(settings.SCAN_MAX_RETRIES),
        f"--min-rate", str(settings.SCAN_MIN_RATE),
        f"--host-timeout", f"{settings.SCAN_HOST_TIMEOUT_MIN}m",
        "-v", "--reason",
    ]

    if scan_mode in STEALTH_PROFILES:
        profile = STEALTH_PROFILES[scan_mode]
        parts = METHOD_ARGS["nmap_syn_full"] + [
            profile["timing"],
            "--scan-delay", profile["scan_delay"],
            "--max-rate", profile["max_rate"],
        ] + profile["extra"] + reliability_flags
    elif scan_mode == "quick":
        parts = METHOD_ARGS["nmap_syn_full"] + ["-T4", "--top-ports", "100"] + reliability_flags
    else:
        parts = METHOD_ARGS["nmap_syn_full"] + ["-T4"] + reliability_flags

    return " ".join(parts)


def _merge_results(all_results: dict, new_results: list[dict]):
    """合并扫描结果，同 IP 的端口去重，低优先级字段从新结果补充。"""
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

        if scan_method == "nmap_syn_full":
            return await self._scan_full_port_chunked(targets, ports, scan_mode, max_concurrent=max_concurrent, **kwargs)

        # Ping/ARP：简单快速扫描，用线程池
        if scan_method in ("nmap_ping", "nmap_arp"):
            args = self._build_args(scan_method, scan_mode, ports)
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._run_nmap, targets, args)

        # SYN/Connect 等耗时扫描：子进程 + 实时进度 + 端口块并发
        if progress_callback:
            return await self._scan_with_progress(targets, scan_method, scan_mode, ports, progress_callback, max_concurrent)

        # 无进度回调的回退
        args = self._build_args(scan_method, scan_mode, ports)
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_nmap, targets, args)

    # ----------------------------------------------------------------
    # 核心方法：并发扫描（按端口块并发 for 全端口 / 按网段并发 for 指定端口）
    # ----------------------------------------------------------------

    async def _scan_with_progress(
        self, targets: str, scan_method: str, scan_mode: str,
        ports: str | None, progress_callback, max_concurrent: int = 4
    ) -> list[dict]:
        """并发执行 nmap 子进程，实时输出进度。

        - 全端口 (无 ports 且非 quick)：按端口块并发，每块扫所有网段
        - 指定端口 / quick：按网段并发
        """
        is_full_port = (scan_method in ("nmap_syn", "nmap_connect")
                        and scan_mode not in ("quick",)
                        and not ports)

        if is_full_port:
            return await self._scan_port_chunked(targets, scan_method, scan_mode, progress_callback, max_concurrent)

        # 非全端口：按网段并发
        return await self._scan_by_segment(targets, scan_method, scan_mode, ports, progress_callback, max_concurrent)

    async def _scan_port_chunked(
        self, targets: str, scan_method: str, scan_mode: str,
        progress_callback, max_concurrent: int = 4
    ) -> list[dict]:
        """全端口扫描：按端口块（5000/块）并发，每个端口块一个 nmap 进程扫所有目标网段。"""
        max_concurrent = min(max(1, max_concurrent), 8)
        semaphore = asyncio.Semaphore(max_concurrent)
        target_list = _split_targets(targets)

        port_chunks = _build_port_chunks()
        total = len(port_chunks)

        await progress_callback(
            f"全端口扫描: 拆分为 {total} 个端口块 (每块 {PORT_CHUNK_SIZE} 端口), 并发数 {max_concurrent}, 目标网段 {len(target_list)}"
        )

        all_results: dict = {}
        completed = 0
        global_host_count = 0
        global_port_count = 0

        async def _scan_port_chunk(port_start: int, port_end: int):
            nonlocal completed, global_host_count, global_port_count
            async with semaphore:
                port_spec = f"{port_start}-{port_end}"
                args = self._build_args(scan_method, scan_mode, port_spec)
                nmap_path = settings.NMAP_PATH
                cmd = [nmap_path] + shlex.split(args) + target_list

                xml_fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="netguard_p_")
                os.close(xml_fd)
                cmd.extend(["-oX", xml_path])

                try:
                    timeout_sec = settings.SCAN_HOST_DISCOVERY_TIMEOUT * 60
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )

                    last_progress_time = 0.0
                    chunk_port_count = 0

                    try:
                        if proc.stdout:
                            while True:
                                try:
                                    line = await asyncio.wait_for(proc.stdout.readline(), timeout=30)
                                except asyncio.TimeoutError:
                                    await progress_callback(
                                        f"[端口 {port_spec}] 扫描进行中... (全局: {global_host_count} 主机, {global_port_count} 开放端口)"
                                    )
                                    continue
                                if not line:
                                    break
                                line_str = line.decode("utf-8", errors="replace").strip()
                                if not line_str:
                                    continue

                                if line_str.startswith("Nmap scan report for ") or line_str.startswith("Nmap scan report for\t"):
                                    global_host_count += 1
                                if line_str.startswith("Discovered open port"):
                                    chunk_port_count += 1
                                    global_port_count += 1

                                if _PROGRESS_PATTERNS.search(line_str):
                                    now = time.time()
                                    if now - last_progress_time >= 3:
                                        await progress_callback(
                                            f"[端口 {port_spec}] {line_str} (全局: {global_host_count} 主机, {global_port_count} 开放端口)"
                                        )
                                        last_progress_time = now

                        await asyncio.wait_for(proc.wait(), timeout=timeout_sec)
                    except asyncio.TimeoutError:
                        proc.kill()
                        await proc.wait()
                        await progress_callback(f"[端口 {port_spec}] 扫描超时, 已终止")

                    results = self._parse_xml_results(xml_path)
                    _merge_results(all_results, results)
                    completed += 1
                    await progress_callback(
                        f"[端口 {port_spec}] 完成 ({completed}/{total}), 本块 {chunk_port_count} 个开放端口"
                    )

                except Exception as e:
                    completed += 1
                    await progress_callback(f"[端口 {port_spec}] 扫描失败: {e}")
                finally:
                    if os.path.exists(xml_path):
                        os.unlink(xml_path)

        tasks = [_scan_port_chunk(ps, pe) for ps, pe in port_chunks]
        await asyncio.gather(*tasks)

        total_hosts = len(all_results)
        total_open_ports = sum(len(r.get("ports", [])) for r in all_results.values())
        await progress_callback(
            f"全端口扫描完成, 共发现 {total_hosts} 个存活主机, {total_open_ports} 个开放端口"
        )
        return list(all_results.values())

    async def _scan_by_segment(
        self, targets: str, scan_method: str, scan_mode: str,
        ports: str | None, progress_callback, max_concurrent: int = 4
    ) -> list[dict]:
        """按网段并发扫描（用于指定端口/quick模式）。"""
        target_list = _split_targets(targets)
        max_concurrent = min(max(1, max_concurrent), 8)
        semaphore = asyncio.Semaphore(max_concurrent)

        if len(target_list) > 1:
            await progress_callback(f"检测到 {len(target_list)} 个网段, 最大并发 {max_concurrent} 个 nmap 进程")

        all_results: dict = {}
        completed = 0
        total = len(target_list)

        async def _scan_one_segment(segment: str):
            nonlocal completed
            async with semaphore:
                args = self._build_args(scan_method, scan_mode, ports)
                nmap_path = settings.NMAP_PATH
                cmd = [nmap_path] + shlex.split(args) + [segment]

                xml_fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="netguard_")
                os.close(xml_fd)
                cmd.extend(["-oX", xml_path])

                try:
                    timeout_sec = settings.SCAN_HOST_DISCOVERY_TIMEOUT * 60
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )

                    last_progress_time = 0.0
                    host_count = 0
                    port_count = 0

                    try:
                        if proc.stdout:
                            while True:
                                try:
                                    line = await asyncio.wait_for(proc.stdout.readline(), timeout=30)
                                except asyncio.TimeoutError:
                                    await progress_callback(
                                        f"[{segment}] 扫描进行中... (已发现 {host_count} 主机, {port_count} 开放端口)"
                                    )
                                    continue
                                if not line:
                                    break
                                line_str = line.decode("utf-8", errors="replace").strip()
                                if not line_str:
                                    continue

                                if line_str.startswith("Nmap scan report for ") or line_str.startswith("Nmap scan report for\t"):
                                    host_count += 1
                                if line_str.startswith("Discovered open port"):
                                    port_count += 1

                                if _PROGRESS_PATTERNS.search(line_str):
                                    now = time.time()
                                    if now - last_progress_time >= 2:
                                        msg = f"[{segment}] {line_str}"
                                        if host_count > 0 or port_count > 0:
                                            msg = f"[{segment}] {line_str} (已发现 {host_count} 主机, {port_count} 开放端口)"
                                        await progress_callback(msg)
                                        last_progress_time = now

                        await asyncio.wait_for(proc.wait(), timeout=timeout_sec)
                    except asyncio.TimeoutError:
                        proc.kill()
                        await proc.wait()
                        await progress_callback(f"[{segment}] 扫描超时 ({settings.SCAN_HOST_DISCOVERY_TIMEOUT}分钟), 已终止")

                    results = self._parse_xml_results(xml_path)
                    completed += 1
                    await progress_callback(
                        f"[{segment}] 完成 ({completed}/{total}), 发现 {len(results)} 个存活主机"
                    )
                    _merge_results(all_results, results)

                except Exception as e:
                    completed += 1
                    await progress_callback(f"[{segment}] 扫描失败: {e}")
                finally:
                    if os.path.exists(xml_path):
                        os.unlink(xml_path)

        tasks = [_scan_one_segment(seg) for seg in target_list]
        await asyncio.gather(*tasks)

        total_hosts = len(all_results)
        total_open_ports = sum(len(r.get("ports", [])) for r in all_results.values())
        await progress_callback(
            f"全部网段扫描完成, 共发现 {total_hosts} 个存活主机, {total_open_ports} 个开放端口"
        )
        return list(all_results.values())

    # ----------------------------------------------------------------
    # 全端口分块扫描（服务发现用，支持 chunk 回调）
    # ----------------------------------------------------------------

    async def _scan_full_port_chunked(self, targets: str, ports: str | None, scan_mode: str, max_concurrent: int = 4, **kwargs) -> list[dict]:
        """全端口分块扫描，按端口块并发，支持 on_chunk_done 回调。"""
        target_list = _split_targets(targets)
        max_concurrent = min(max(1, max_concurrent), 8)
        semaphore = asyncio.Semaphore(max_concurrent)
        chunk_size = kwargs.get("chunk_size", settings.SCAN_CHUNK_SIZE)
        base_args = _build_full_port_args(scan_mode)
        on_chunk_done = kwargs.get("on_chunk_done")
        progress_callback = kwargs.get("progress_callback")

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
                args = f"{base_args} -p{port_spec}"

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

                    chunk_results = self._parse_xml_results(xml_path)
                    _merge_results(all_results, chunk_results)
                    completed_tasks += 1

                    if progress_callback and completed_tasks % 5 == 0:
                        await progress_callback(
                            f"全端口扫描进度: {completed_tasks}/{total_tasks} 块完成"
                        )

                    if on_chunk_done:
                        on_chunk_done(chunk_idx, port_start, port_end, success=True)

                except Exception:
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
        parts = []
        if scan_method in METHOD_ARGS:
            parts.extend(METHOD_ARGS[scan_method])

        is_ping_scan = scan_method in ("nmap_ping", "nmap_arp")

        if not is_ping_scan:
            if scan_mode in STEALTH_PROFILES:
                profile = STEALTH_PROFILES[scan_mode]
                parts.append(profile["timing"])
                parts.extend(["--scan-delay", profile["scan_delay"]])
                parts.extend(["--max-rate", profile["max_rate"]])
                parts.extend(profile["extra"])
                if not ports:
                    parts.extend(["-p", "1-65535"])
            elif scan_mode == "quick":
                parts.extend(["-T4", "--top-ports", "100"])
            else:
                parts.append("-T4")
                if not ports:
                    parts.extend(["-p", "1-65535"])
            if ports:
                parts.extend(["-p", ports])
            parts.extend(["-v", "--reason"])
        else:
            if scan_mode == "quick":
                parts.extend(["-T4", "--top-ports", "100"])
            else:
                parts.append("-T4")

        return " ".join(parts)

    def _run_nmap(self, targets: str, args: str) -> list[dict]:
        nm = nmap.PortScanner(nmap_search_path=[settings.NMAP_PATH])
        try:
            nm.scan(hosts=targets, arguments=args)
        except nmap.PortScannerError as e:
            if "root" in str(e).lower() and "-sS" in args:
                args = args.replace("-sS", "-sT")
                nm.scan(hosts=targets, arguments=args)
            else:
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
