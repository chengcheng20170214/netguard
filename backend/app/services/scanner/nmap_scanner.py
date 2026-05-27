
import asyncio
import ipaddress
import re
import nmap
from .base import BaseScanner
from app.config import settings


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


class NmapScanner(BaseScanner):
    async def scan(self, targets: str, ports: str | None = None, **kwargs) -> list[dict]:
        targets = validate_targets(targets)
        scan_method = kwargs.get("scan_method", "nmap_syn")
        scan_mode = kwargs.get("scan_mode", "standard")

        if scan_method == "nmap_syn_full":
            return await self._scan_full_port_chunked(targets, ports, scan_mode, **kwargs)

        args = self._build_args(scan_method, scan_mode, ports)
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(None, self._run_nmap, targets, args)
        return results

    async def _scan_full_port_chunked(self, targets: str, ports: str | None, scan_mode: str, **kwargs) -> list[dict]:
        chunk_size = kwargs.get("chunk_size", settings.SCAN_CHUNK_SIZE)
        base_args = _build_full_port_args(scan_mode)

        chunk_ranges = []
        start = 1
        while start <= 65535:
            end = min(start + chunk_size - 1, 65535)
            chunk_ranges.append((start, end))
            start = end + 1

        on_chunk_done = kwargs.get("on_chunk_done")

        all_results = {}
        for i, (port_start, port_end) in enumerate(chunk_ranges):
            port_spec = f"{port_start}-{port_end}"
            args = f"{base_args} -p{port_spec}"

            try:
                loop = asyncio.get_event_loop()
                chunk_results = await loop.run_in_executor(None, self._run_nmap, targets, args)
                for r in chunk_results:
                    ip = r.get("ip")
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
            except Exception:
                if on_chunk_done:
                    on_chunk_done(i, port_start, port_end, success=False)
                continue

            if on_chunk_done:
                on_chunk_done(i, port_start, port_end, success=True)

        return list(all_results.values())

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
