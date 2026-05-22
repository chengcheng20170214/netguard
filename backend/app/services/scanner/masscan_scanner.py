
import asyncio
from .base import BaseScanner
from app.config import settings

class MasscanScanner(BaseScanner):
    async def scan(self, targets: str, ports: str | None = None, **kwargs) -> list[dict]:
        scan_mode = kwargs.get("scan_mode", "standard")
        rate = "10000"
        if scan_mode.startswith("stealth_light"):
            rate = "100"
        elif scan_mode.startswith("stealth_medium"):
            rate = "50"
        elif scan_mode.startswith("stealth_deep"):
            rate = "10"

        args = [settings.MASSCAN_PATH, targets, "--rate", rate, "-oL", "-"]
        if ports:
            args.extend(["-p", ports])
        else:
            args.extend(["-p", "1-65535"])

        if scan_mode.startswith("stealth"):
            args.append("--randomize-hosts")

        proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, _ = await proc.communicate()

        results_map = {}
        for line in stdout.decode().strip().split("\n"):
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "open":
                proto = parts[1]
                port = int(parts[2])
                ip = parts[3]
                if ip not in results_map:
                    results_map[ip] = {"ip": ip, "mac": None, "hostname": None, "os": None, "ports": []}
                results_map[ip]["ports"].append({"port": port, "proto": proto, "service": "", "version": ""})

        return list(results_map.values())
