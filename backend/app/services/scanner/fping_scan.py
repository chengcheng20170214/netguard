
import asyncio
from .base import BaseScanner
from app.config import settings

class FpingScanner(BaseScanner):
    async def scan(self, targets: str, ports: str | None = None, **kwargs) -> list[dict]:
        args = [settings.FPING_PATH, "-a", "-g", targets, "-q"]
        proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        stdout, _ = await proc.communicate()

        results = []
        for line in stdout.decode().strip().split("\n"):
            ip = line.strip()
            if ip:
                results.append({"ip": ip, "mac": None, "hostname": None, "os": None, "ports": []})
        return results
