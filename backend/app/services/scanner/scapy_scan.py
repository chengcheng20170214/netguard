
from .base import BaseScanner

class ScapyScanner(BaseScanner):
    async def scan(self, targets: str, ports: str | None = None, **kwargs) -> list[dict]:
        try:
            from scapy.all import srp, ARP, Ether, conf
            conf.verb = 0
        except ImportError:
            return []

        import asyncio
        loop = asyncio.get_event_loop()
        results = []

        def do_arp_scan():
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targets), timeout=3, verbose=0)
            hosts = []
            for snd, rcv in ans:
                hosts.append({
                    "ip": rcv.psrc,
                    "mac": rcv.hwsrc,
                    "hostname": None,
                    "os": None,
                    "ports": []
                })
            return hosts

        results = await loop.run_in_executor(None, do_arp_scan)
        return results
