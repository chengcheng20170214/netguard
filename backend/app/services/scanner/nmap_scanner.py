
import asyncio
import xml.etree.ElementTree as ET
from .base import BaseScanner
from app.config import settings

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
}

class NmapScanner(BaseScanner):
    async def scan(self, targets: str, ports: str | None = None, **kwargs) -> list[dict]:
        scan_method = kwargs.get("scan_method", "nmap_syn")
        scan_mode = kwargs.get("scan_mode", "standard")
        args = [settings.NMAP_PATH]

        if scan_method in METHOD_ARGS:
            args.extend(METHOD_ARGS[scan_method])

        if scan_mode in STEALTH_PROFILES:
            profile = STEALTH_PROFILES[scan_mode]
            args.append(profile["timing"])
            args.extend(["--scan-delay", profile["scan_delay"]])
            args.extend(["--max-rate", profile["max_rate"]])
            args.extend(profile["extra"])
        elif scan_mode == "quick":
            args.extend(["-T4", "--top-ports", "100"])
        else:
            args.append("-T4")

        if ports:
            args.extend(["-p", ports])

        args.extend(["-oX", "-", targets])

        proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0 and not stdout:
            return []

        return self._parse_xml(stdout.decode())

    def _parse_xml(self, xml_output: str) -> list[dict]:
        results = []
        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError:
            return results

        for host in root.findall(".//host"):
            if host.get("status", {}).get("state") == "down" if hasattr(host, "get") else False:
                continue
            addr_elem = host.find("address[@addrtype='ipv4']")
            mac_elem = host.find("address[@addrtype='mac']")
            hostnames = host.find("hostnames")
            os_elem = host.find("os")

            ip = addr_elem.get("addr") if addr_elem is not None else None
            if not ip:
                continue

            mac = mac_elem.get("addr") if mac_elem is not None else None
            hostname = None
            if hostnames is not None:
                hn = hostnames.find("hostname")
                if hn is not None:
                    hostname = hn.get("name")

            os_name = None
            if os_elem is not None:
                osmatch = os_elem.find("osmatch")
                if osmatch is not None:
                    os_name = osmatch.get("name")

            ports_list = []
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port in ports_elem.findall("port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        svc = port.find("service")
                        ports_list.append({
                            "port": int(port.get("portid", 0)),
                            "proto": port.get("protocol", "tcp"),
                            "service": svc.get("name", "") if svc is not None else "",
                            "version": svc.get("version", "") if svc is not None else "",
                        })

            results.append({"ip": ip, "mac": mac, "hostname": hostname, "os": os_name, "ports": ports_list})

        return results
