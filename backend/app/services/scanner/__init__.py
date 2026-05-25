
from .nmap_scanner import NmapScanner
from .masscan_scanner import MasscanScanner
from .scapy_scan import ScapyScanner
from .fping_scan import FpingScanner
from .socket_scanner import SocketScanner
import shutil
import logging

logger = logging.getLogger(__name__)

_nmap_available = shutil.which("nmap") is not None
_masscan_available = shutil.which("masscan") is not None
_fping_available = shutil.which("fping") is not None

SCANNER_REGISTRY = {}

if _nmap_available:
    SCANNER_REGISTRY.update({
        "nmap_syn": NmapScanner, "nmap_connect": NmapScanner,
        "nmap_udp": NmapScanner, "nmap_service": NmapScanner,
        "nmap_os": NmapScanner, "nmap_script": NmapScanner,
    })
else:
    logger.info("nmap not found, all nmap methods fallback to SocketScanner (TCP full connect)")
    for m in ["nmap_syn", "nmap_connect", "nmap_udp", "nmap_service", "nmap_os", "nmap_script"]:
        SCANNER_REGISTRY[m] = SocketScanner

if _masscan_available:
    SCANNER_REGISTRY["masscan"] = MasscanScanner
else:
    SCANNER_REGISTRY["masscan"] = SocketScanner

if _fping_available:
    SCANNER_REGISTRY["fping"] = FpingScanner
else:
    SCANNER_REGISTRY["fping"] = SocketScanner

SCANNER_REGISTRY["arp_scan"] = ScapyScanner
