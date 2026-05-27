
from .nmap_scanner import NmapScanner
import shutil
import logging

logger = logging.getLogger(__name__)

_nmap_available = shutil.which("nmap") is not None

if not _nmap_available:
    logger.critical("nmap not found - all scanning requires nmap. Install: sudo apt install nmap")

SCANNER_REGISTRY = {
    "nmap_syn": NmapScanner,
    "nmap_syn_full": NmapScanner,
    "nmap_connect": NmapScanner,
    "nmap_udp": NmapScanner,
    "nmap_service": NmapScanner,
    "nmap_os": NmapScanner,
    "nmap_script": NmapScanner,
    "nmap_ping": NmapScanner,
    "nmap_arp": NmapScanner,
}
