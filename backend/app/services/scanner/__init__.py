
from .nmap_scanner import NmapScanner
from .masscan_scanner import MasscanScanner
from .scapy_scan import ScapyScanner
from .fping_scan import FpingScanner

SCANNER_REGISTRY = {
    "nmap_syn": NmapScanner,
    "nmap_connect": NmapScanner,
    "nmap_udp": NmapScanner,
    "nmap_service": NmapScanner,
    "nmap_os": NmapScanner,
    "nmap_script": NmapScanner,
    "masscan": MasscanScanner,
    "fping": FpingScanner,
    "arp_scan": ScapyScanner,
}
