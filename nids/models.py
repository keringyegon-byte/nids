"""Shared data structures and the catalogue of detection types."""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK, TCP_URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
ICMP_ECHO_REQUEST = 8

PORT_SCAN = "PORT_SCAN"
SLOW_PORT_SCAN = "SLOW_PORT_SCAN"
SYN_FLOOD = "SYN_FLOOD"
DDOS_SYN = "DDOS_SYN"
ICMP_FLOOD = "ICMP_FLOOD"
BRUTE_FORCE = "BRUTE_FORCE"
ARP_SPOOFING = "ARP_SPOOFING"
UNAUTHORIZED = "UNAUTHORIZED_CONNECTION"
USB_STORAGE = "USB_STORAGE"
USB_HID = "USB_HID"

# name -> (description, default severity, threshold, window seconds, extra, comparison, unit, category)
TYPE_INFO = {
    PORT_SCAN:      ("Fast port scan: many unique ports probed by one host", "MEDIUM", 50, 1, 0, ">", "unique ports", "NETWORK"),
    SLOW_PORT_SCAN: ("Slow/stealth port scan spread over a longer window", "MEDIUM", 100, 60, 0, ">", "unique ports", "NETWORK"),
    SYN_FLOOD:      ("SYN flood: too many TCP SYN packets from one host", "HIGH", 100, 1, 0, ">", "SYN packets", "NETWORK"),
    DDOS_SYN:       ("Distributed SYN flood: many hosts overwhelming one target (extra = minimum sources)", "HIGH", 300, 1, 10, ">", "SYN packets", "NETWORK"),
    ICMP_FLOOD:     ("ICMP (ping) flood from one host", "MEDIUM", 100, 1, 0, ">", "ICMP echo requests", "NETWORK"),
    BRUTE_FORCE:    ("Repeated login attempts against SSH/FTP/RDP style ports", "HIGH", 10, 30, 0, ">", "connection attempts", "NETWORK"),
    ARP_SPOOFING:   ("ARP spoofing: an IP address suddenly claimed by a different MAC address", "HIGH", 1, 60, 0, ">=", "binding changes", "NETWORK"),
    UNAUTHORIZED:   ("Connection attempts to restricted ports (e.g. Telnet, VNC, backdoor ports)", "LOW", 3, 10, 0, ">", "restricted-port attempts", "NETWORK"),
    USB_STORAGE:    ("Untrusted external storage (flash drive / external disk) connected", "MEDIUM", 1, 1, 0, ">=", "devices", "USB"),
    USB_HID:        ("Untrusted keyboard-like USB device connected (possible BadUSB)", "MEDIUM", 1, 1, 0, ">=", "devices", "USB"),
}
ATTACK_TYPES = tuple(TYPE_INFO)
NETWORK_TYPES = tuple(k for k, v in TYPE_INFO.items() if v[7] == "NETWORK")


@dataclass(frozen=True)
class PacketInfo:
    """Header fields the Detection Engine needs from one packet."""
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str                      # TCP, UDP, ICMP, ARP or OTHER
    dst_port: Optional[int] = None
    tcp_flags: Optional[int] = None
    icmp_type: Optional[int] = None
    arp_mac: Optional[str] = None      # sender MAC claimed inside an ARP packet
    src_mac: Optional[str] = None

    @property
    def is_syn(self) -> bool:
        return (self.protocol == "TCP" and self.tcp_flags is not None
                and (self.tcp_flags & 0x17) == TCP_SYN)

    @property
    def is_scan_probe(self) -> bool:
        if self.protocol != "TCP" or self.tcp_flags is None:
            return False
        return self.is_syn or self.tcp_flags in (0x00, TCP_FIN, TCP_FIN | TCP_PSH | TCP_URG)

    @property
    def is_echo_request(self) -> bool:
        return self.protocol == "ICMP" and self.icmp_type == ICMP_ECHO_REQUEST


@dataclass
class Detection:
    timestamp: float
    source_ip: Optional[str]
    target_ip: Optional[str]
    attack_type: str
    severity: str
    count: int
    window_seconds: float
    details: str = ""
    device: Optional[str] = None       # USB device description for USB alerts
    simulated: bool = False


def format_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
