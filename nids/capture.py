"""Packet Capture Module: live sniffing (promiscuous mode) and PCAP replay via Scapy."""
import os
import time
from typing import Callable, Iterator, List, Optional

from .models import PacketInfo


class CaptureError(Exception):
    """A problem the administrator can fix (privileges, interface, file)."""


def has_capture_privileges() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False


def scapy_available() -> bool:
    try:
        import scapy.all  # noqa: F401
        return True
    except Exception:
        return False


def list_interfaces() -> List[dict]:
    """Return [{'name', 'description', 'ip'}] for the interfaces Scapy can capture on."""
    try:
        from scapy.all import conf
        out = []
        for iface in conf.ifaces.values():
            name = getattr(iface, "name", None) or str(iface)
            ip = getattr(iface, "ip", "") or ""
            desc = getattr(iface, "description", "") or ""
            if ip in ("", "0.0.0.0") and not desc:
                continue
            out.append({"name": name, "description": desc, "ip": ip})
        return out
    except Exception as exc:
        raise CaptureError(f"Could not list network interfaces: {exc}")


def packet_to_info(pkt) -> Optional[PacketInfo]:
    """Extract the header fields used by the detection rules. IPv6/other frames are skipped."""
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP, Ether
    ts = float(pkt.time)
    if ARP in pkt:
        a = pkt[ARP]
        return PacketInfo(ts, a.psrc, a.pdst, "ARP", arp_mac=str(a.hwsrc).lower(),
                          src_mac=pkt[Ether].src.lower() if Ether in pkt else None)
    if IP not in pkt:
        raw = bytes(pkt) if pkt.__class__.__name__ == "Raw" else b""
        if raw and raw[0] >> 4 == 4:                 # raw-IP capture without link header
            pkt = IP(raw)
        else:
            return None
    ip = pkt[IP]
    if TCP in pkt:
        t = pkt[TCP]
        return PacketInfo(ts, ip.src, ip.dst, "TCP", int(t.dport), int(t.flags))
    if ICMP in pkt:
        return PacketInfo(ts, ip.src, ip.dst, "ICMP", icmp_type=int(pkt[ICMP].type))
    if UDP in pkt:
        return PacketInfo(ts, ip.src, ip.dst, "UDP", int(pkt[UDP].dport))
    return PacketInfo(ts, ip.src, ip.dst, "OTHER")


class LiveCapture:
    """Background sniffer that can be started and stopped from the dashboard."""

    def __init__(self):
        self._sniffer = None
        self.interface: Optional[str] = None
        self.error: Optional[str] = None

    @property
    def running(self) -> bool:
        return bool(self._sniffer is not None and getattr(self._sniffer, "running", False))

    def start(self, interface: str, callback: Callable[[PacketInfo], None]) -> None:
        if self.running:
            raise CaptureError("Capture is already running.")
        if not has_capture_privileges():
            raise CaptureError("Packet capture needs administrator/root privileges. Restart the program "
                               "with sudo (Linux) or from an Administrator terminal (Windows).")
        try:
            from scapy.all import AsyncSniffer, conf
        except Exception as exc:
            raise CaptureError(f"Scapy is not installed or could not be loaded: {exc}")
        conf.sniff_promisc = True

        def _on_packet(pkt):
            info = packet_to_info(pkt)
            if info is not None:
                callback(info)

        self.error = None
        self._sniffer = AsyncSniffer(iface=interface, prn=_on_packet, store=False)
        self._sniffer.start()
        time.sleep(0.4)
        if not self.running:
            exc = getattr(self._sniffer, "exception", None)
            self._sniffer = None
            raise CaptureError(f"Could not capture on '{interface}': {exc or 'interface unavailable'}")
        self.interface = interface

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                if self._sniffer.running:
                    self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None


def read_pcap(path: str) -> Iterator[PacketInfo]:
    if not os.path.isfile(path):
        raise CaptureError(f"PCAP file not found: {path}")
    from scapy.all import PcapReader
    try:
        with PcapReader(path) as reader:
            for pkt in reader:
                info = packet_to_info(pkt)
                if info is not None:
                    yield info
    except Exception as exc:
        raise CaptureError(f"Could not read PCAP file '{path}': {exc}")
