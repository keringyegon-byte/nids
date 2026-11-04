"""Attack simulator for demonstrations.

Two modes
  inject   (default, safe) synthetic packets are fed straight into the detection engine. Needs no
           administrator rights and sends nothing on the network.
  network  real packets are sent with Scapy to a PRIVATE or loopback target you own, and are then
           picked up by the live sniffer. Needs administrator rights. Hard limits on rate, duration
           and target are enforced. ARP spoofing is never sent on a real network.
"""
import ipaddress
import random
import threading
import time
from typing import Callable, Dict, Optional

from .models import PacketInfo, TCP_SYN

MAX_RATE, MAX_DURATION = 2000, 60

SCENARIOS: Dict[str, dict] = {
    "port_scan": dict(title="Port scan (Nmap-style)", detects="PORT_SCAN", network=True, duration=6, rate=80,
                      text="One host probes hundreds of ports on a target in a few seconds."),
    "slow_scan": dict(title="Slow / stealth port scan", detects="SLOW_PORT_SCAN", network=True, duration=22,
                      rate=6, text="A patient scanner stays under the fast-scan limit; the long-window rule still catches it."),
    "syn_flood": dict(title="SYN flood", detects="SYN_FLOOD", network=True, duration=6, rate=600,
                      text="One host floods a server with TCP connection requests."),
    "ddos": dict(title="Distributed SYN flood (DDoS)", detects="DDOS_SYN", network=False, duration=8, rate=480,
                 text="Dozens of hosts each send a modest amount, but together they overwhelm one target."),
    "icmp_flood": dict(title="ICMP (ping) flood", detects="ICMP_FLOOD", network=True, duration=6, rate=400,
                       text="One host sends a storm of ping requests."),
    "brute_force": dict(title="SSH brute-force login attempts", detects="BRUTE_FORCE", network=True, duration=10,
                        rate=3, text="Repeated rapid connection attempts to the SSH login port."),
    "arp_spoof": dict(title="ARP spoofing (man-in-the-middle)", detects="ARP_SPOOFING", network=False, duration=5,
                      rate=1, text="An attacker claims the gateway's IP address with its own MAC address."),
    "unauthorized": dict(title="Connection attempts to restricted port (Telnet)", detects="UNAUTHORIZED_CONNECTION",
                         network=True, duration=6, rate=1, text="Repeated attempts to reach a forbidden service."),
    "usb_storage": dict(title="Untrusted flash drive with autorun.inf", detects="USB_STORAGE", network=False,
                        duration=1, rate=1, text="Simulates plugging in an unknown flash drive carrying an autorun file."),
    "usb_hid": dict(title="Rogue keyboard (BadUSB)", detects="USB_HID", network=False, duration=1, rate=1,
                    text="Simulates a USB device that identifies itself as a keyboard."),
}
DEMO_SEQUENCE = ["port_scan", "syn_flood", "icmp_flood", "brute_force", "arp_spoof", "ddos", "unauthorized",
                 "usb_storage", "usb_hid"]


def is_safe_target(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (a.is_private or a.is_loopback) and not a.is_multicast and not a.is_unspecified


class Simulator:
    def __init__(self, core):
        self.core = core
        self._thread: Optional[threading.Thread] = None
        self._bg: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._bg_stop = threading.Event()
        self.status = dict(running=False, scenario=None, mode="inject", progress=0.0, sent=0, message="",
                           background=False)

    # ----------------------------------------------------------------- control
    def start(self, scenario: str, mode: str = "inject", target: str = "192.168.1.10",
              duration: Optional[float] = None, rate: Optional[float] = None) -> None:
        if self._thread and self._thread.is_alive():
            raise ValueError("A simulation is already running. Stop it first.")
        if scenario != "full_demo" and scenario not in SCENARIOS:
            raise ValueError(f"Unknown scenario: {scenario}")
        if mode not in ("inject", "network"):
            raise ValueError("Mode must be 'inject' or 'network'.")
        if mode == "network":
            if not self.core.privileged:
                raise ValueError("Network mode needs administrator/root privileges.")
            if not is_safe_target(target):
                raise ValueError("For safety, network mode only allows private (LAN) or loopback targets.")
            if scenario != "full_demo" and not SCENARIOS[scenario]["network"]:
                raise ValueError("This scenario is only available in inject mode "
                                 "(it must never be sent on a real network).")
        params = dict(mode=mode, target=target, duration=duration, rate=rate)
        self._stop.clear()
        self.status.update(running=True, scenario=scenario, mode=mode, progress=0.0, sent=0, message="")
        self._thread = threading.Thread(target=self._run, args=(scenario, params), daemon=True, name="simulator")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def set_background(self, on: bool) -> None:
        if on and not (self._bg and self._bg.is_alive()):
            self._bg_stop.clear()
            self._bg = threading.Thread(target=self._background, daemon=True, name="sim-background")
            self._bg.start()
            self.status["background"] = True
        elif not on:
            self._bg_stop.set()
            self.status["background"] = False

    # --------------------------------------------------------------- internals
    def _run(self, scenario: str, params: dict) -> None:
        self.core.sim_network_active = params["mode"] == "network"
        try:
            names = DEMO_SEQUENCE if scenario == "full_demo" else [scenario]
            for i, name in enumerate(names):
                if self._stop.is_set():
                    break
                self.status["message"] = f"{SCENARIOS[name]['title']}" + (f"  ({i + 1}/{len(names)})" if len(names) > 1 else "")
                p = dict(params)
                if scenario == "full_demo":
                    p["duration"], p["rate"] = None, None
                    if p["mode"] == "network" and not SCENARIOS[name]["network"]:
                        p["mode"] = "inject"
                getattr(self, f"_sc_{name}")(p)
                if len(names) > 1 and not self._stop.is_set():
                    self._sleep(3.0)                       # pause so the audience can follow
        except Exception as exc:
            self.status["message"] = f"Simulation error: {exc}"
        finally:
            self.core.sim_network_active = False
            self.status.update(running=False, progress=1.0 if not self._stop.is_set() else self.status["progress"])
            if not self.status["message"].startswith("Simulation error"):
                self.status["message"] = "Stopped" if self._stop.is_set() else "Finished"

    def _sleep(self, secs: float) -> None:
        self._stop.wait(secs)

    def _emit(self, info: PacketInfo, mode: str, net_pkt=None) -> None:
        if mode == "network":
            from scapy.all import send
            send(net_pkt, verbose=0)
        else:
            self.core.process_packet(info, simulated=True)
        self.status["sent"] += 1

    def _paced(self, p: dict, name: str, make: Callable[[int], tuple]) -> None:
        """Send make(i) -> (PacketInfo, scapy_packet_factory) at the requested rate for the duration."""
        d = SCENARIOS[name]
        duration = min(float(p["duration"] or d["duration"]), MAX_DURATION)
        rate = min(float(p["rate"] or d["rate"]), MAX_RATE)
        t0, sent = time.time(), 0
        while not self._stop.is_set():
            elapsed = time.time() - t0
            if elapsed >= duration:
                break
            due = int(elapsed * rate) + 1
            while sent < due and not self._stop.is_set():
                info, net = make(sent)
                self._emit(info, p["mode"], net)
                sent += 1
            self.status["progress"] = min(elapsed / duration, 1.0)
            time.sleep(0.01)
        self.status["progress"] = 1.0

    @staticmethod
    def _net(builder):
        def lazy():
            return builder()
        return lazy

    def _syn(self, src, dst, dport, sport=None):
        info = PacketInfo(time.time(), src, dst, "TCP", dport, TCP_SYN)
        return info

    def _sc_port_scan(self, p):
        tgt, src = p["target"], "192.168.56.66" if p["mode"] == "inject" else None
        def make(i):
            port = 1 + (i * 7) % 65000
            info = PacketInfo(time.time(), src or "127.0.0.1", tgt, "TCP", port, TCP_SYN)
            net = None
            if p["mode"] == "network":
                from scapy.all import IP, TCP
                net = IP(dst=tgt) / TCP(sport=random.randint(1025, 65000), dport=port, flags="S")
            return info, net
        self._paced(p, "port_scan", make)

    def _sc_slow_scan(self, p):
        tgt, src = p["target"], "192.168.56.67"
        def make(i):
            port = 1000 + i
            info = PacketInfo(time.time(), src, tgt, "TCP", port, TCP_SYN)
            net = None
            if p["mode"] == "network":
                from scapy.all import IP, TCP
                net = IP(dst=tgt) / TCP(sport=random.randint(1025, 65000), dport=port, flags="S")
            return info, net
        self._paced(p, "slow_scan", make)

    def _sc_syn_flood(self, p):
        tgt, src = p["target"], "192.168.56.68"
        def make(i):
            info = PacketInfo(time.time(), src, tgt, "TCP", 80, TCP_SYN)
            net = None
            if p["mode"] == "network":
                from scapy.all import IP, TCP
                net = IP(dst=tgt) / TCP(sport=random.randint(1025, 65000), dport=80, flags="S")
            return info, net
        self._paced(p, "syn_flood", make)

    def _sc_ddos(self, p):
        tgt = p["target"]
        def make(i):
            src = f"10.20.{(i % 40) // 20}.{10 + (i % 40)}"
            return PacketInfo(time.time(), src, tgt, "TCP", 80, TCP_SYN), None
        self._paced(p, "ddos", make)

    def _sc_icmp_flood(self, p):
        tgt, src = p["target"], "192.168.56.69"
        def make(i):
            info = PacketInfo(time.time(), src, tgt, "ICMP", icmp_type=8)
            net = None
            if p["mode"] == "network":
                from scapy.all import IP, ICMP
                net = IP(dst=tgt) / ICMP()
            return info, net
        self._paced(p, "icmp_flood", make)

    def _sc_brute_force(self, p):
        tgt, src = p["target"], "192.168.56.70"
        def make(i):
            info = PacketInfo(time.time(), src, tgt, "TCP", 22, TCP_SYN)
            net = None
            if p["mode"] == "network":
                from scapy.all import IP, TCP
                net = IP(dst=tgt) / TCP(sport=random.randint(1025, 65000), dport=22, flags="S")
            return info, net
        self._paced(p, "brute_force", make)

    def _sc_unauthorized(self, p):
        tgt, src = p["target"], "192.168.56.71"
        def make(i):
            info = PacketInfo(time.time(), src, tgt, "TCP", 23, TCP_SYN)
            net = None
            if p["mode"] == "network":
                from scapy.all import IP, TCP
                net = IP(dst=tgt) / TCP(sport=random.randint(1025, 65000), dport=23, flags="S")
            return info, net
        self._paced(p, "unauthorized", make)

    def _sc_arp_spoof(self, p):
        gw, real, fake = "192.168.1.1", "aa:bb:cc:00:00:01", "de:ad:be:ef:66:66"
        self.core.process_packet(PacketInfo(time.time(), gw, "192.168.1.20", "ARP", arp_mac=real), simulated=True)
        self._sleep(1.0)
        for _ in range(int(p["duration"] or 5)):
            if self._stop.is_set():
                break
            self.core.process_packet(PacketInfo(time.time(), gw, "192.168.1.20", "ARP", arp_mac=fake), simulated=True)
            self.status["sent"] += 1
            self._sleep(1.0)

    def _sc_usb_storage(self, p):
        self.core.simulate_usb("storage", autorun=True)

    def _sc_usb_hid(self, p):
        self.core.simulate_usb("hid")

    def _background(self) -> None:
        """Quiet, harmless traffic from ~40 clients so the dashboard charts look alive."""
        rnd = random.Random()
        while not self._bg_stop.is_set():
            for _ in range(rnd.randint(25, 60)):
                src = f"192.168.1.{rnd.randint(20, 60)}"
                kind = rnd.random()
                now = time.time()
                if kind < 0.45:
                    info = PacketInfo(now, src, rnd.choice(["192.168.1.10", "192.168.1.11"]), "TCP",
                                      rnd.choice([80, 443, 443]), TCP_SYN)
                elif kind < 0.9:
                    info = PacketInfo(now, src, "192.168.1.1", "UDP", 53)
                else:
                    info = PacketInfo(now, src, "192.168.1.1", "ICMP", icmp_type=8)
                self.core.process_packet(info, simulated=True)
            self._bg_stop.wait(1.0)
