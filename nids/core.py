"""NIDSCore: owns the database, detection engine, capture, USB monitor and simulator,
and exposes the operations used by the web dashboard."""
import threading
import time
from collections import defaultdict, deque
from typing import Optional

from . import __version__
from .capture import CaptureError, LiveCapture, has_capture_privileges, list_interfaces, scapy_available
from .database import Database
from .detector import DetectionEngine
from .models import (Detection, PacketInfo, TYPE_INFO, USB_HID, USB_STORAGE, format_time)
from .simulator import DEMO_SEQUENCE, SCENARIOS, Simulator
from .usb_monitor import USBDevice, USBMonitor, default_provider


def human_size(n: int) -> str:
    if not n:
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0


class NIDSCore:
    def __init__(self, config: dict, db: Optional[Database] = None, start_usb: bool = True):
        self.cfg = config
        self.db = db or Database(config["database_path"])
        self.lock = threading.RLock()
        self.privileged = has_capture_privileges()
        self.started = time.time()
        self.session_id = self.db.start_session("dashboard")
        self.sim_network_active = False
        self.packets_total = 0
        self.recent = deque(maxlen=150)
        self._pps = defaultdict(int)
        self._stats_cache, self._stats_at = None, 0.0
        self.sim_usb = {}
        self.engine: Optional[DetectionEngine] = None
        self.reload_engine()
        self.capture = LiveCapture()
        self.simulator = Simulator(self)
        self.usb = USBMonitor(default_provider(), self._on_usb_event, interval=config.get("usb_poll_seconds", 3))
        if start_usb:
            self.usb.start()

    # ---------------------------------------------------------------- engine
    def reload_engine(self) -> None:
        with self.lock:
            db = self.db
            self.engine = DetectionEngine(
                db.load_rules(), [h["ip_address"] for h in db.trusted_hosts()],
                [p["port_number"] for p in db.ports("RESTRICTED")], [p["port_number"] for p in db.ports("AUTH")],
                cooldown=self.cfg.get("cooldown_seconds", 10))

    def process_packet(self, info: PacketInfo, simulated: bool = False) -> None:
        with self.lock:
            self.packets_total += 1
            sec = int(info.timestamp)
            self._pps[sec] += 1
            if self.packets_total % 2000 == 0:
                cutoff = int(time.time()) - 180
                for k in [k for k in self._pps if k < cutoff]:
                    del self._pps[k]
            for d in self.engine.process(info):
                d.simulated = simulated or self.sim_network_active
                self._emit(d)

    def _emit(self, d: Detection) -> None:
        try:
            aid = self.db.add_alert(d, self.session_id)
        except Exception as exc:
            aid = -1
            print(f"[ERROR] Alert could not be saved: {exc}", flush=True)
        self._stats_at = 0.0
        self.recent.appendleft(dict(id=aid, time=format_time(d.timestamp), source=d.source_ip, target=d.target_ip,
                                    device=d.device, type=d.attack_type, count=d.count, severity=d.severity,
                                    details=d.details, simulated=d.simulated))
        if self.cfg.get("console_alerts", True):
            who = d.source_ip or d.device or "?"
            tag = " [SIMULATED]" if d.simulated else ""
            print(f"[ALERT] {format_time(d.timestamp)} | {d.severity:<6} | {d.attack_type:<23} | "
                  f"{who} -> {d.target_ip or '-'} | {d.count} | {d.details}{tag}", flush=True)

    # ------------------------------------------------------------------- USB
    def _on_usb_event(self, action: str, dev: USBDevice, scan: Optional[dict]) -> None:
        with self.lock:
            sim = dev.simulated
            mount = dev.mounts[0] if dev.mounts else ""
            if action == "removed":
                self.db.add_usb_event("removed", dev.kind, dev.dev_id, dev.label, mount, dev.size_bytes,
                                      "-", "Device removed", sim)
                return
            trusted = self.db.is_usb_trusted(dev.dev_id)
            parts = [f"{dev.kind} device", dev.label]
            if dev.size_bytes:
                parts.append(human_size(dev.size_bytes))
            if dev.fs:
                parts.append(dev.fs)
            severity = None
            if scan:
                if scan.get("error"):
                    parts.append(f"folder scan failed: {scan['error']}")
                else:
                    parts.append(f"{scan['entries']} items in root folder")
                    if scan["autorun"]:
                        parts.append("autorun.inf PRESENT")
                    if scan["executables"]:
                        parts.append("executables/scripts: " + ", ".join(scan["executables"][:5]))
            rules = {r.name: r for r in self.engine.rules.values()}
            if dev.kind == "storage":
                rule = rules.get(USB_STORAGE)
                severity = "HIGH" if scan and scan.get("autorun") else (rule.severity if rule else "MEDIUM")
                atype, enabled = USB_STORAGE, bool(rule and rule.enabled)
            elif dev.kind == "hid":
                rule = rules.get(USB_HID)
                severity = rule.severity if rule else "MEDIUM"
                atype, enabled = USB_HID, bool(rule and rule.enabled)
            else:
                atype, enabled = None, False
            details = "; ".join(parts)
            if atype and enabled and not trusted:
                verdict = "ALERT"
                self._emit(Detection(time.time(), None, None, atype, severity, 1, 1, details,
                                     device=dev.label, simulated=sim))
            else:
                verdict = "TRUSTED" if trusted else "LOGGED"
            self.db.add_usb_event("connected", dev.kind, dev.dev_id, dev.label, mount, dev.size_bytes,
                                  verdict, details, sim)

    def simulate_usb(self, kind: str, autorun: bool = False) -> None:
        if kind == "storage":
            dev = USBDevice("SIM:FLASH-0001", "storage", "Kingston DataTraveler 3.0 (SIMULATED)", "0951", "1666",
                            "SIM0001", ["E:\\"], "FAT32", 16 * 1024 ** 3, simulated=True)
            scan = dict(entries=7, autorun=autorun, executables=["setup.exe", "invoice.pdf.lnk", "run.bat"],
                        hidden=1, error=None)
        else:
            dev = USBDevice("SIM:KBD-0002", "hid", "USB Keyboard (SIMULATED rogue device)", "1234", "5678",
                            "SIM0002", [], "", 0, simulated=True)
            scan = None
        self.sim_usb[dev.dev_id] = dev
        self._on_usb_event("connected", dev, scan)

        def remove():
            if self.sim_usb.pop(dev.dev_id, None) is not None:
                self._on_usb_event("removed", dev, None)
        t = threading.Timer(12.0, remove)
        t.daemon = True
        t.start()

    def usb_devices(self) -> list:
        devs = list(self.usb.current.values()) + list(self.sim_usb.values())
        out = []
        for d in devs:
            row = d.to_dict()
            row["trusted"] = self.db.is_usb_trusted(d.dev_id)
            row["label"] = d.label
            row["size_text"] = human_size(d.size_bytes)
            out.append(row)
        return out

    # --------------------------------------------------------------- capture
    def start_capture(self, iface: str) -> None:
        self.capture.start(iface, self.process_packet)

    def stop_capture(self) -> None:
        self.capture.stop()

    def clear_simulated(self) -> int:
        with self.lock:
            n = self.db.clear_simulated()
            keep = [a for a in self.recent if not a["simulated"]]
            self.recent.clear()
            self.recent.extend(keep)
            self._stats_at = 0.0
            return n

    # --------------------------------------------------------- configuration
    def update_rule(self, name, threshold, window, enabled, extra) -> None:
        if name not in TYPE_INFO:
            raise ValueError("Unknown rule.")
        self.db.update_rule(name, threshold, window, enabled, extra)
        self.reload_engine()

    # ----------------------------------------------------------------- state
    def _db_stats(self) -> dict:
        if self._stats_cache is None or time.time() - self._stats_at > 1.5:
            self._stats_cache, self._stats_at = self.db.stats(), time.time()
        return self._stats_cache

    def meta(self) -> dict:
        return dict(version=__version__, scenarios=[dict(id=k, **{x: v[x] for x in ("title", "text", "detects", "network", "duration", "rate")})
                                                   for k, v in SCENARIOS.items()],
                    demo_sequence=DEMO_SEQUENCE,
                    types={k: dict(description=v[0], severity=v[1], comparison=v[5], unit=v[6], category=v[7])
                           for k, v in TYPE_INFO.items()})

    def state(self) -> dict:
        now = time.time()
        with self.lock:
            sec = int(now)
            pps = [self._pps.get(s, 0) for s in range(sec - 59, sec + 1)]
            recent = list(self.recent)[:40]
            suppressed = self.engine.stats.suppressed
            packets = self.packets_total
        stats = self._db_stats()
        rules = []
        for r in self.db.load_rules():
            info = TYPE_INFO[r.name]
            rules.append(dict(name=r.name, threshold=r.threshold, window=int(r.window), enabled=r.enabled,
                              extra=r.extra, severity=r.severity, description=info[0], comparison=info[5],
                              unit=info[6], category=info[7]))
        return dict(
            now=format_time(now), uptime=int(now - self.started), version=__version__,
            capture=dict(running=self.capture.running, interface=self.capture.interface,
                         privileged=self.privileged, scapy=scapy_available()),
            usb=dict(supported=self.usb.provider is not None, running=self.usb.running, error=self.usb.error,
                     devices=self.usb_devices(), events=self.db.usb_events(15)),
            sim=dict(self.simulator.status),
            traffic=dict(packets=packets, pps=pps, current=pps[-2] if len(pps) > 1 else 0, suppressed=suppressed),
            alerts=dict(stats=stats, recent=recent),
            rules=rules, trusted_hosts=self.db.trusted_hosts(), trusted_usb=self.db.trusted_usb(),
            ports=self.db.ports())

    def interfaces(self) -> list:
        try:
            return list_interfaces()
        except CaptureError:
            return []

    def shutdown(self) -> None:
        self.simulator.stop()
        self.simulator.set_background(False)
        self.usb.stop()
        self.capture.stop()
        try:
            self.db.end_session(self.session_id)
        except Exception:
            pass
