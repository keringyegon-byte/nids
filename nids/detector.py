"""Detection Engine: threshold rules over sliding windows, plus ARP-spoofing and
distributed-flood detection. Independent of Scapy and the database, so it can be unit
tested and can analyse live traffic, simulated traffic or PCAP replays."""
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set

from .models import (ARP_SPOOFING, BRUTE_FORCE, DDOS_SYN, Detection, ICMP_FLOOD, PacketInfo,
                     PORT_SCAN, SLOW_PORT_SCAN, SYN_FLOOD, UNAUTHORIZED)


@dataclass
class Rule:
    name: str
    threshold: int
    window: float = 1.0
    severity: str = "MEDIUM"
    enabled: bool = True
    extra: int = 0                    # DDOS_SYN: minimum number of distinct sources


@dataclass
class EngineStats:
    packets: int = 0
    trusted_ignored: int = 0
    detections: int = 0
    suppressed: int = 0


class _TimeWindow:
    __slots__ = ("window", "q")

    def __init__(self, window: float):
        self.window, self.q = window, deque()

    def add(self, ts: float, item=None) -> int:
        q = self.q
        q.append(ts)
        cutoff = ts - self.window
        while q and q[0] <= cutoff:
            q.popleft()
        return len(q)

    def detail(self) -> str:
        return ""


class _PortWindow:
    """Unique destination ports seen inside the window (memory bounded by #unique ports)."""
    __slots__ = ("window", "d")

    def __init__(self, window: float):
        self.window, self.d = window, OrderedDict()

    def add(self, ts: float, port: int) -> int:
        d = self.d
        if port in d:
            d.move_to_end(port)
        d[port] = ts
        cutoff = ts - self.window
        while d:
            first = next(iter(d))
            if d[first] <= cutoff:
                del d[first]
            else:
                break
        return len(d)

    def detail(self) -> str:
        return "ports e.g. " + ",".join(str(p) for p in sorted(self.d)[:10])


class _DestWindow:
    """SYN packets aimed at one destination, with the set of sources that sent them."""
    __slots__ = ("window", "q", "src")

    def __init__(self, window: float):
        self.window, self.q, self.src = window, deque(), Counter()

    def add(self, ts: float, src: str):
        self.q.append((ts, src))
        self.src[src] += 1
        cutoff = ts - self.window
        q = self.q
        while q and q[0][0] <= cutoff:
            _, s = q.popleft()
            self.src[s] -= 1
            if self.src[s] <= 0:
                del self.src[s]
        return len(q), len(self.src)


@dataclass
class _SourceState:
    last_seen: float = 0.0
    windows: Dict[str, object] = field(default_factory=dict)


class DetectionEngine:
    def __init__(self, rules: Iterable[Rule], trusted_hosts: Iterable[str] = (),
                 restricted_ports: Iterable[int] = (), auth_ports: Iterable[int] = (),
                 cooldown: float = 10.0, prune_every: int = 5000):
        self.rules: Dict[str, Rule] = {r.name: r for r in rules}
        self.trusted: Set[str] = set(trusted_hosts)
        self.restricted: Set[int] = set(restricted_ports)
        self.auth: Set[int] = set(auth_ports)
        self.cooldown = float(cooldown)
        self.stats = EngineStats()
        self._sources: Dict[str, _SourceState] = {}
        self._dests: Dict[str, _DestWindow] = {}
        self._arp: Dict[str, str] = {}
        self._arp_changes: Dict[str, deque] = {}
        self._last_alert: Dict[tuple, float] = {}
        self._prune_every = prune_every

    # ------------------------------------------------------------------ public
    def process(self, pkt: PacketInfo) -> List[Detection]:
        self.stats.packets += 1
        if self.stats.packets % self._prune_every == 0:
            self._prune(pkt.timestamp)
        if pkt.protocol == "ARP":
            return self._arp_check(pkt)

        src = pkt.src_ip
        if src in self.trusted:
            self.stats.trusted_ignored += 1
            return []
        state = self._sources.get(src)
        if state is None:
            state = self._sources[src] = _SourceState()
        state.last_seen = pkt.timestamp

        found: List[Detection] = []
        if pkt.protocol == "TCP":
            if pkt.is_scan_probe and pkt.dst_port is not None:
                self._update(found, PORT_SCAN, pkt, state, pkt.dst_port)
                self._update(found, SLOW_PORT_SCAN, pkt, state, pkt.dst_port)
            if pkt.is_syn:
                self._update(found, SYN_FLOOD, pkt, state)
                self._ddos(found, pkt)
                if pkt.dst_port in self.restricted:
                    self._update(found, UNAUTHORIZED, pkt, state)
                if pkt.dst_port in self.auth:
                    self._update(found, BRUTE_FORCE, pkt, state,
                                 note=f"attempts to {pkt.dst_ip}:{pkt.dst_port}")
        elif pkt.is_echo_request:
            self._update(found, ICMP_FLOOD, pkt, state)
        return found

    # --------------------------------------------------------------- internals
    def _update(self, out, name, pkt, state, item=None, note="") -> None:
        rule = self.rules.get(name)
        if rule is None or not rule.enabled:
            return
        win = state.windows.get(name)
        if win is None:
            cls = _PortWindow if name in (PORT_SCAN, SLOW_PORT_SCAN) else _TimeWindow
            win = state.windows[name] = cls(rule.window)
        count = win.add(pkt.timestamp, item)
        if count <= rule.threshold:
            return
        if name == SLOW_PORT_SCAN:           # a fast scan already reported: no duplicate
            last_fast = self._last_alert.get((pkt.src_ip, PORT_SCAN))
            if last_fast is not None and pkt.timestamp - last_fast < rule.window:
                return
        detail = win.detail() or (f"{count} {note}" if note else f"{count} events in {rule.window:g}s")
        self._raise(out, name, rule, pkt.src_ip, pkt.dst_ip, pkt.timestamp, count, detail,
                    key=(pkt.src_ip, name))

    def _ddos(self, out, pkt) -> None:
        rule = self.rules.get(DDOS_SYN)
        if rule is None or not rule.enabled:
            return
        win = self._dests.get(pkt.dst_ip)
        if win is None:
            win = self._dests[pkt.dst_ip] = _DestWindow(rule.window)
        count, nsrc = win.add(pkt.timestamp, pkt.src_ip)
        if count > rule.threshold and nsrc >= max(rule.extra, 2):
            top = ", ".join(ip for ip, _ in win.src.most_common(3))
            self._raise(out, DDOS_SYN, rule, f"Multiple ({nsrc} sources)", pkt.dst_ip,
                        pkt.timestamp, count, f"{nsrc} sources, e.g. {top}", key=(pkt.dst_ip, DDOS_SYN))

    def _arp_check(self, pkt) -> List[Detection]:
        rule = self.rules.get(ARP_SPOOFING)
        ip, mac = pkt.src_ip, pkt.arp_mac
        if rule is None or not rule.enabled or not mac or ip in (None, "", "0.0.0.0"):
            return []
        known = self._arp.get(ip)
        if known is None:
            self._arp[ip] = mac
            return []
        if known == mac:
            return []
        self._arp[ip] = mac
        changes = self._arp_changes.setdefault(ip, deque())
        changes.append(pkt.timestamp)
        while changes and changes[0] <= pkt.timestamp - rule.window:
            changes.popleft()
        if len(changes) >= rule.threshold:
            out: List[Detection] = []
            self._raise(out, ARP_SPOOFING, rule, ip, pkt.dst_ip, pkt.timestamp, len(changes),
                        f"{ip} changed from {known} to {mac}", key=(ip, ARP_SPOOFING))
            return out
        return []

    def _raise(self, out, name, rule, source, target, ts, count, detail, key) -> None:
        last = self._last_alert.get(key)
        if last is not None and 0 <= ts - last < self.cooldown:
            self.stats.suppressed += 1
            return
        self._last_alert[key] = ts
        self.stats.detections += 1
        out.append(Detection(ts, source, target, name, rule.severity, count, rule.window, detail))

    def _prune(self, now: float) -> None:
        horizon = max([r.window for r in self.rules.values()] + [1.0]) + 1.0
        for ip in [i for i, s in self._sources.items() if now - s.last_seen > horizon]:
            del self._sources[ip]
        for ip in [i for i, w in self._dests.items() if not w.q or now - w.q[-1][0] > horizon]:
            del self._dests[ip]
        for key in [k for k, t in self._last_alert.items() if now - t > max(self.cooldown, horizon)]:
            del self._last_alert[key]
