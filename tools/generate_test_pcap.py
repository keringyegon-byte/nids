#!/usr/bin/env python3
"""Generate a labelled lab test capture (PCAP + ground-truth JSON) for evaluating the NIDS.

Traffic is synthesised with Scapy: ordinary client behaviour, deliberately "busy but
legitimate" hosts (to test false positives), and attackers that mimic Nmap scans and
hping3 floods. Every source IP is labelled, so tools/evaluate.py can score the NIDS.

  python tools/generate_test_pcap.py --out lab_test.pcap --seed 1
"""
import argparse
import json
import logging
import random

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import ARP, Ether, IP, TCP, UDP, ICMP, wrpcap

BASE = 1_700_000_000.0                 # arbitrary fixed start time (reproducible)
SERVERS = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]


def pkt(ts, p):
    p.time = ts
    return p


def tcp(ts, src, dst, dport, flags="S", sport=None, rnd=random):
    return pkt(ts, IP(src=src, dst=dst) / TCP(sport=sport or rnd.randint(1025, 65000),
                                              dport=dport, flags=flags))


def build(seed: int, duration: int, clients: int, per_type: int):
    rnd = random.Random(seed)
    packets, truth = [], {}

    # ---- ordinary clients: web browsing, DNS, occasional ping -----------------------
    for i in range(clients):
        ip = f"192.168.1.{20 + i}"
        truth[ip] = {"label": "NORMAL"}
        t = rnd.uniform(0, 2)
        while t < duration:
            kind = rnd.random()
            if kind < 0.55:                                    # page load: a small burst of SYNs
                for _ in range(rnd.randint(1, 12)):
                    packets.append(tcp(BASE + t + rnd.uniform(0, 0.8), ip, rnd.choice(SERVERS),
                                       rnd.choice([80, 443, 443, 443]), rnd=rnd))
            elif kind < 0.9:
                packets.append(pkt(BASE + t, IP(src=ip, dst="192.168.1.1") /
                                   UDP(sport=rnd.randint(1025, 65000), dport=53)))
            else:
                packets.append(pkt(BASE + t, IP(src=ip, dst=rnd.choice(SERVERS)) / ICMP(type=8)))
            t += rnd.expovariate(1 / 2.5)

    # ---- busy but legitimate hosts (must NOT alarm) ---------------------------------
    heavy = "192.168.1.100"            # download manager: 60 new connections/s for 5 s
    truth[heavy] = {"label": "NORMAL"}
    for k in range(300):
        packets.append(tcp(BASE + 8 + k / 60, heavy, "192.168.1.10", 443, rnd=rnd))
    monitor = "192.168.1.101"          # network monitoring tool: 20 pings/s for 10 s
    truth[monitor] = {"label": "NORMAL"}
    for k in range(200):
        packets.append(pkt(BASE + 12 + k / 20, IP(src=monitor, dst="192.168.1.1") / ICMP(type=8)))
    server = "192.168.1.10"            # busy web server: 80 SYN-ACK replies/s to many clients
    truth[server] = {"label": "NORMAL"}
    for k in range(400):
        packets.append(tcp(BASE + 5 + k / 80, server, f"192.168.1.{20 + k % clients}",
                           rnd.randint(1025, 65000), flags="SA", sport=443, rnd=rnd))

    # ---- attackers --------------------------------------------------------------------
    def start():
        return rnd.uniform(5, duration - 15)

    scan_rates = [90, 75, 60]                        # ports per second (above 50/s, below the 100 SYN/s flood limit)
    flood_rates = [1000, 400, 150]                   # packets per second (all above 100/s)
    for n in range(per_type):
        # Nmap-style SYN port scan of one host
        ip, s, r = f"10.0.1.{10 + n}", start(), scan_rates[n % 3]
        truth[ip] = {"label": "PORT_SCAN", "start": BASE + s}
        ports = rnd.sample(range(1, 1025), 300)
        for k, port in enumerate(ports):
            packets.append(tcp(BASE + s + k / r, ip, "192.168.1.10", port, rnd=rnd))

        # hping3-style SYN flood against a web server
        ip, s, r = f"10.0.2.{10 + n}", start(), flood_rates[n % 3]
        truth[ip] = {"label": "SYN_FLOOD", "start": BASE + s}
        for k in range(r * 5):
            packets.append(tcp(BASE + s + k / r, ip, "192.168.1.11", 80, rnd=rnd))

        # ping flood
        ip, s, r = f"10.0.3.{10 + n}", start(), flood_rates[n % 3]
        truth[ip] = {"label": "ICMP_FLOOD", "start": BASE + s}
        for k in range(r * 5):
            packets.append(pkt(BASE + s + k / r, IP(src=ip, dst="192.168.1.12") / ICMP(type=8)))

        # repeated attempts on Telnet / RDP
        ip, s = f"10.0.4.{10 + n}", start()
        truth[ip] = {"label": "UNAUTHORIZED_CONNECTION", "start": BASE + s}
        for k in range(6):
            packets.append(tcp(BASE + s + k * 1.0, ip, "192.168.1.10",
                               23 if n % 2 == 0 else 5900, rnd=rnd))

    for n in range(per_type):
        # SSH brute force: one login attempt per second for 20 s
        ip, s = f"10.0.5.{10 + n}", start()
        truth[ip] = {"label": "BRUTE_FORCE", "start": BASE + s}
        for k in range(20):
            packets.append(tcp(BASE + s + k * 1.0, ip, "192.168.1.10", 22, rnd=rnd))

        # slow port scan: 5 ports per second for 40 s (below the fast-scan limit)
        ip, s = f"10.0.6.{10 + n}", start()
        truth[ip] = {"label": "SLOW_PORT_SCAN", "start": BASE + s}
        for k in range(200):
            packets.append(tcp(BASE + s + k / 5.0, ip, "192.168.1.10", 2000 + k, rnd=rnd))

        # distributed SYN flood: 40 spoofed hosts x 12 SYN/s for 6 s against one target
        victim, s = f"192.168.1.{13 + n}", start()
        truth[f"DDOS@{victim}"] = {"label": "DDOS_SYN", "start": BASE + s}
        for k in range(480 * 6):
            packets.append(tcp(BASE + s + k / 480.0, f"172.16.{n}.{10 + k % 40}", victim, 80, rnd=rnd))

        # ARP spoofing: attacker claims the gateway/host IP with a different MAC
        victim_ip = f"192.168.1.{1 + n}"
        truth[f"ARP@{victim_ip}"] = {"label": "ARP_SPOOFING", "start": BASE + (s := start()) + 2}
        real_mac, fake_mac = f"aa:bb:cc:00:00:{n + 1:02x}", f"de:ad:be:ef:00:{n + 1:02x}"
        for k in range(3):
            packets.append(pkt(BASE + s + k * 0.5, Ether(src=real_mac) / ARP(op=2, psrc=victim_ip, hwsrc=real_mac, pdst="192.168.1.20")))
        for k in range(4):
            packets.append(pkt(BASE + s + 2 + k, Ether(src=fake_mac) / ARP(op=2, psrc=victim_ip, hwsrc=fake_mac, pdst="192.168.1.20")))

    # ordinary hosts also announce themselves with ARP (must not alarm)
    for i in range(clients):
        mac = f"cc:00:00:00:{i:02x}:01"
        for k in range(3):
            packets.append(pkt(BASE + 3 + k * 20 + i * 0.1, Ether(src=mac) / ARP(op=1, psrc=f"192.168.1.{20 + i}", hwsrc=mac, pdst="192.168.1.1")))

    packets.sort(key=lambda p: float(p.time))
    frames = []
    for p in packets:                       # wrap in Ethernet, as on a real LAN capture
        f = p if Ether in p else Ether() / p
        f.time = p.time
        frames.append(f)
    return frames, truth


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="lab_test.pcap")
    ap.add_argument("--truth", help="ground-truth JSON (default: <out>.truth.json)")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--duration", type=int, default=120, help="seconds of traffic")
    ap.add_argument("--clients", type=int, default=40, help="ordinary client hosts")
    ap.add_argument("--attackers-per-type", type=int, default=3)
    a = ap.parse_args()

    packets, truth = build(a.seed, a.duration, a.clients, a.attackers_per_type)
    wrpcap(a.out, packets)
    truth_path = a.truth or a.out + ".truth.json"
    with open(truth_path, "w") as fh:
        json.dump(truth, fh, indent=1)
    n_att = sum(1 for v in truth.values() if v["label"] != "NORMAL")
    print(f"Wrote {len(packets)} packets to {a.out}\n"
          f"Wrote ground truth for {len(truth)} hosts ({n_att} attackers) to {truth_path}")


if __name__ == "__main__":
    main()
