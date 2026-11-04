#!/usr/bin/env python3
"""Score the NIDS against a labelled capture produced by generate_test_pcap.py.

Unit of evaluation = one source host.
  TP  attacker host that raised an alert of its own attack type
  FN  attacker host with no matching alert
  FP  normal host that raised any alert (or attacker raising an alert of a *different* type
      is NOT counted as FP; it is reported separately)
  TN  normal host that stayed silent
Detection delay = first matching alert time - attack start time (capture time).
Throughput is measured separately on the whole capture.

  python tools/evaluate.py lab_test.pcap [--truth lab_test.pcap.json] [--csv results.csv]
"""
import argparse
import csv
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nids.capture import read_pcap
from nids.database import default_rules
from nids.detector import DetectionEngine
from nids.models import ATTACK_TYPES, DDOS_SYN, ARP_SPOOFING


def run(pcap, cooldown=10):
    eng = DetectionEngine(default_rules(), restricted_ports=[23, 4444, 5900], auth_ports=[21, 22, 3389],
                          cooldown=cooldown)
    detections, t0 = [], time.perf_counter()
    for info in read_pcap(pcap):
        detections += eng.process(info)
    return detections, eng.stats, time.perf_counter() - t0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--truth")
    ap.add_argument("--csv", help="write the per-attack-type table to this CSV file")
    a = ap.parse_args()
    truth = json.load(open(a.truth or a.pcap + ".truth.json"))

    detections, stats, secs = run(a.pcap)
    def key_of(d):
        if d.attack_type == DDOS_SYN:
            return "DDOS@" + d.target_ip
        if d.attack_type == ARP_SPOOFING:
            return "ARP@" + d.source_ip
        return d.source_ip
    first = {}                                         # (entity, type) -> first alert time
    for d in detections:
        first.setdefault((key_of(d), d.attack_type), d.timestamp)
    alerted_hosts = {key_of(d) for d in detections}

    rows, TP = [], 0
    for typ in ATTACK_TYPES:
        hosts = [ip for ip, v in truth.items() if v["label"] == typ]
        hit = [ip for ip in hosts if (ip, typ) in first]
        delays = [first[(ip, typ)] - truth[ip]["start"] for ip in hit]
        TP += len(hit)
        rows.append([typ, len(hosts), len(hit), len(hosts) - len(hit),
                     100.0 * len(hit) / len(hosts) if hosts else 0.0,
                     statistics.mean(delays) if delays else float("nan"),
                     statistics.stdev(delays) if len(delays) > 1 else 0.0,
                     max(delays) if delays else float("nan")])
    attackers = sum(1 for v in truth.values() if v["label"] != "NORMAL")
    normals = [ip for ip, v in truth.items() if v["label"] == "NORMAL"]
    FP = sum(1 for ip in normals if ip in alerted_hosts)
    TN, FN = len(normals) - FP, attackers - TP
    n = TP + TN + FP + FN

    print(f"\nCapture: {a.pcap}  ({stats.packets} packets, {len(truth)} hosts)\n")
    print(f"{'Attack type':<25}{'Hosts':>6}{'TP':>4}{'FN':>4}{'TPR %':>8}"
          f"{'Delay mean s':>14}{'SD s':>7}{'Max s':>7}")
    print("-" * 75)
    for r in rows:
        print(f"{r[0]:<25}{r[1]:>6}{r[2]:>4}{r[3]:>4}{r[4]:>8.1f}{r[5]:>14.3f}{r[6]:>7.3f}{r[7]:>7.3f}")
    print("-" * 75)
    print(f"Overall: TP={TP} FN={FN} FP={FP} TN={TN}")
    print(f"  True Positive Rate  = {100 * TP / attackers:.1f}%")
    print(f"  False Positive Rate = {100 * FP / len(normals):.1f}%")
    print(f"  Accuracy            = {100 * (TP + TN) / n:.1f}%")
    print(f"  Throughput          = {stats.packets / secs:,.0f} packets/s "
          f"({secs:.2f}s for {stats.packets} packets, incl. PCAP parsing)")
    extras = [d for d in detections if truth.get(key_of(d), {}).get("label", "NORMAL") not in
              ("NORMAL", d.attack_type)]
    for d in extras:
        print(f"  Extra alert: attacker {key_of(d)} ({truth[key_of(d)]['label']}) "
              f"also triggered {d.attack_type} (count {d.count}).")
    for ip in normals:
        if ip in alerted_hosts:
            print(f"  FALSE POSITIVE: {ip} -> "
                  f"{sorted({d.attack_type for d in detections if d.source_ip == ip})}")
    for typ in ATTACK_TYPES:
        for ip, v in truth.items():
            if v["label"] == typ and (ip, typ) not in first:
                print(f"  MISSED: {ip} ({typ})")
    if a.csv:
        with open(a.csv, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["attack_type", "hosts", "tp", "fn", "tpr_percent",
                        "delay_mean_s", "delay_sd_s", "delay_max_s"])
            w.writerows(rows)
        print(f"\nPer-type table written to {a.csv}")


if __name__ == "__main__":
    main()
