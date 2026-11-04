"""Automated tests for NIDS v2. Run:  python -m unittest discover -s tests -v   (no root needed)"""
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nids.core import NIDSCore
from nids.database import Database, default_rules
from nids.detector import DetectionEngine
from nids.models import *
from nids.simulator import is_safe_target
from nids.usb_monitor import (LinuxProvider, USBDevice, USBMonitor, parse_windows_json, scan_drive_root)
from nids.validation import valid_date, valid_int, valid_ipv4
from nids.webapp import serve

ATT, VIC = "10.0.0.66", "192.168.1.10"


def tcp(ts, port=80, src=ATT, dst=VIC, flags=TCP_SYN):
    return PacketInfo(ts, src, dst, "TCP", port, flags)


def ping(ts, src=ATT, icmp_type=8):
    return PacketInfo(ts, src, VIC, "ICMP", icmp_type=icmp_type)


def arp(ts, ip, mac):
    return PacketInfo(ts, ip, "192.168.1.20", "ARP", arp_mac=mac)


def engine(**kw):
    kw.setdefault("restricted_ports", {23, 5900})
    kw.setdefault("auth_ports", {22, 3389})
    return DetectionEngine(default_rules(), **kw)


def feed(e, packets):
    out = []
    for p in packets:
        out += e.process(p)
    return out


def types(dets):
    return [d.attack_type for d in dets]


class NetworkRuleTests(unittest.TestCase):
    def test_port_scan_threshold_is_strict(self):
        self.assertEqual(types(feed(engine(), [tcp(i * .01, 1000 + i) for i in range(60)])), [PORT_SCAN])
        self.assertEqual(feed(engine(), [tcp(i * .01, 1000 + i) for i in range(50)]), [])

    def test_repeated_single_port_not_a_scan(self):
        self.assertEqual(types(feed(engine(), [tcp(i * .02, 443) for i in range(45)])), [])

    def test_server_syn_ack_replies_ignored(self):
        replies = [tcp(i * .01, 40000 + i, src=VIC, flags=TCP_SYN | TCP_ACK) for i in range(300)]
        self.assertEqual(feed(engine(), replies), [])

    def test_null_scan_counted(self):
        pk = [tcp(i * .01, 1000 + i, flags=0) for i in range(60)]
        self.assertIn(PORT_SCAN, types(feed(engine(), pk)))

    def test_slow_scan_caught_by_long_window_but_not_fast_rule(self):
        d = feed(engine(), [tcp(i * 0.2, 2000 + i) for i in range(400)])      # 5 ports/s for 80 s
        self.assertEqual(set(types(d)), {SLOW_PORT_SCAN})            # never the fast rule
        self.assertLess(d[0].timestamp, 25)                          # caught well before the scan ends

    def test_fast_scan_does_not_also_raise_slow_scan(self):
        d = feed(engine(), [tcp(i * .005, 1000 + i) for i in range(300)])
        self.assertNotIn(SLOW_PORT_SCAN, types(d))

    def test_syn_flood(self):
        d = feed(engine(), [tcp(i * .004) for i in range(150)])
        self.assertEqual(types(d), [SYN_FLOOD]); self.assertEqual(d[0].severity, "HIGH")
        self.assertEqual(feed(engine(), [tcp(i * .005) for i in range(100)]), [])

    def test_icmp_flood_and_replies(self):
        self.assertEqual(types(feed(engine(), [ping(i * .004) for i in range(150)])), [ICMP_FLOOD])
        self.assertEqual(feed(engine(), [ping(i * .004, icmp_type=0) for i in range(300)]), [])

    def test_distributed_flood_detected_even_when_each_source_is_quiet(self):
        pk = [tcp(i / 500.0, 80, src=f"10.9.0.{i % 40}") for i in range(500)]    # 40 hosts x 12/s
        d = feed(engine(), pk)
        self.assertEqual(types(d), [DDOS_SYN])
        self.assertTrue(d[0].source_ip.startswith("Multiple"))
        self.assertEqual(d[0].target_ip, VIC)

    def test_busy_server_with_few_clients_is_not_ddos(self):
        pk = [tcp(i / 400.0, 80, src=f"10.9.0.{i % 3}") for i in range(400)]      # 3 sources only
        self.assertNotIn(DDOS_SYN, types(feed(engine(), pk)))

    def test_brute_force_on_ssh(self):
        d = feed(engine(), [tcp(i * 1.0, 22) for i in range(12)])
        self.assertEqual(types(d), [BRUTE_FORCE]); self.assertIn("192.168.1.10:22", d[0].details)
        self.assertEqual(feed(engine(), [tcp(i * 1.0, 22) for i in range(8)]), [])

    def test_unauthorized_ports(self):
        self.assertEqual(types(feed(engine(), [tcp(i * 2.0, 23) for i in range(4)])), [UNAUTHORIZED])
        self.assertEqual(feed(engine(), [tcp(i * 2.0, 8080) for i in range(10)]), [])

    def test_arp_spoofing_detected_on_mac_change(self):
        d = feed(engine(), [arp(0, "192.168.1.1", "aa:aa"), arp(1, "192.168.1.1", "aa:aa"),
                            arp(2, "192.168.1.1", "bb:bb")])
        self.assertEqual(types(d), [ARP_SPOOFING]); self.assertIn("aa:aa to bb:bb", d[0].details)

    def test_arp_normal_traffic_and_new_hosts_not_flagged(self):
        pk = [arp(i, f"192.168.1.{i + 2}", f"cc:{i:02d}") for i in range(30)] + [arp(40, "192.168.1.2", "cc:00")]
        self.assertEqual(feed(engine(), pk), [])

    def test_trusted_host_ignored(self):
        e = engine(trusted_hosts={ATT})
        self.assertEqual(feed(e, [tcp(i * .004) for i in range(300)]), [])

    def test_cooldown_and_repeat(self):
        e = engine(cooldown=10)
        self.assertEqual(len(feed(e, [tcp(i * .004) for i in range(1000)])), 1)
        self.assertEqual(len(feed(e, [tcp(30 + i * .004) for i in range(200)])), 1)

    def test_disabled_rule_silent(self):
        rules = default_rules()
        for r in rules:
            r.enabled = r.name != SYN_FLOOD
        e = DetectionEngine(rules)
        self.assertNotIn(SYN_FLOOD, types(feed(e, [tcp(i * .004) for i in range(300)])))

    def test_idle_state_pruned(self):
        e = DetectionEngine(default_rules(), prune_every=10)
        feed(e, [tcp(i * .1, src=f"10.1.0.{i}") for i in range(10)])
        feed(e, [tcp(900 + i * .1, src="10.9.9.9") for i in range(10)])
        self.assertLessEqual(len(e._sources), 2)


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.db = Database(os.path.join(tempfile.mkdtemp(), "t.db"))
        self.sid = self.db.start_session("t")

    def tearDown(self):
        self.db.close()

    def add(self, ts, src, typ, sev="HIGH", sim=False, device=None):
        return self.db.add_alert(Detection(ts, src, VIC, typ, sev, 5, 1, "x", device, sim), self.sid)

    def test_seed_contains_all_rules_and_ports(self):
        names = {r.name for r in self.db.load_rules()}
        self.assertEqual(names, set(ATTACK_TYPES))
        self.assertEqual([p["port_number"] for p in self.db.ports("AUTH")], [21, 22, 3389])

    def test_filters_stats_and_simulated_flag(self):
        self.add(1_700_000_000, "1.1.1.1", SYN_FLOOD)
        self.add(1_700_000_100, "2.2.2.2", PORT_SCAN, "MEDIUM", sim=True)
        self.add(1_700_000_200, None, USB_STORAGE, "MEDIUM", device="Kingston flash")
        self.assertEqual(len(self.db.search_alerts()), 3)
        self.assertEqual(len(self.db.search_alerts(simulated=True)), 1)
        self.assertEqual(len(self.db.search_alerts(source_ip="Kingston")), 1)
        self.assertEqual(len(self.db.search_alerts(attack_type=SYN_FLOOD, severity="HIGH")), 1)
        self.assertEqual(self.db.stats()["total"], 3)
        self.assertEqual(self.db.clear_simulated(), 1)
        self.assertEqual(len(self.db.search_alerts()), 2)

    def test_csv_export(self):
        self.add(1_700_000_000, "1.1.1.1", SYN_FLOOD)
        path = os.path.join(tempfile.mkdtemp(), "o.csv")
        self.assertEqual(self.db.export_csv(path, self.db.search_alerts()), 1)
        self.assertEqual(len(open(path).read().strip().splitlines()), 2)

    def test_rule_update_reset_and_lists(self):
        self.db.update_rule(DDOS_SYN, 500, 2, False, 20)
        r = {x.name: x for x in self.db.load_rules()}[DDOS_SYN]
        self.assertEqual((r.threshold, r.window, r.enabled, r.extra), (500, 2.0, False, 20))
        self.db.reset_rules()
        self.assertEqual({x.name: x for x in self.db.load_rules()}[DDOS_SYN].threshold, 300)
        self.assertTrue(self.db.add_trusted_host("192.168.1.1")); self.assertFalse(self.db.add_trusted_host("192.168.1.1"))
        self.assertTrue(self.db.add_port(8888, "RESTRICTED")); self.assertFalse(self.db.add_port(8888, "RESTRICTED"))
        self.assertTrue(self.db.add_trusted_usb("X:1")); self.assertTrue(self.db.is_usb_trusted("X:1"))
        self.assertTrue(self.db.remove_trusted_usb("X:1")); self.assertFalse(self.db.is_usb_trusted("X:1"))

    def test_sql_injection_text_is_inert(self):
        self.add(1_700_000_000, "1.1.1.1", SYN_FLOOD)
        self.assertEqual(self.db.search_alerts(source_ip="1.1.1.1' OR '1'='1"), [])

    def test_threads_can_write_concurrently(self):
        def work(i):
            for k in range(30):
                self.add(1_700_000_000 + k, f"9.9.9.{i}", SYN_FLOOD)
        ts = [threading.Thread(target=work, args=(i,)) for i in range(5)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(self.db.stats()["total"], 150)


class FakeProvider:
    def __init__(self): self.devs = {}
    def snapshot(self): return dict(self.devs)


class USBTests(unittest.TestCase):
    def test_monitor_baseline_connect_remove(self):
        prov, events = FakeProvider(), []
        old = USBDevice("A:1", "storage", "Old disk", mounts=["/mnt/a"])
        prov.devs["A:1"] = old
        m = USBMonitor(prov, lambda a, d, s: events.append((a, d.dev_id)), mount_wait=0)
        m.poll_once()                                        # baseline: no events
        self.assertEqual(events, [])
        prov.devs["B:2"] = USBDevice("B:2", "storage", "Flash", mounts=[tempfile.mkdtemp()])
        m.poll_once(); self.assertEqual(events, [("connected", "B:2")])
        m.poll_once(); self.assertEqual(len(events), 1)      # not announced twice
        del prov.devs["B:2"]; m.poll_once()
        self.assertEqual(events[-1], ("removed", "B:2"))

    def test_storage_waits_for_mount(self):
        prov, events = FakeProvider(), []
        m = USBMonitor(prov, lambda a, d, s: events.append(a), mount_wait=100)
        m.poll_once()
        prov.devs["C:3"] = USBDevice("C:3", "storage", "Flash")
        m.poll_once(); self.assertEqual(events, [])
        prov.devs["C:3"].mounts = [tempfile.mkdtemp()]
        m.poll_once(); self.assertEqual(events, ["connected"])

    def test_folder_scan_finds_autorun_and_executables(self):
        d = tempfile.mkdtemp()
        for n in ("autorun.inf", "setup.EXE", "holiday.jpg", ".hidden"):
            open(os.path.join(d, n), "w").close()
        r = scan_drive_root(d)
        self.assertTrue(r["autorun"]); self.assertEqual(r["executables"], ["setup.EXE"]); self.assertEqual(r["hidden"], 1)
        self.assertIsNotNone(scan_drive_root("/nonexistent/path")["error"])

    def test_linux_provider_on_fake_sysfs(self):
        root = tempfile.mkdtemp()
        dev = f"{root}/devices/pci0/usb1/1-2"
        os.makedirs(f"{dev}/1-2:1.0"); os.makedirs(f"{dev}/host6/target6/block/sdb")
        for f, v in dict(idVendor="0951", idProduct="1666", serial="001A92", product="DataTraveler",
                         manufacturer="Kingston", bDeviceClass="00").items():
            open(f"{dev}/{f}", "w").write(v + "\n")
        open(f"{dev}/1-2:1.0/bInterfaceClass", "w").write("08\n")
        open(f"{dev}/host6/target6/block/sdb/size", "w").write("31116288\n")
        os.makedirs(f"{root}/bus/usb/devices"); os.symlink(dev, f"{root}/bus/usb/devices/1-2")
        os.makedirs(f"{root}/block"); os.symlink(f"{dev}/host6/target6/block/sdb", f"{root}/block/sdb")
        open(f"{root}/mounts", "w").write("/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 /media/user/FLASH vfat rw 0 0\n")
        s = LinuxProvider(root, f"{root}/mounts").snapshot()
        d = s["0951:1666:001A92"]
        self.assertEqual((d.kind, d.mounts, d.fs), ("storage", ["/media/user/FLASH"], "vfat"))
        self.assertGreater(d.size_bytes, 14 * 1024 ** 3)

    def test_windows_json_parsing(self):
        txt = json.dumps([
            dict(kind="storage", id="USBSTOR\\DISK&VEN_KINGSTON\\001A", name="Kingston", serial="001A", size=16 * 10 ** 9, letters="E:,F:"),
            dict(kind="hid", id="HID\\VID_046D&PID_C31C\\7&1", name="HID Keyboard Device", serial="", size=0, letters=""),
            dict(kind="other", id="USB\\VID_0951&PID_1666\\x", name="USB Mass Storage Device", serial="", size=0, letters="")])
        d = parse_windows_json(txt)
        self.assertEqual(len(d), 2)                                 # mass-storage duplicate dropped
        k = d["HID\\VID_046D&PID_C31C\\7&1"]
        self.assertEqual((k.kind, k.vid, k.pid), ("hid", "046d", "c31c"))
        self.assertEqual(d["USBSTOR\\DISK&VEN_KINGSTON\\001A"].mounts, ["E:\\", "F:\\"])
        self.assertEqual(parse_windows_json(""), {}); self.assertEqual(parse_windows_json("garbage"), {})
        self.assertEqual(len(parse_windows_json(json.dumps(dict(kind="hid", id="HID\\VID_1&PID_2", name="k")))), 1)


class CoreTests(unittest.TestCase):
    def setUp(self):
        cfg = dict(database_path=os.path.join(tempfile.mkdtemp(), "c.db"), console_alerts=False, cooldown_seconds=10)
        self.core = NIDSCore(cfg, start_usb=False)

    def tearDown(self):
        self.core.shutdown()

    def test_untrusted_usb_alerts_trusted_does_not(self):
        c = self.core
        dev = USBDevice("Z:9", "storage", "Sandisk", mounts=["/mnt/z"], size_bytes=8 * 1024 ** 3)
        c._on_usb_event("connected", dev, dict(entries=3, autorun=False, executables=[], hidden=0, error=None))
        a = c.db.search_alerts()
        self.assertEqual((a[0]["type_name"], a[0]["severity"]), (USB_STORAGE, "MEDIUM"))
        c.db.add_trusted_usb("Z:9")
        c._on_usb_event("connected", dev, None)
        self.assertEqual(len(c.db.search_alerts()), 1)
        self.assertEqual(c.db.usb_events(5)[0]["verdict"], "TRUSTED")

    def test_autorun_escalates_to_high(self):
        dev = USBDevice("Z:8", "storage", "Stick", mounts=["/mnt/z"])
        self.core._on_usb_event("connected", dev, dict(entries=2, autorun=True, executables=["a.exe"], hidden=0, error=None))
        self.assertEqual(self.core.db.search_alerts()[0]["severity"], "HIGH")

    def test_keyboard_device_alert_and_other_devices_only_logged(self):
        c = self.core
        c._on_usb_event("connected", USBDevice("K:1", "hid", "Keyboard"), None)
        c._on_usb_event("connected", USBDevice("W:1", "other", "Webcam"), None)
        self.assertEqual([a["type_name"] for a in c.db.search_alerts()], [USB_HID])
        self.assertEqual(len(c.db.usb_events(5)), 2)

    def test_packets_flow_to_database_and_are_flagged_simulated(self):
        c = self.core
        now = time.time()
        for i in range(150):
            c.process_packet(tcp(now + i * .002), simulated=True)
        a = c.db.search_alerts()
        self.assertEqual((a[0]["type_name"], a[0]["simulated"]), (SYN_FLOOD, 1))
        self.assertEqual(c.clear_simulated(), 1)

    def test_rule_change_takes_effect(self):
        c = self.core
        c.update_rule(SYN_FLOOD, 20, 1, True, 0)
        now = time.time()
        for i in range(40):
            c.process_packet(tcp(now + i * .01))
        self.assertEqual(c.db.search_alerts()[0]["type_name"], SYN_FLOOD)

    def test_simulate_usb_helper_and_timer_cleanup(self):
        self.core.simulate_usb("storage", autorun=True)
        self.assertEqual(self.core.db.search_alerts()[0]["severity"], "HIGH")
        self.assertEqual(len(self.core.usb_devices()), 1)


class SimulatorSafetyTests(unittest.TestCase):
    def test_target_safety(self):
        for ok in ("192.168.1.10", "10.0.0.5", "172.16.3.4", "127.0.0.1"):
            self.assertTrue(is_safe_target(ok), ok)
        for bad in ("8.8.8.8", "1.1.1.1", "224.0.0.1", "0.0.0.0", "abc", "", "93.184.216.34"):
            self.assertFalse(is_safe_target(bad), bad)

    def test_inject_scenarios_raise_expected_alerts(self):
        cfg = dict(database_path=os.path.join(tempfile.mkdtemp(), "s.db"), console_alerts=False)
        core = NIDSCore(cfg, start_usb=False)
        try:
            for sc, want in (("brute_force", BRUTE_FORCE), ("unauthorized", UNAUTHORIZED), ("arp_spoof", ARP_SPOOFING)):
                core.simulator.start(sc, "inject", "192.168.1.10", duration=(5 if sc == "arp_spoof" else 6), rate=3 if sc == "brute_force" else None)
                while core.simulator.status["running"]:
                    time.sleep(0.1)
                self.assertIn(want, [a["type_name"] for a in core.db.search_alerts()], sc)
            with self.assertRaises(ValueError):
                core.simulator.start("syn_flood", "network", "8.8.8.8")
            with self.assertRaises(ValueError):
                core.simulator.start("nope", "inject")
        finally:
            core.shutdown()


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cfg = dict(database_path=os.path.join(tempfile.mkdtemp(), "w.db"), console_alerts=False, host="127.0.0.1")
        cls.core = NIDSCore(cfg, start_usb=False)
        cls.server = serve(cls.core, "127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.core.shutdown()

    def req(self, path, body=None, headers=None):
        r = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", headers=headers or {},
                                   data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def test_dashboard_and_state(self):
        code, body = self.req("/")
        self.assertEqual(code, 200); self.assertIn(b"Network Intrusion Detection System", body)
        s = json.loads(self.req("/api/state")[1])
        self.assertEqual(len(s["traffic"]["pps"]), 60); self.assertEqual(len(s["rules"]), 10)
        self.assertEqual(len(json.loads(self.req("/api/meta")[1])["scenarios"]), 10)

    def test_rule_update_and_validation(self):
        ok = json.loads(self.req("/api/rule", dict(name=PORT_SCAN, threshold=70, window=1, enabled=True, extra=0))[1])
        self.assertTrue(ok["ok"])
        code, body = self.req("/api/rule", dict(name=PORT_SCAN, threshold="x", window=1))
        self.assertEqual(code, 400)
        code, _ = self.req("/api/trusted_host", dict(action="add", ip="999.1.1.1")); self.assertEqual(code, 400)
        code, _ = self.req("/api/alerts?date_from=garbage"); self.assertEqual(code, 400)
        code, _ = self.req("/api/alerts?type=NOPE"); self.assertEqual(code, 400)

    def test_csv_export_and_foreign_host_blocked(self):
        code, body = self.req("/api/export.csv")
        self.assertEqual(code, 200); self.assertTrue(body.startswith(b"alert_id,"))
        code, _ = self.req("/api/state", headers={"Host": "evil.example.com"}); self.assertEqual(code, 403)
        code, _ = self.req("/api/rules/reset", {}, headers={"Origin": "http://evil.example.com"}); self.assertEqual(code, 403)


class ValidationTests(unittest.TestCase):
    def test_all(self):
        self.assertTrue(valid_ipv4("192.168.1.1")); self.assertFalse(valid_ipv4("256.1.1.1"))
        self.assertTrue(valid_date("2026-09-14")); self.assertFalse(valid_date("14/09/2026"))
        self.assertTrue(valid_int("5", 1, 9)); self.assertFalse(valid_int("x", 1, 9)); self.assertFalse(valid_int(None, 1, 9))


if __name__ == "__main__":
    unittest.main()
